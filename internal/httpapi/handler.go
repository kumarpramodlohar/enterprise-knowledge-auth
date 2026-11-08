// Package httpapi provides the authenticated internal policy API handler.
// It checks the TLS caller and request contract before invoking the service,
// then returns bounded responses or privacy-safe error codes.
package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/contract"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/policy"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/service"
)

var correlationPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type Handler struct {
	service *service.Service
	trust   contract.Trust
	callers map[string]struct{}
	maxPage int
	logger  *slog.Logger
}

// New validates the handler's service, identity trust, caller allowlist, and
// page limit, then copies the configured allowlists. This prevents inconsistent
// request bounds and later mutation of trust configuration.
func New(s *service.Service, trust contract.Trust, callers []string, maxPage int, logger *slog.Logger) (*Handler, error) {
	if s == nil || logger == nil || maxPage < contract.DefaultPageSize || maxPage != s.MaxPageSize() || len(callers) == 0 || (len(trust.AllowedIssuers) == 0 && !trust.LocalEnabled) || (trust.LocalEnabled && trust.LocalNamespace == "") {
		return nil, errors.New("invalid HTTP API configuration")
	}
	copyCallers := make(map[string]struct{}, len(callers))
	for _, caller := range callers {
		if caller == "" {
			return nil, errors.New("empty caller identity")
		}
		copyCallers[caller] = struct{}{}
	}
	issuers := make(map[string]struct{}, len(trust.AllowedIssuers))
	for issuer := range trust.AllowedIssuers {
		if issuer == "" {
			return nil, errors.New("empty issuer")
		}
		issuers[issuer] = struct{}{}
	}
	trust.AllowedIssuers = issuers
	return &Handler{service: s, trust: trust, callers: copyCallers, maxPage: maxPage, logger: logger}, nil
}

// ServeHTTP authorizes the TLS caller, validates the bounded JSON request, and
// dispatches the three internal policy operations. It returns safe error
// envelopes rather than exposing request or policy details. The hosting server
// must require and verify client certificates over end-to-end TLS.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Correlation-Id")
	if !correlationPattern.MatchString(id) {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			h.logger.Error("correlation ID generation failed")
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "unavailable")
			return
		}
		id = hex.EncodeToString(random[:])
	}
	caller, ok := h.caller(r)
	if !ok {
		h.writeError(w, http.StatusForbidden, "CALLER_FORBIDDEN", id)
		return
	}
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Method != http.MethodPost || err != nil || mediaType != "application/json" || (len(params) != 0 && !(len(params) == 1 && strings.EqualFold(params["charset"], "utf-8"))) {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", id)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, contract.MaxBodySize+1))
	if err != nil || len(body) > contract.MaxBodySize {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", id)
		return
	}
	switch r.URL.Path {
	case "/internal/v1/users/resolve":
		request, err := contract.DecodeResolve(body, h.trust)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", id)
			return
		}
		status, err := h.service.Resolve(r.Context(), request.Identity)
		if err != nil {
			h.failure(w, err, id)
			return
		}
		h.writeJSON(w, http.StatusOK, struct {
			Status service.ResolveStatus `json:"status"`
		}{status})
	case "/internal/v1/permissions/check":
		request, err := contract.DecodeCheck(body, h.trust)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", id)
			return
		}
		collection, err := parseUUID(request.CollectionID)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", id)
			return
		}
		decision, err := h.service.Check(r.Context(), request.Identity, collection, policy.Permission(request.Permission))
		if err != nil {
			h.failure(w, err, id)
			return
		}
		h.writeJSON(w, http.StatusOK, struct {
			Decision policy.Decision `json:"decision"`
		}{decision})
	case "/internal/v1/scopes/page":
		request, err := contract.DecodePage(body, h.trust, h.maxPage)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", id)
			return
		}
		page, err := h.service.Page(r.Context(), request.Identity, caller, request.PageSize, request.Cursor)
		if err != nil {
			h.failure(w, err, id)
			return
		}
		type entry struct {
			CollectionID string            `json:"collectionId"`
			Permission   policy.Permission `json:"permission"`
		}
		entries := make([]entry, 0, len(page.Entries))
		for _, item := range page.Entries {
			entries = append(entries, entry{formatUUID(item.CollectionID), item.Permission})
		}
		h.writeJSON(w, http.StatusOK, struct {
			Role       policy.Role `json:"role"`
			Revision   string      `json:"revision"`
			Entries    []entry     `json:"entries"`
			NextCursor *string     `json:"nextCursor"`
		}{page.Role, page.Revision, entries, page.NextCursor})
	default:
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", id)
	}
}

// caller checks the TLS-verified certificate chain and its validity dates,
// then requires one allowlisted URI SAN. This ensures identity assertions and
// cursor bindings come only from an explicitly authorized backend identity.
func (h *Handler) caller(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	cert := r.TLS.PeerCertificates[0]
	now := time.Now()
	validChain := false
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) == 0 || !chain[0].Equal(cert) {
			continue
		}
		valid := true
		for _, member := range chain {
			if now.Before(member.NotBefore) || !now.Before(member.NotAfter) {
				valid = false
				break
			}
		}
		if valid {
			validChain = true
			break
		}
	}
	if !validChain || len(cert.URIs) != 1 {
		return "", false
	}
	name := cert.URIs[0].String()
	_, ok := h.callers[name]
	return name, ok
}

// failure maps service errors to internal HTTP status codes and logs only a
// safe category and correlation ID. Unexpected failures remain errors rather
// than becoming authorization decisions.
func (h *Handler) failure(w http.ResponseWriter, err error, id string) {
	status, code := http.StatusInternalServerError, "INTERNAL_ERROR"
	switch {
	case errors.Is(err, service.ErrInvalidCursor):
		status, code = http.StatusBadRequest, "INVALID_CURSOR"
	case errors.Is(err, service.ErrRevisionChanged):
		status, code = http.StatusConflict, "POLICY_REVISION_CHANGED"
	case errors.Is(err, service.ErrScopeLimit):
		status, code = http.StatusUnprocessableEntity, "SCOPE_LIMIT_EXCEEDED"
	case errors.Is(err, service.ErrUnavailable):
		status, code = http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"
	}
	h.logger.Warn("policy operation failed", "code", code, "correlationId", id)
	h.writeError(w, status, code, id)
}

// writeError sends the stable code and correlation ID envelope without
// disclosing the underlying error or sensitive request details.
func (h *Handler) writeError(w http.ResponseWriter, status int, code, id string) {
	h.writeJSON(w, status, struct {
		Code          string `json:"code"`
		CorrelationID string `json:"correlationId"`
	}{code, id})
}

// writeJSON sets JSON and no-store headers, writes the response, and logs a
// safe warning if encoding or delivery fails. This avoids caching policy
// responses or silently ignoring write failures.
func (h *Handler) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.logger.Warn("failed to write response")
	}
}

// parseUUID converts a previously contract-validated UUID string into bytes for
// the policy service, preserving the binary representation used by the store.
func parseUUID(value string) ([16]byte, error) {
	var id [16]byte
	raw, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(raw) != len(id) {
		return id, errors.New("invalid UUID")
	}
	copy(id[:], raw)
	return id, nil
}

// formatUUID converts a collection ID from bytes to the canonical lowercase
// UUID form required in scope responses.
func formatUUID(id [16]byte) string {
	raw := hex.EncodeToString(id[:])
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
}

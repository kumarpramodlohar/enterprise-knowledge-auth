// Package policy contains deterministic policy evaluation, not resource checks.
package policy

import "errors"

type Role string
type Permission string
type Decision string

const (
	Admin  Role = "ADMIN"
	Member Role = "MEMBER"
	None   Role = "NONE"

	Read   Permission = "READ"
	Manage Permission = "MANAGE"

	Allow Decision = "ALLOW"
	Deny  Decision = "DENY"
)

var ErrInvalidState = errors.New("invalid or incomplete policy state")

// Evaluate requires a fresh, successfully loaded state. A nil grant means that
// no grant exists for the requested collection; an OIDC identity must exist.
func Evaluate(kind string, role Role, grant *Permission, requested Permission) (Decision, error) {
	if (kind != "OIDC" && kind != "LOCAL") || (requested != Read && requested != Manage) {
		return "", ErrInvalidState
	}
	if role != Admin && role != Member && role != None {
		return "", ErrInvalidState
	}
	if grant != nil && *grant != Read && *grant != Manage {
		return "", ErrInvalidState
	}
	if role == None {
		if kind != "LOCAL" || grant != nil {
			return "", ErrInvalidState
		}
		return Deny, nil
	}
	if role == Admin {
		return Allow, nil
	}
	if grant == nil {
		return Deny, nil
	}
	if *grant == Manage || requested == Read && *grant == Read {
		return Allow, nil
	}
	return Deny, nil
}

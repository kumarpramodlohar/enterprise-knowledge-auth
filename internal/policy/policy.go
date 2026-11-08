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

// Evaluate checks a freshly loaded role and optional grant against a requested
// permission. ADMIN allows both permissions, MANAGE includes READ, and an
// unknown local user is denied; malformed state or a missing OIDC user is an
// error rather than a decision. A nil grant means no collection grant exists.
// This does not check whether the resource itself exists.
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

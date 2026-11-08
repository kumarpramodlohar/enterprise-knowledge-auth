package policy

import "testing"

func TestEvaluate(t *testing.T) {
	read, manage, invalid := Read, Manage, Permission("WRITE")
	tests := []struct {
		name, kind string
		role       Role
		grant      *Permission
		request    Permission
		want       Decision
		fail       bool
	}{
		{"admin", "OIDC", Admin, nil, Manage, Allow, false},
		{"member read", "OIDC", Member, &read, Read, Allow, false},
		{"read not manage", "OIDC", Member, &read, Manage, Deny, false},
		{"manage implies read", "OIDC", Member, &manage, Read, Allow, false},
		{"manage", "OIDC", Member, &manage, Manage, Allow, false},
		{"no grant", "LOCAL", Member, nil, Read, Deny, false},
		{"unknown local", "LOCAL", None, nil, Read, Deny, false},
		{"missing oidc", "OIDC", None, nil, Read, "", true},
		{"orphan grant", "LOCAL", None, &read, Read, "", true},
		{"invalid grant", "OIDC", Admin, &invalid, Read, "", true},
		{"invalid role", "OIDC", "OTHER", nil, Read, "", true},
		{"invalid requested permission", "OIDC", Admin, nil, "WRITE", "", true},
		{"invalid kind", "OTHER", Admin, nil, Read, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Evaluate(tt.kind, tt.role, tt.grant, tt.request)
			if (err != nil) != tt.fail || got != tt.want {
				t.Fatalf("got %q, %v; want %q, fail=%v", got, err, tt.want, tt.fail)
			}
		})
	}
}

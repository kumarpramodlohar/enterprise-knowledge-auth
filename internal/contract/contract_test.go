package contract

import (
	"strings"
	"testing"
)

var trust = Trust{AllowedIssuers: map[string]struct{}{"https://issuer.example": {}}, LocalNamespace: "dev", LocalEnabled: true}

func TestResolveIdentityAndStrictJSON(t *testing.T) {
	tests := []struct {
		name, body string
		valid      bool
	}{
		{"oidc", `{"identity":{"kind":"OIDC","issuer":"https://issuer.example","subject":"Alice"}}`, true},
		{"local", `{"identity":{"kind":"LOCAL","namespace":"dev","username":"Alice"}}`, true},
		{"exact issuer", `{"identity":{"kind":"OIDC","issuer":"https://ISSUER.example","subject":"Alice"}}`, false},
		{"local namespace", `{"identity":{"kind":"LOCAL","namespace":"other","username":"Alice"}}`, false},
		{"kind-specific field", `{"identity":{"kind":"OIDC","issuer":"https://issuer.example","subject":"a","username":""}}`, false},
		{"duplicate", `{"identity":{"kind":"LOCAL","kind":"LOCAL","namespace":"dev","username":"a"}}`, false},
		{"escaped duplicate", `{"identity":{"kind":"LOCAL","k\u0069nd":"LOCAL","namespace":"dev","username":"a"}}`, false},
		{"case mismatch", `{"Identity":{"kind":"LOCAL","namespace":"dev","username":"a"}}`, false},
		{"unknown", `{"identity":{"kind":"LOCAL","namespace":"dev","username":"a"},"extra":1}`, false},
		{"null", `{"identity":null}`, false},
		{"null field", `{"identity":{"kind":"LOCAL","namespace":"dev","username":null}}`, false},
		{"trailing", `{"identity":{"kind":"LOCAL","namespace":"dev","username":"a"}} {}`, false},
		{"array", `[]`, false},
		{"unpaired surrogate", `{"identity":{"kind":"LOCAL","namespace":"dev","username":"\ud800"}}`, false},
		{"paired surrogate", `{"identity":{"kind":"LOCAL","namespace":"dev","username":"\ud83d\ude00"}}`, true},
		{"invalid utf8", "{\"identity\":\"\xff\"}", false},
		{"oversize field", `{"identity":{"kind":"LOCAL","namespace":"dev","username":"` + strings.Repeat("a", MaxFieldSize+1) + `"}}`, false},
		{"oversize body", `{"identity":{"kind":"LOCAL","namespace":"dev","username":"a"}}` + strings.Repeat(" ", MaxBodySize), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeResolve([]byte(tt.body), trust)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v, error=%v", tt.valid, err)
			}
		})
	}
	if _, err := DecodeResolve([]byte(`{"identity":{"kind":"LOCAL","namespace":"dev","username":"a"}}`), Trust{}); err == nil {
		t.Fatal("local identity accepted when disabled")
	}
}

func TestCheckAndPage(t *testing.T) {
	id := `"identity":{"kind":"LOCAL","namespace":"dev","username":"a"}`
	for _, permission := range []string{"READ", "MANAGE"} {
		_, err := DecodeCheck([]byte(`{`+id+`,"collectionId":"00000000-0000-0000-0000-0000000000AB","permission":"`+permission+`"}`), trust)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{
		`{` + id + `,"collectionId":"invalid","permission":"READ"}`,
		`{` + id + `,"collectionId":"00000000-0000-0000-0000-000000000000","permission":"WRITE"}`,
		`{` + id + `,"pageSize":null}`,
		`{` + id + `,"cursor":null}`,
		`{` + id + `,"cursor":""}`,
		`{` + id + `,"pageSize":0}`,
		`{` + id + `,"pageSize":501}`,
		`{` + id + `,"pageSize":1.5}`,
	} {
		if strings.Contains(body, `"collectionId"`) {
			if _, err := DecodeCheck([]byte(body), trust); err == nil {
				t.Fatalf("accepted %s", body)
			}
		} else if _, err := DecodePage([]byte(body), trust, 500); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	page, err := DecodePage([]byte(`{`+id+`}`), trust, 500)
	if err != nil || page.PageSize != 100 || page.Cursor != "" {
		t.Fatalf("unexpected page: %+v, %v", page, err)
	}
	page, err = DecodePage([]byte(`{`+id+`,"pageSize":500,"cursor":"abc"}`), trust, 500)
	if err != nil || page.PageSize != 500 || page.Cursor != "abc" {
		t.Fatalf("unexpected page: %+v, %v", page, err)
	}
}

package cel

import (
	"testing"
)

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		vars       map[string]interface{}
		want       bool
	}{
		{
			name:       "simple true",
			expression: "request.method == 'GET'",
			vars:       map[string]interface{}{"request": map[string]interface{}{"method": "GET"}},
			want:       true,
		},
		{
			name:       "simple false",
			expression: "request.method == 'POST'",
			vars:       map[string]interface{}{"request": map[string]interface{}{"method": "GET"}},
			want:       false,
		},
		{
			name:       "string contains",
			expression: "request.url.matches('(?i)union\\\\s+select')",
			vars:       map[string]interface{}{"request": map[string]interface{}{"url": "/search?q=UNION SELECT * FROM users"}},
			want:       true,
		},
		{
			name:       "string not contains",
			expression: "request.url.matches('(?i)union\\\\s+select')",
			vars:       map[string]interface{}{"request": map[string]interface{}{"url": "/search?q=hello"}},
			want:       false,
		},
		{
			name:       "ip check",
			expression: "ip.startsWith('10.')",
			vars:       map[string]interface{}{"ip": "10.0.0.1"},
			want:       true,
		},
		{
			name:       "tenant check",
			expression: "tenant_id != 'admin'",
			vars:       map[string]interface{}{"tenant_id": "default"},
			want:       true,
		},
		{
			name:       "empty expression",
			expression: "",
			vars:       map[string]interface{}{},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Evaluate(tt.expression, tt.vars)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	if !ContainsAny("hello world", []string{"hello"}) {
		t.Error("expected true")
	}
	if ContainsAny("hello world", []string{"xyz"}) {
		t.Error("expected false")
	}
}

func TestEntropy(t *testing.T) {
	if Entropy("") != 0 {
		t.Error("empty string should have 0 entropy")
	}
	if Entropy("aaaa") != 0 {
		t.Error("entropy of identical characters should be 0")
	}
	if Entropy("aabb") <= 0 {
		t.Error("entropy should be > 0 for mixed characters")
	}
}

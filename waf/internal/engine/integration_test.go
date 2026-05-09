package engine

import (
	"os"
	"testing"

	"waf/internal/core"

	"go.uber.org/zap"
)

func TestFullPipeline_SQLInjection(t *testing.T) {
	rulesYAML := `
rules:
  - name: "SQLi_Union"
    description: "Detect SQL UNION"
    severity: "CRITICAL"
    expression: "request.url.matches('(?i)union')"
    action: "BLOCK"
    score: 0.9
`
	path := writeRulesFile(t, rulesYAML)
	defer os.Remove(path)

	logger, _ := zap.NewDevelopment()
	se, err := NewSecurityEngine(path, logger)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		url       string
		wantBlock bool
	}{
		{"SQLi_detector", "/search?q=1 UNION SELECT * FROM users", true},
		{"SQLi_rule", "/search?q=union select", true},
		{"benign", "/search?q=hello", false},
		{"XSS_detector", "/?q=<script>alert(1)</script>", true},
		{"path_traversal", "/file?path=../../../etc/passwd", true},
		{"SSRF_localhost", "/proxy?url=http://localhost:8080", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &core.RequestContext{
				URL:      tt.url,
				Method:   "GET",
				TenantID: "default",
				Headers:  map[string]string{},
				IP:       "127.0.0.1",
			}
			result, err := se.Evaluate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if result.Blocked != tt.wantBlock {
				t.Errorf("blocked = %v, want %v, score = %f, reason = %s",
					result.Blocked, tt.wantBlock, result.Score, result.Reason)
			}
		})
	}
}

func TestFullPipeline_CommandInjection(t *testing.T) {
	rulesYAML := `
rules: []
`
	path := writeRulesFile(t, rulesYAML)
	defer os.Remove(path)

	logger, _ := zap.NewDevelopment()
	se, err := NewSecurityEngine(path, logger)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		url       string
		wantBlock bool
	}{
		{"semicolon", "/?cmd=id;ls", true},
		{"pipe", "/?cmd=ls|cat", true},
		{"backtick", "/?cmd=`whoami`", true},
		{"dollar", "/?cmd=$(whoami)", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &core.RequestContext{
				URL:      tt.url,
				Method:   "GET",
				TenantID: "default",
				Headers:  map[string]string{},
				IP:       "127.0.0.1",
			}
			result, err := se.Evaluate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if result.Blocked != tt.wantBlock {
				t.Errorf("blocked = %v, want %v, score = %f, reason = %s",
					result.Blocked, tt.wantBlock, result.Score, result.Reason)
			}
		})
	}
}

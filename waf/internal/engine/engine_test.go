package engine

import (
	"os"
	"testing"

	"waf/internal/core"

	"go.uber.org/zap"
)

func writeRulesFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "waf-rules-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		os.Remove(f.Name())
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestRuleManager(t *testing.T) {
	rulesYAML := `
rules:
  - name: "TestBlock"
    description: "Test blocking rule"
    severity: "HIGH"
    expression: "request.url.matches('(?i)admin')"
    action: "BLOCK"
    score: 0.9
`
	path := writeRulesFile(t, rulesYAML)
	defer os.Remove(path)

	logger, _ := zap.NewDevelopment()
	rm, err := NewRuleManager(path, logger)
	if err != nil {
		t.Fatal(err)
	}

	if len(rm.rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rm.rules))
	}

	ctx := &core.RequestContext{
		URL:      "/admin",
		TenantID: "default",
		Method:   "GET",
		Headers:  map[string]string{},
	}

	result := rm.Evaluate(ctx)
	if !result.Blocked {
		t.Error("expected blocked for admin URL")
	}
	if result.Score != 0.9 {
		t.Errorf("expected score 0.9, got %f", result.Score)
	}

	// Test safe URL
	ctxSafe := &core.RequestContext{
		URL:      "/public",
		TenantID: "default",
		Method:   "GET",
		Headers:  map[string]string{},
	}

	resultSafe := rm.Evaluate(ctxSafe)
	if resultSafe.Blocked {
		t.Error("expected not blocked for safe URL")
	}
}

func TestScoreToLevel(t *testing.T) {
	tests := []struct {
		score float64
		want  core.ThreatLevel
	}{
		{0, core.ThreatLevelLow},
		{0.3, core.ThreatLevelMedium},
		{0.65, core.ThreatLevelHigh},
		{0.86, core.ThreatLevelCritical},
	}
	for _, tt := range tests {
		if got := scoreToLevel(tt.score); got != tt.want {
			t.Errorf("scoreToLevel(%f) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

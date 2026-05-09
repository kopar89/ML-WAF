package detectors

import (
	"testing"

	"waf/internal/core"
)

func makeContext(url, cookie string) *core.RequestContext {
	return &core.RequestContext{
		URL:       url,
		SessionID: cookie,
		Headers:   map[string]string{"Content-Type": "application/xml"},
	}
}

func TestSQLInjectionDetector(t *testing.T) {
	d := &SQLInjectionDetector{}
	tests := []struct {
		name string
		ctx  *core.RequestContext
		want bool
	}{
		{"union select", makeContext("/search?q=1 UNION SELECT * FROM users", ""), true},
		{"select from", makeContext("/api?query=SELECT * FROM accounts", ""), true},
		{"drop table", makeContext("/admin?cmd=DROP TABLE users", ""), true},
		{"exec xp_", makeContext("/rpc?q=exec xp_cmdshell", ""), true},
		{"benign", makeContext("/search?q=hello", ""), false},
		{"select in path", makeContext("/select?q=all", ""), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.IsTriggered(tt.ctx); got != tt.want {
				t.Errorf("SQLInjectionDetector.IsTriggered() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXSSDetector(t *testing.T) {
	d := &XSSDetector{}
	tests := []struct {
		name string
		ctx  *core.RequestContext
		want bool
	}{
		{"script tag", makeContext("/?q=<script>alert(1)</script>", ""), true},
		{"javascript uri", makeContext("/?q=javascript:alert(1)", ""), true},
		{"onerror", makeContext("/?img=1 onerror=alert(1)", ""), true},
		{"benign", makeContext("/?q=hello", ""), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.IsTriggered(tt.ctx); got != tt.want {
				t.Errorf("XSSDetector.IsTriggered() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommandInjectionDetector(t *testing.T) {
	d := &CommandInjectionDetector{}
	tests := []struct {
		name string
		ctx  *core.RequestContext
		want bool
	}{
		{"semicolon command", makeContext("/?cmd=id;ls", ""), true},
		{"pipe", makeContext("/?cmd=ls|cat", ""), true},
		{"backtick", makeContext("/?cmd=`whoami`", ""), true},
		{"whoami", makeContext("/?cmd=whoami", ""), true},
		{"benign", makeContext("/?name=john", ""), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.IsTriggered(tt.ctx); got != tt.want {
				t.Errorf("CommandInjectionDetector.IsTriggered() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSRFDetector(t *testing.T) {
	d := &SSRFDetector{}
	tests := []struct {
		name string
		ctx  *core.RequestContext
		want bool
	}{
		{"localhost", makeContext("/proxy?url=http://localhost:8080/admin", ""), true},
		{"127.0.0.1", makeContext("/proxy?url=http://127.0.0.1:22", ""), true},
		{"169.254 metadata", makeContext("/proxy?url=http://169.254.169.254/latest/meta-data", ""), true},
		{"10.x internal", makeContext("/proxy?url=http://10.0.0.1/config", ""), true},
		{"benign", makeContext("/proxy?url=https://api.example.com", ""), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.IsTriggered(tt.ctx); got != tt.want {
				t.Errorf("SSRFDetector.IsTriggered() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXXEDetector(t *testing.T) {
	d := &XXEDetector{}
	tests := []struct {
		name string
		ctx  *core.RequestContext
		want bool
	}{
		{"doctype", makeContext("/?xml=<!DOCTYPE foo>", ""), true},
		{"entity system", makeContext("/?xml=<!ENTITY xxe SYSTEM \"file:///etc/passwd\">", ""), true},
		{"benign", makeContext("/api?q=hello", ""), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.IsTriggered(tt.ctx); got != tt.want {
				t.Errorf("XXEDetector.IsTriggered() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPathTraversalDetector(t *testing.T) {
	d := &PathTraversalDetector{}
	tests := []struct {
		name string
		ctx  *core.RequestContext
		want bool
	}{
		{"dot dot slash", makeContext("/file?path=../../../etc/passwd", ""), true},
		{"encoded", makeContext("/file?path=%2e%2e%2fetc/passwd", ""), true},
		{"benign", makeContext("/file?path=/var/log", ""), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.IsTriggered(tt.ctx); got != tt.want {
				t.Errorf("PathTraversalDetector.IsTriggered() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAll(t *testing.T) {
	detectors := All()
	if len(detectors) != 8 {
		t.Errorf("expected 8 detectors, got %d", len(detectors))
	}
}

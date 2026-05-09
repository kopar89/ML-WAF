package config

import (
	"os"
	"testing"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "waf-config-*.yaml")
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

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ListenAddr != ":8080" {
		t.Errorf("expected :8080, got %s", cfg.ListenAddr)
	}
	if cfg.BackendURL != "http://localhost:9090" {
		t.Errorf("expected http://localhost:9090, got %s", cfg.BackendURL)
	}
	if !cfg.Security.Enabled {
		t.Error("security should be enabled by default")
	}
}

func TestLoadFromFile(t *testing.T) {
	yamlContent := `
listen_addr: ":9090"
backend_url: "http://example.com"
redis:
  addr: "myredis:6379"
`
	path := writeTempFile(t, yamlContent)
	defer os.Remove(path)

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Errorf("expected :9090, got %s", cfg.ListenAddr)
	}
	if cfg.BackendURL != "http://example.com" {
		t.Errorf("expected http://example.com, got %s", cfg.BackendURL)
	}
	if cfg.Redis.Addr != "myredis:6379" {
		t.Errorf("expected myredis:6379, got %s", cfg.Redis.Addr)
	}
}

func TestValidate(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	cfg.ListenAddr = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty listen_addr")
	}

	cfg = DefaultConfig()
	cfg.BackendURL = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty backend_url")
	}

	cfg = DefaultConfig()
	cfg.Redis.Addr = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty redis.addr")
	}
}

func TestApplyAndRollback(t *testing.T) {
	yamlContent := `
listen_addr: ":8080"
backend_url: "http://initial.com"
redis:
  addr: "redis:6379"
`
	path := writeTempFile(t, yamlContent)
	defer os.Remove(path)

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}

	newCfg := DefaultConfig()
	newCfg.ListenAddr = ":9090"
	newCfg.BackendURL = "http://new.com"

	if err := cfg.ApplyChanges(newCfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Errorf("expected :9090, got %s", cfg.ListenAddr)
	}

	if err := cfg.Rollback(); err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("expected :8080 after rollback, got %s", cfg.ListenAddr)
	}
}

func TestWatch(t *testing.T) {
	cfg := DefaultConfig()
	newCfg := DefaultConfig()
	if cfg.Watch(newCfg) {
		t.Error("expected no change for identical configs")
	}

	newCfg.BackendURL = "http://changed.com"
	if !cfg.Watch(newCfg) {
		t.Error("expected change detected")
	}
}

type mockNotifier struct {
	called bool
}

func (m *mockNotifier) OnConfigChanged(_, _ *Config) error {
	m.called = true
	return nil
}

func TestSubscribeNotify(t *testing.T) {
	cfg := DefaultConfig()
	notifier := &mockNotifier{}
	cfg.Subscribe(notifier)

	newCfg := DefaultConfig()
	newCfg.BackendURL = "http://changed.com"
	cfg.Watch(newCfg)

	if !notifier.called {
		t.Error("expected notifier to be called")
	}
}

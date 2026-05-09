package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ConfigChangeNotifier
type ConfigChangeNotifier interface {
	OnConfigChanged(oldCfg, newCfg *Config) error
}

// SecurityConfig безопасность
type SecurityConfig struct {
	Enabled   bool     `json:"enabled" yaml:"enabled"`
	RulesFile string   `json:"rules_file" yaml:"rules_file"`
	Detection []string `json:"detection" yaml:"detection"`
}

// LoggingConfig логи
type LoggingConfig struct {
	Level    string `json:"level" yaml:"level"`
	Format   string `json:"format" yaml:"format"`
	Output   string `json:"output" yaml:"output"`
	FilePath string `json:"file_path" yaml:"file_path"`
}

// Module плагин
type Module struct {
	Name        string                 `json:"name" yaml:"name"`
	DisplayName string                 `json:"display_name" yaml:"display_name"`
	Version     string                 `json:"version" yaml:"version"`
	Enabled     bool                   `json:"enabled" yaml:"enabled"`
	Priority    int                    `json:"priority" yaml:"priority"`
	Config      map[string]interface{} `json:"config" yaml:"config"`
}

// TenantConfig арендатор
type TenantConfig struct {
	TenantID   string `json:"tenant_id" yaml:"tenant_id"`
	TenantName string `json:"tenant_name" yaml:"tenant_name"`
	Domain     string `json:"domain" yaml:"domain"`
}

// RedisConfig настройки редис
type RedisConfig struct {
	Addr     string `json:"addr" yaml:"addr"`
	Password string `json:"password" yaml:"password"`
	DB       int    `json:"db" yaml:"db"`
}

// Config конфиг для waf
type Config struct {
	mu              sync.RWMutex           `json:"-" yaml:"-"`
	ListenAddr      string                 `json:"listen_addr" yaml:"listen_addr"`
	BackendURL      string                 `json:"backend_url" yaml:"backend_url"`
	ReadTimeout     time.Duration          `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout    time.Duration          `json:"write_timeout" yaml:"write_timeout"`
	ShutdownTimeout time.Duration          `json:"shutdown_timeout" yaml:"shutdown_timeout"`
	Security        SecurityConfig         `json:"security" yaml:"security"`
	Log             LoggingConfig          `json:"logging" yaml:"logging"`
	Redis           RedisConfig            `json:"redis" yaml:"redis"`
	Modules         []Module               `json:"modules" yaml:"modules"`
	Tenant          TenantConfig           `json:"tenant" yaml:"tenant"`
	watchers        []ConfigChangeNotifier `json:"-" yaml:"-"`
	rollback        *Config                `json:"-" yaml:"-"`
	filePath        string                 `json:"-" yaml:"-"`
}

// DefaultConfig дефолт конфиг
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:      ":8080",
		BackendURL:      "http://localhost:9090",
		ReadTimeout:     10 * time.Second,
		WriteTimeout:    10 * time.Second,
		ShutdownTimeout: 15 * time.Second,
		Security: SecurityConfig{
			Enabled:   true,
			RulesFile: "configs/rules.yaml",
			Detection: []string{"sqli", "xss", "cmdi", "ssrf", "xxe", "path_traversal", "file_inclusion", "cookie_tampering"},
		},
		Log: LoggingConfig{
			Level:    "info",
			Format:   "json",
			Output:   "stdout",
			FilePath: "",
		},
		Redis: RedisConfig{
			Addr: "localhost:6379",
			DB:   0,
		},
		Tenant: TenantConfig{
			TenantID: "default",
		},
	}
}

// LoadFromFile чтение данных из файла
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read file: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	cfg := DefaultConfig()
	cfg.filePath = path

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: yaml parse: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: json parse: %w", err)
		}
	default:
		return nil, fmt.Errorf("config: unsupported format %s", ext)
	}

	rollback := *cfg
	cfg.rollback = &rollback

	return cfg, nil
}

// Validate
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("config: listen_addr is required")
	}
	if c.BackendURL == "" {
		return fmt.Errorf("config: backend_url is required")
	}
	if !strings.HasPrefix(c.BackendURL, "http://") && !strings.HasPrefix(c.BackendURL, "https://") {
		return fmt.Errorf("config: backend_url must start with http:// or https://")
	}
	if c.Redis.Addr == "" {
		return fmt.Errorf("config: redis.addr is required")
	}
	return nil
}

// Subscribe
func (c *Config) Subscribe(n ConfigChangeNotifier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.watchers = append(c.watchers, n)
}

// Unsubscribe удаление наблюдателя
func (c *Config) Unsubscribe(n ConfigChangeNotifier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, w := range c.watchers {
		if fmt.Sprintf("%p", w) == fmt.Sprintf("%p", n) {
			c.watchers = append(c.watchers[:i], c.watchers[i+1:]...)
			return
		}
	}
}

// Watch сравнение новой и старой конфигурации
func (c *Config) Watch(newCfg *Config) bool {
	c.mu.RLock()
	changed := c.ListenAddr != newCfg.ListenAddr ||
		c.BackendURL != newCfg.BackendURL ||
		c.Security.Enabled != newCfg.Security.Enabled ||
		c.Security.RulesFile != newCfg.Security.RulesFile ||
		c.Redis.Addr != newCfg.Redis.Addr
	c.mu.RUnlock()

	if changed {
		c.notify(newCfg)
	}
	return changed
}

// ApplyChanges применяет новую конфигурацию и сохраняет состояние отката.
func (c *Config) ApplyChanges(newCfg *Config) error {
	c.mu.Lock()
	if err := newCfg.Validate(); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("config: apply invalid: %w", err)
	}
	old := *c
	c.rollback = &old

	c.ListenAddr = newCfg.ListenAddr
	c.BackendURL = newCfg.BackendURL
	c.ReadTimeout = newCfg.ReadTimeout
	c.WriteTimeout = newCfg.WriteTimeout
	c.ShutdownTimeout = newCfg.ShutdownTimeout
	c.Security = newCfg.Security
	c.Log = newCfg.Log
	c.Redis = newCfg.Redis
	c.Modules = newCfg.Modules
	c.Tenant = newCfg.Tenant

	watchers := make([]ConfigChangeNotifier, len(c.watchers))
	copy(watchers, c.watchers)
	c.mu.Unlock()

	for _, w := range watchers {
		if err := w.OnConfigChanged(&old, newCfg); err != nil {
			fmt.Printf("config: watcher error: %v\n", err)
		}
	}
	return nil
}

// Rollback возвращается к предыдущей конфигурации
func (c *Config) Rollback() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rollback == nil {
		return fmt.Errorf("config: nothing to rollback")
	}
	*c = *c.rollback
	c.rollback = nil
	return nil
}

func (c *Config) notify(newCfg *Config) {
	c.mu.RLock()
	watchers := make([]ConfigChangeNotifier, len(c.watchers))
	copy(watchers, c.watchers)
	c.mu.RUnlock()
	for _, w := range watchers {
		if err := w.OnConfigChanged(c, newCfg); err != nil {
			fmt.Printf("config: watcher error: %v\n", err)
		}
	}
}

func GetEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if n, err := fmt.Sscanf(val, "%d", &defaultVal); err == nil && n == 1 {
			return defaultVal
		}
	}
	return defaultVal
}

func GetEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}

func GetEnvString(key string, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

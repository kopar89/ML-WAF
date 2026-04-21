package configs

import (
		"encoding/json"
		"errors"
		"fmt"
		"net"
		"os"
		"path/filepath"
		"strings"
		"sync"
		"time"
		yaml "gopkg.in/yaml.v3"
	   )

type ConfigChangeNotifier interface {
	OnConfigChanged(oldCfg, newCfg *Config) error
}

type Config struct {
	mu             sync.RWMutex           `json:"-"`
	ListenAddr     string                 `json:"listen_addr"`
	BackendURL     string                 `json:"backend_url"`
	SelectDataBase string                 `json:"select_data_base"`
	TimeOut        time.Duration          `json:"time_out"`
	Security       SecurityConfig         `json:"security"`
	Log            LoggingConfig          `json:"logging"`
	TenantConfig   TenantSettings         `json:"tenant_settings"`
	Modules        []Module               `json:"modules"`
	watchers       []ConfigChangeNotifier `json:"-"`
	rollback       *Config                `json:"-"`
}

// НАСТРОЙКА ТЕНТОВ

// TenantSettings структура настроек тентов
type TenantSettings struct {
	TenantId   string        `json:"tenant_id"`
	TenantName string        `json:"tenant_name"`
	Domain     string        `json:"domain"`
	Quota      QuotaSettings `json:"quota"`
}

// QuotaSettings ограничения запросов для тента
type QuotaSettings struct {
	MaxRequestSize int64        `json:"max_request_size"`
	RequestHour    int          `json:"request_hour"`
	RequestDay     int          `json:"request_day"`
	Localize       Localization `json:"localize"`
}

// Localization локализация тента
type Localization struct {
	Language string `json:"language"`
	Timezone string `json:"timezone"`
}

// МОДУЛИ

// Module структура для включения/выключения детекции
type Module struct {
	Name        string                 `json:"name"`
	DisplayName string                 `json:"display_name"`
	Version     string                 `json:"version"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Config      map[string]interface{} `json:"config"`
}

// SECURITY & LOGGING

type SecurityConfig struct {
	Detection []string `json:"detection"`
	RulesFile string   `json:"rules_file"`
	Enabled   bool     `json:"enabled"`
}

type LoggingConfig struct {
	Level    string `json:"level"`
	FilePath string `json:"file_path"`
	Output   string `json:"output"`
	Format   string `json:"format"`
	ID       int    `json:"id"`
}

// Загрузка данных из бд/другого хранилища

type ConfigStore interface {
	Load() (*Config, error)
	Save(cfg *Config) error
}

type FileStore struct {
	path string
}

func (f *FileStore) Load() (*Config, error) {
	if f == nil || f.path == "" {
		return nil, errors.New("путь к файлу не указан")
	}
	data, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("ошибка при чтении файла: %v", err)
	}

	ext := strings.ToLower(filepath.Ext(f.path))
	switch ext {
	case ".json":
		cfg := &Config{}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("ошибка при парсинге конфигурации: %v", err)
		}
		return cfg, nil
	case ".yaml", ".yml":
		var m map[string]interface{}
		if err := yaml.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("ошибка при парсинге YAML конфигурации: %v", err)
		}
		jb, err := json.Marshal(m)
		if err != nil {
			return nil, fmt.Errorf("ошибка при конвертации YAML в JSON: %v", err)
		}
		cfg := &Config{}
		if err := json.Unmarshal(jb, cfg); err != nil {
			return nil, fmt.Errorf("ошибка при парсинге конфигурации: %v", err)
		}
		return cfg, nil
	default:
		return nil, fmt.Errorf("unsupported file extension: %s", ext)
	}
}

// МЕТОДЫ ВАЛИДАЦИИ

func (c *Config) Validate() error {
	// Validate listen address using robust parsing
	if c.ListenAddr == "" {
		return errors.New("listen_addr is empty")
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("listen_addr invalid: %w", err)
	}

	if c.BackendURL == "" {
		return errors.New("backend_url is empty")
	}

	if !strings.HasPrefix(c.BackendURL, "http://") && !strings.HasPrefix(c.BackendURL, "https://") {
		return errors.New("backend_url must start with http:// or https://")
	}

	if len(c.Modules) == 0 {
		return errors.New("modules list is empty")
	}

	for i, module := range c.Modules {
		if module.Name == "" {
			return fmt.Errorf("module at index %d has empty name", i)
		}
	}

	if c.TenantConfig.TenantId == "" {
		return errors.New("tenant_id is empty")
	}

	if c.TenantConfig.Domain == "" {
		return errors.New("tenant domain is empty")
	}

	return nil
}

func (c *Config) Watch(newCfg *Config) bool {
	// Считать изменения под защитой чтения, уведомлять позже вне блокировки
	c.mu.RLock()
	changed := c.BackendURL != newCfg.BackendURL ||
		c.ListenAddr != newCfg.ListenAddr ||
		c.TimeOut != newCfg.TimeOut ||
		!securityConfigEqual(&c.Security, &newCfg.Security) ||
		!loggingConfigEqual(&c.Log, &newCfg.Log) ||
		!tenantSettingsEqual(&c.TenantConfig, &newCfg.TenantConfig) ||
		!modulesEqual(c.Modules, newCfg.Modules)
	c.mu.RUnlock()

	if changed {
		c.notifyWatchers(newCfg)
	}

	return changed
}

// Subscribe добавляет наблюдателя для изменений
func (c *Config) Subscribe(notifier ConfigChangeNotifier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.watchers = append(c.watchers, notifier)
	fmt.Printf("Наблюдатель добавлен. Всего наблюдателей: %d\n", len(c.watchers))
}

// Unsubscribe удаляет наблюдателя
func (c *Config) Unsubscribe(notifier ConfigChangeNotifier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, w := range c.watchers {
		if w == notifier {
			c.watchers = append(c.watchers[:i], c.watchers[i+1:]...)
			fmt.Printf("Наблюдатель удален. Осталось: %d\n", len(c.watchers))
			return
		}
	}
}

// notifyWatchers уведомляет все обработчики об изменениях
func (c *Config) notifyWatchers(newCfg *Config) {
	// копируем наблюдателей под lock, чтобы избежать гонок
	c.mu.RLock()
	watchers := append([]ConfigChangeNotifier(nil), c.watchers...)
	c.mu.RUnlock()
	for _, watcher := range watchers {
		go func(w ConfigChangeNotifier) {
			if err := w.OnConfigChanged(c, newCfg); err != nil {
				fmt.Printf("Ошибка при обработке изменения конфигурации: %v\n", err)
			}
		}(watcher)
	}
}

// ============= МЕТОДЫ ПРИМЕНЕНИЯ И ОТКАТА =============

// ApplyChanges применяет новую конфигурацию после валидации
func (c *Config) ApplyChanges(newCfg *Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := newCfg.Validate(); err != nil {
		return fmt.Errorf("новая конфигурация невалидна: %w", err)
	}

	oldCfg := *c
	c.rollback = &oldCfg

	if newCfg.watchers != nil {
		c.watchers = newCfg.watchers
	}
	c.ListenAddr = newCfg.ListenAddr
	c.BackendURL = newCfg.BackendURL
	c.SelectDataBase = newCfg.SelectDataBase
	c.TimeOut = newCfg.TimeOut
	c.Security = newCfg.Security
	c.Log = newCfg.Log
	c.TenantConfig = newCfg.TenantConfig
	c.Modules = newCfg.Modules

	c.notifyWatchers(newCfg)

	fmt.Println("Конфигурация успешно применена")

	return nil
}

// Rollback откатывает конфигурацию к предыдущему состоянию (без аргументов)
func (c *Config) Rollback() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.rollback == nil {
		return nil
	}
	*c = *c.rollback
	c.rollback = nil
	fmt.Println("Конфигурация откачена к предыдущему состоянию")
	return nil
}

// LoadFromStore загружает конфигурацию из хранилища (заглушка)
func (c *Config) LoadFromStore() error {
	fmt.Println("Конфигурация загружена из хранилища")
	return nil
}

// ============= ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ СРАВНЕНИЯ =============

// modulesEqual сравнивает слайсы модулей
func modulesEqual(a, b []Module) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name ||
			a[i].DisplayName != b[i].DisplayName ||
			a[i].Version != b[i].Version ||
			a[i].Enabled != b[i].Enabled ||
			a[i].Priority != b[i].Priority {
			return false
		}
	}
	return true
}

// securityConfigEqual сравнивает конфигурации безопасности
func securityConfigEqual(a, b *SecurityConfig) bool {
	if a.Enabled != b.Enabled || a.RulesFile != b.RulesFile {
		return false
	}
	if len(a.Detection) != len(b.Detection) {
		return false
	}
	for i := range a.Detection {
		if a.Detection[i] != b.Detection[i] {
			return false
		}
	}
	return true
}

// loggingConfigEqual сравнивает конфигурации логирования
func loggingConfigEqual(a, b *LoggingConfig) bool {
	return a.Level == b.Level &&
		a.FilePath == b.FilePath &&
		a.Output == b.Output &&
		a.Format == b.Format &&
		a.ID == b.ID
}

// tenantSettingsEqual сравнивает настройки тентов
func tenantSettingsEqual(a, b *TenantSettings) bool {
	if a.TenantId != b.TenantId ||
		a.TenantName != b.TenantName ||
		a.Domain != b.Domain {
		return false
	}

	// Сравнение Quota
	if a.Quota.MaxRequestSize != b.Quota.MaxRequestSize ||
		a.Quota.RequestHour != b.Quota.RequestHour ||
		a.Quota.RequestDay != b.Quota.RequestDay {
		return false
	}

	// Сравнение Localization
	if a.Quota.Localize.Language != b.Quota.Localize.Language ||
		a.Quota.Localize.Timezone != b.Quota.Localize.Timezone {
		return false
	}

	return true
}

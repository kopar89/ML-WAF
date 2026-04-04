package configs

import (
	"strings"
	"time"
	"fmt"
	"errors"
	"sync"
	"encoding/json"
	"os"
)

// ConfigChangeNotifier интерфейс для обработки изменений конфигурации
type ConfigChangeNotifier interface {
	OnConfigChanged(oldCfg, newCfg *Config) error
}

type Config struct {
	mu         sync.RWMutex `json:"-"`
	ListenAddr string `json:"listen_addr"`
	BackendURL string `json:"backend_url"`
	SelectDataBase string `json:"select_data_base"`
	TimeOut    time.Time `json:"time_out"`
	Securiry   SecurityConfig `json:"security"`
	Log        LoggingConfig `json:"logging"`
	Tent       TenantSettings `json:"tenant_settings"`
	Modules    []Module `json:"modules"`
	watchers   []ConfigChangeNotifier `json:"-"`
	rollback   *Config  `json:"-"`
}

// НАСТРОЙКА ТЕНТОВ 

// TenantSettings структура настроек тентов
type TenantSettings struct {
	TenantId    string `json:"tenant_id"`
	TenantName  string `json:"tenant_name"`
	Domain      string `json:"domain"`
	Quota       QuotaSettings `json:"quota"`
}

// QuotaSettings ограничения запросов для тента
type QuotaSettings struct {
	MaxRequestSize int64 `json:"max_request_size"`
	RequestHour    int `json:"request_hour"`
	RequestDay     int `json:"request_day"`
	Localize       Localization `json:"localize"`
}

// Localization локализация тента
type Localization struct {
	Language string `json:"language"`
	Timezone string `json:"timezone"` // например: "Europe/Moscow"
}

// МОДУЛИ

// Module структура для включения/выключения детекции
type Module struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Version     string `json:"version"`
	Enabled     bool `json:"enabled"`
	Priority    int
	Config      map[string]interface{}
}

// SECURITY & LOGGING 

type SecurityConfig struct {
	Detection []string `json:"detection"`
	RulesFile string `json:"rules_file"`
	Enabled   bool `json:"enabled"`
}

type LoggingConfig struct {
	Level    string `json:"level"`
	FilePath string `json:"file_path"`
	Output   string `json:"output"`
	Format   string `json:"format"`
	ID       int `json:"id"`
}


// Загрузка данных из бд/другого хранилища

type ConfigStore interface{
	Load() (*Config, error)
	Save(cfg *Config) error
	//WatchChang(<-chan *Config)
}


type File struct{
	path string
}

// чтение json для структуры конфигурации из файла
func(f *File) Load() (*Config, error){
	if f == nil || f.path == "" {
		return nil, errors.New("путь к файлу не указан")
	}
	// Реализовать загрузку из файла (например, JSON или YAML)
	data, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("ошибка при чтении файла: %v", err)
	}

	cfg := &Config{}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("ошибка при парсинге конфигурации: %v", err)
	}

	// Здесь должна быть логика парсинга данных (например, JSON или YAML)
	return cfg, nil
}


// МЕТОДЫ ВАЛИДАЦИИ

func (c *Config) Validate() error {
	// Проверка ListenAddr
	if c.ListenAddr == "" {
		return errors.New("listen_addr is empty")
	}

	if !strings.HasPrefix(c.ListenAddr, ":") {
		return errors.New("listen_addr must start with ':' (e.g. ':3000')")
	}

	// Проверка BackendURL
	if c.BackendURL == "" {
		return errors.New("backend_url is empty")
	}

	if !strings.HasPrefix(c.BackendURL, "http://") && !strings.HasPrefix(c.BackendURL, "https://") {
		return errors.New("backend_url must start with http:// or https://")
	}

	// Проверка Modules
	if len(c.Modules) == 0 {
		return errors.New("modules list is empty")
	}

	for i, module := range c.Modules {
		if module.Name == "" {
			return fmt.Errorf("module at index %d has empty name", i)
		}
	}

	// Проверка TenantSettings
	if c.Tent.TenantId == "" {
		return errors.New("tenant_id is empty")
	}

	if c.Tent.Domain == "" {
		return errors.New("tenant domain is empty")
	}

	return nil
}

// ============= МЕТОДЫ НАБЛЮДЕНИЯ =============

// Watch проверяет изменения между текущей и новой конфигурацией
func (c *Config) Watch(newCfg *Config) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	changed := false
	changeDetails := make(map[string]interface{})

	// Сравнение BackendURL
	if c.BackendURL != newCfg.BackendURL {
		changed = true
		changeDetails["BackendURL"] = map[string]string{
			"old": c.BackendURL,
			"new": newCfg.BackendURL,
		}
	}

	// Сравнение ListenAddr
	if c.ListenAddr != newCfg.ListenAddr {
		changed = true
		changeDetails["ListenAddr"] = map[string]string{
			"old": c.ListenAddr,
			"new": newCfg.ListenAddr,
		}
	}

	// Сравнение TimeOut
	if c.TimeOut != newCfg.TimeOut {
		changed = true
		changeDetails["TimeOut"] = map[string]string{
			"old": c.TimeOut.String(),
			"new": newCfg.TimeOut.String(),
		}
	}

	// Сравнение Security
	if !securityConfigEqual(&c.Securiry, &newCfg.Securiry) {
		changed = true
		changeDetails["SecurityConfig"] = "конфигурация безопасности изменилась"
	}

	// Сравнение Logging
	if !loggingConfigEqual(&c.Log, &newCfg.Log) {
		changed = true
		changeDetails["LoggingConfig"] = "конфигурация логирования изменилась"
	}

	// Сравнение TenantSettings
	if !tenantSettingsEqual(&c.Tent, &newCfg.Tent) {
		changed = true
		changeDetails["TenantSettings"] = map[string]string{
			"old_id":   c.Tent.TenantId,
			"new_id":   newCfg.Tent.TenantId,
			"old_name": c.Tent.TenantName,
			"new_name": newCfg.Tent.TenantName,
		}
	}

	// Сравнение Modules
	if !modulesEqual(c.Modules, newCfg.Modules) {
		changed = true
		changeDetails["Modules"] = "конфигурация модулей изменилась"
	}

	if changed {
		fmt.Printf("Обнаружены изменения конфигурации:\n%+v\n", changeDetails)
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
	// Простое удаление (если нужна типизированная очистка, переделайте)
	fmt.Println("Наблюдатель удален")
}

// notifyWatchers уведомляет все обработчики об изменениях
func (c *Config) notifyWatchers(newCfg *Config) {
	for _, watcher := range c.watchers {
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

	// Проверяем валидность новой конфигурации
	if err := newCfg.Validate(); err != nil {
		return fmt.Errorf("новая конфигурация невалидна: %w", err)
	}

	// Сохраняем старую конфигурацию для отката
	oldCfg := *c

	// Применяем изменения
	*c = *newCfg

	// Разблокируем для уведомления
	c.mu.Unlock()

	// Уведомляем наблюдателей
	c.notifyWatchers(newCfg)

	c.mu.Lock()

	fmt.Println("Конфигурация успешно применена")
	oldCfg = *&oldCfg
	
	return nil
}

// Rollback откатывает конфигурацию к предыдущему состоянию
func (c *Config) Rollback(oldCfg *Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	*c = *oldCfg
	fmt.Println("Конфигурация откачена к предыдущему состоянию")
	return nil
}

// LoadFromStore загружает конфигурацию из хранилища (заглушка)
func (c *Config) LoadFromStore() error {
	// реализация загрузки из БД, файла или другого хранилища

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

# Web Application Firewall (WAF)

Production-grade Web Application Firewall на Go с поддержкой ML-детекции (в development).

## Возможности

- **8 встроенных детекторов атак**: SQL Injection, XSS, Command Injection, SSRF, XXE, Path Traversal, File Inclusion, Cookie Tampering
- **CEL-based правила**: гибкий язык правил через Common Expression Language
- **Rate Limiting**: sliding window rate limiting с Redis backend
- **Hot Reload**: перезагрузка конфигурации без перезапуска
- **Prometheus Metrics**: встроенные метрики для мониторинга
- **Structured Logging**: JSON логирование через zap
- **Graceful Shutdown**: корректное завершение работы

## Быстрый старт

### Требования

- Go 1.22+
- Redis (опционально, для production rate limiting)

### Сборка

```bash
cd waf
go build -o waf-bin ./cmd/waf/
```

### Запуск

```bash
# Запуск с конфигурацией по умолчанию
./waf-bin

# Показать версию
./waf-bin --version

# Указать свой конфиг
./waf-bin --config /path/to/config.yaml
```

### Docker

```bash
cd waf
docker-compose up -d
```

## Конфигурация

### Основной конфиг (`configs/config.yaml`)

```yaml
listen_addr: ":8080"
backend_url: "http://localhost:9090"
read_timeout: 10s
write_timeout: 10s

security:
  enabled: true
  rules_file: "configs/rules.yaml"

redis:
  addr: "localhost:6379"
  password: ""
  db: 0

tenant:
  tenant_id: "default"
```

### Переменные окружения

| Переменная | Описание | По умолчанию |
|------------|----------|---------------|
| `WAF_CONFIG_PATH` | Путь к конфигу | `configs/config.yaml` |
| `WAF_RATE_LIMIT` | Лимит запросов | `100` |
| `WAF_RATE_WINDOW` | Окно rate limiting | `60s` |

## Правила безопасности

WAF поставляется с **50+ правилами** для обнаружения:

- **OWASP A01** - Broken Access Control 
- **OWASP A02** - Cryptographic Failures 
- **OWASP A03** - Injection 
- **OWASP A05** - Security Misconfiguration 
- **OWASP A08** - Insecure Deserialization 
- **OWASP A10** - SSRF 

### Примеры атак

```bash
# SQL Injection - заблокировано
curl "http://localhost:8080/search?q=1 UNION SELECT * FROM users"

# XSS - заблокировано  
curl "http://localhost:8080/?q=<script>alert(1)</script>"

# Path Traversal - заблокировано
curl "http://localhost:8080/file?path=../../../etc/passwd"

# Legitimate request - разрешено
curl "http://localhost:8080/api/users"
```

## API Endpoints

| Endpoint | Описание |
|----------|----------|
| `/health` | Health check |
| `/metrics` | Prometheus метрики |
| `/` | Проксирование запросов |
| `:6060/debug/pprof/` | Profiling (только localhost) |

## Тестирование

```bash
# Запуск всех тестов
go test ./... -v

# Запуск с покрытием
go test ./... -cover

# Тесты детекторов
go test ./internal/detectors/ -v -run TestSQL
```

## Архитектура

```
Client → WAFCore → SecurityEngine → Detectors + Rules → Backend
                      ↓
              RateLimiter (Redis)
              EventPublisher (async)
              Metrics (Prometheus)
```

## Разработка

### Структура проекта

```
waf/
├── cmd/waf/main.go          # Точка входа
├── internal/
│   ├── auth/               # JWT валидация
│   ├── config/             # Конфигурация с hot-reload
│   ├── core/               # WAFCore
│   ├── detectors/         # 8 детекторов атак
│   ├── engine/             # SecurityEngine + RuleManager
│   ├── middleware/         # RateLimiter
│   ├── metrics/            # Prometheus
│   └── publisher/          # EventPublisher
├── pkg/cel/                # CEL компилятор
├── configs/                # Конфигурации
└── tests/
```

### Добавление нового детектора

```go
// internal/detectors/detectors.go
type NewDetector struct{}

func (d *NewDetector) Name() string     { return "NewDetector" }
func (d *NewDetector) Category() string { return "New Category" }
func (d *NewDetector) Severity() string { return "HIGH" }
func (d *NewDetector) Score() float64    { return 0.8 }

func (d *NewDetector) IsTriggered(ctx *core.RequestContext) bool {
    // Логика детекции
    return false
}

// Добавить в All():
// &NewDetector{},
```

### Добавление нового CEL-правила

```yaml
# configs/rules.yaml
rules:
  - name: "MyNewRule"
    description: "Detect something"
    severity: "HIGH"
    expression: "request.url.matches('(?i)bad-pattern')"
    action: "BLOCK"
    score: 0.8
```

## Production рекомендации

1. **Redis** - использовать для rate limiting в production
2. **HTTPS** - запустить за reverse proxy (nginx/traefik)
3. **Мониторинг** - настроить Grafana дашборды
4. **Логирование** - отправлять в Elasticsearch
5. **pprof** - использовать для профилирования производительности

## Лицензия

MIT License

## Ссылки

- [Документация CEL](https://github.com/google/cel-go)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

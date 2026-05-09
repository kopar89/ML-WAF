# Руководство пользователя WAF

## Содержание

1. [Установка](#установка)
2. [Запуск](#запуск)
3. [Конфигурация](#конфигурация)
4. [Тестирование](#тестирование)
5. [Мониторинг](#мониторинг)
6. [Дополнительные возможности](#дополнительные-возможности)

---

## Установка

### Требования

- Go 1.22 или выше
- Redis (опционально, для production режима)

### Сборка из исходников

```bash
cd waf
go build -o waf-bin ./cmd/waf/
```

Бинарный файл `waf-bin` будет создан в директории `waf`.

### Docker

```bash
cd waf
docker-compose up -d
```

---

## Запуск

### Базовый запуск

```bash
./waf-bin
```

WAF запустится на `http://localhost:8080` и будет проксировать запросы на `http://localhost:9090` (по умолчанию).

### Параметры командной строки

```bash
./waf-bin --help
```

```
Usage of ./waf-bin:
  -config string
        Path to config file (default "configs/config.yaml")
  -version
        Show version info
```

### Проверка работы

```bash
# Проверка health endpoint
curl http://localhost:8080/health
# Ответ: OK

# Проверка метрик
curl http://localhost:8080/metrics
```

---

## Конфигурация

### Структура конфига

Файл `configs/config.yaml`:

```yaml
# Адрес для прослушивания
listen_addr: ":8080"

# URL backend сервиса
backend_url: "http://localhost:9090"

# Таймауты
read_timeout: 10s
write_timeout: 10s
shutdown_timeout: 15s

# Настройки безопасности
security:
  enabled: true
  rules_file: "configs/rules.yaml"

# Настройки Redis
redis:
  addr: "localhost:6379"
  password: ""
  db: 0

# Настройки логирования
logging:
  level: "info"
  format: "json"

# Tenant настройки
tenant:
  tenant_id: "default"
  tenant_name: "Default Tenant"
  domain: "localhost"
```

### Переменные окружения

| Переменная | Описание | По умолчанию |
|------------|----------|---------------|
| `WAF_CONFIG_PATH` | Путь к конфигу | `configs/config.yaml` |
| `WAF_RATE_LIMIT` | Лимит запросов/окно | `100` |
| `WAF_RATE_WINDOW` | Длительность окна | `60s` |

Пример:
```bash
WAF_RATE_LIMIT=200 WAF_RATE_WINDOW=30s ./waf-bin
```

---

## Тестирование

### Запуск unit тестов

```bash
# Все тесты
go test ./... -v

# Тесты конкретного пакета
go test ./internal/detectors/ -v
go test ./internal/engine/ -v
```

### Ручное тестирование атак

```bash
# SQL Injection - должен быть ЗАБЛОКИРОВАН
curl -v "http://localhost:8080/search?q=1%20UNION%20SELECT%20*%20FROM%20users"

# XSS - должен быть ЗАБЛОКИРОВАН
curl -v "http://localhost:8080/?q=<script>alert(1)</script>"

# Command Injection - должен быть ЗАБЛОКИРОВАН
curl -v "http://localhost:8080/?cmd=whoami"

# Path Traversal - должен быть ЗАБЛОКИРОВАН
curl -v "http://localhost:8080/file?path=../../../etc/passwd"

# SSRF - должен быть ЗАБЛОКИРОВАН
curl -v "http://localhost:8080/proxy?url=http://127.0.0.1:8080"

# Legitimate request - должен быть РАЗРЕШЕН
curl -v "http://localhost:8080/api/users/1"
```

### Ожидаемые ответы

**Заблокированный запрос (403):**
```
HTTP/1.1 403 Forbidden
403 Forbidden: SQL Injection: SQLInjectionDetector
```

**Rate Limited (429):**
```
HTTP/1.1 429 Too Many Requests
429 Too Many Requests
```

**Разрешённый запрос:** проксируется на backend

---

## Мониторинг

### Prometheus Metrics

```bash
curl http://localhost:8080/metrics
```

Метрики:
- `waf_requests_total` - всего запросов
- `waf_blocked_total` - заблокировано
- `waf_proxied_total` - проксировано
- `waf_rate_limited_total` - rate limited
- `waf_request_duration_ms` - латентность

### Профилирование

pprof доступен по адресу `http://localhost:6060/debug/pprof/`

```bash
# CPU профиль
go tool pprof http://localhost:6060/debug/pprof/profile

# Heap профиль  
go tool pprof http://localhost:6060/debug/pprof/heap
```

### Health Check

```bash
curl http://localhost:8080/health
# Ответ: OK
```

---

## Дополнительные возможности

### Hot Reload конфигурации

WAF поддерживает горячую перезагрузку конфигурации без перезапуска:

1. Измените `configs/config.yaml`
2. WAF автоматически загрузит новые настройки

### Настройка правил

Добавьте новое правило в `configs/rules.yaml`:

```yaml
rules:
  - name: "MyCustomRule"
    description: "Detect custom pattern"
    severity: "MEDIUM"
    expression: "request.url.matches('(?i)my-pattern')"
    action: "BLOCK"  # или "MONITOR"
    score: 0.7
```

Синтаксис CEL выражений:
- `request.url` - полный URL
- `request.path` - путь
- `request.query` - параметры запроса
- `request.method` - HTTP метод
- `request.headers` - заголовки
- `ip` - IP адрес клиента
- `tenant_id` - ID тенанта

### Rate Limiting

Rate limiting работает в двух режимах:

1. **Redis** (production):
   - Требует запущенный Redis
   - Распределённый счётчик

2. **In-memory fallback** (development):
   - Автоматически используется если Redis недоступен

---

## Устранение проблем

### WAF не запускается

```
Error: config: listen_addr is required
```

Проверьте что `config.yaml` содержит `listen_addr`.

### Все запросы блокируются

Проверьте логи:
```bash
./waf-bin 2>&1 | grep -i "blocked"
```

Возможно слишком агрессивные правила.

### Rate Limiting не работает

Проверьте подключение к Redis:
```bash
redis-cli ping
# Должен ответить: PONG
```

### Высокая латентность

Запустите профилирование:
```bash
go tool pprof http://localhost:6060/debug/pprof/profile
```

---

## Примеры использования в коде

### Python клиент

```python
import requests

# Легитимный запрос
response = requests.get("http://localhost:8080/api/users")
print(response.status_code)  # 200

# SQL Injection - блокировка
response = requests.get("http://localhost:8080/search?q=1' OR 1=1--")
print(response.status_code)  # 403
```

### Go клиент

```go
resp, err := http.Get("http://localhost:8080/api/data")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
fmt.Printf("Status: %d\n", resp.StatusCode)
```

---

## Контакты и поддержка

Для вопросов и предложений создайте issue в репозитории проекта.
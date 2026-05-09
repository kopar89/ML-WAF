package metrics

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Экспортер предоставляет метрики Prometheus для WAF
type Exporter struct {
	requestsTotal    prometheus.Counter
	blockedTotal     prometheus.Counter
	proxiedTotal     prometheus.Counter
	rateLimitedTotal prometheus.Counter
	latencyHistogram prometheus.Histogram
	riskScoreGauge   prometheus.Gauge

	legacyRequests    int64
	legacyBlocked     int64
	legacyProxied     int64
	legacyRateLimited int64
	legacyLatencyMs   int64
}

// создается новый объект Exporter и регистрируются метрики Prometheus
func New() *Exporter {
	e := &Exporter{
		requestsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "waf_requests_total",
			Help: "Total number of requests processed.",
		}),
		blockedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "waf_blocked_total",
			Help: "Total number of blocked requests.",
		}),
		proxiedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "waf_proxied_total",
			Help: "Total number of proxied requests.",
		}),
		rateLimitedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "waf_rate_limited_total",
			Help: "Total number of rate-limited requests.",
		}),
		latencyHistogram: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "waf_request_duration_ms",
			Help:    "Request latency in milliseconds.",
			Buckets: prometheus.DefBuckets,
		}),
		riskScoreGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "waf_risk_score",
			Help: "Current risk score of the last evaluated request.",
		}),
	}

	prometheus.MustRegister(e.requestsTotal)
	prometheus.MustRegister(e.blockedTotal)
	prometheus.MustRegister(e.proxiedTotal)
	prometheus.MustRegister(e.rateLimitedTotal)
	prometheus.MustRegister(e.latencyHistogram)
	prometheus.MustRegister(e.riskScoreGauge)

	return e
}

// функция IncRequests увеличивает счетчик запросов
func (e *Exporter) IncRequests() {
	atomic.AddInt64(&e.legacyRequests, 1)
	e.requestsTotal.Inc()
}

// IncBlocked увеличивает счетчик заблокированных устройств
func (e *Exporter) IncBlocked() {
	atomic.AddInt64(&e.legacyBlocked, 1)
	e.blockedTotal.Inc()
}

// IncProxied увеличивает счетчик проксированных соединений
func (e *Exporter) IncProxied() {
	atomic.AddInt64(&e.legacyProxied, 1)
	e.proxiedTotal.Inc()
}

// IncRateLimited увеличивает счетчик ограничений скорости
func (e *Exporter) IncRateLimited() {
	atomic.AddInt64(&e.legacyRateLimited, 1)
	e.rateLimitedTotal.Inc()
}

// функция AddLatency регистрирует задержку запроса
func (e *Exporter) AddLatency(d time.Duration) {
	ms := float64(d) / float64(time.Millisecond)
	atomic.AddInt64(&e.legacyLatencyMs, int64(ms))
	e.latencyHistogram.Observe(ms)
}

// функция SetRiskScore устанавливает текущий уровень оценки риска
func (e *Exporter) SetRiskScore(score float64) {
	e.riskScoreGauge.Set(score)
}

// ServeHTTP предоставляет метрики по адресу /metrics.
func (e *Exporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

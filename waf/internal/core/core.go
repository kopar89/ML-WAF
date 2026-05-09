package core

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"waf/internal/config"
	"waf/internal/metrics"
	"waf/internal/middleware"
	"waf/internal/publisher"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ThreatLevel отражает степень серьезности обнаруженной угрозы.
type ThreatLevel int

const (
	ThreatLevelLow ThreatLevel = iota
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

func (t ThreatLevel) String() string {
	switch t {
	case ThreatLevelLow:
		return "LOW"
	case ThreatLevelMedium:
		return "MEDIUM"
	case ThreatLevelHigh:
		return "HIGH"
	case ThreatLevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// RequestContext содержит весь контекст для одного запроса.
type RequestContext struct {
	RequestID   string
	TenantID    string
	IP          string
	Method      string
	URL         string
	Headers     map[string]string
	JWTClaims   map[string]interface{}
	RiskScore   float64
	MLScore     float64
	Fingerprint string
	SessionID   string
	blocked     bool
	threatLevel ThreatLevel
}

// IsBlocked возвращает значение, указывающее, был ли запрос заблокирован.
func (rc *RequestContext) IsBlocked() bool { return rc.blocked }

// GetThreatLevel возвращает уровень доверия
func (rc *RequestContext) GetThreatLevel() ThreatLevel { return rc.threatLevel }

// SecurityEvaluator
type SecurityEvaluator interface {
	Evaluate(ctx *RequestContext) (*SecurityResult, error)
}

// SecurityResult оценка юезопасности
type SecurityResult struct {
	Blocked bool
	Score   float64
	Level   ThreatLevel
	Reason  string
}

// WAFCore является центральным механизмом WAF, координирующим все подсистемы
type WAFCore struct {
	cfg         *config.Config
	security    SecurityEvaluator
	rateLimiter *middleware.RateLimiter
	eventPub    *publisher.EventPublisher
	metrics     *metrics.Exporter
	logger      *zap.Logger
	proxy       *httputil.ReverseProxy
	backendURL  *url.URL
	server      *http.Server
	mu          sync.RWMutex
	quit        chan struct{}
}

// Создание нового экземпляра WAFCore.
func New(cfg *config.Config, logger *zap.Logger, sec SecurityEvaluator) (*WAFCore, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("core: invalid config: %w", err)
	}

	backendURL, err := url.Parse(cfg.BackendURL)
	if err != nil {
		return nil, fmt.Errorf("core: invalid backend URL: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	rl, err := middleware.NewRateLimiter(cfg.Redis, logger)
	if err != nil {
		return nil, fmt.Errorf("core: rate limiter init: %w", err)
	}

	ep := publisher.New(logger)
	metricsExporter := metrics.New()

	return &WAFCore{
		cfg:         cfg,
		security:    sec,
		rateLimiter: rl,
		eventPub:    ep,
		metrics:     metricsExporter,
		logger:      logger,
		proxy:       proxy,
		backendURL:  backendURL,
		quit:        make(chan struct{}),
	}, nil
}

// Start начинает прослушивать и обрабатывать запросы.
func (w *WAFCore) Start() error {
	w.cfg.Subscribe(w)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", w.handleHealth)
	mux.HandleFunc("/metrics", w.handleMetrics)
	mux.HandleFunc("/", w.handleRequest)

	w.server = &http.Server{
		Addr:         w.cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  w.cfg.ReadTimeout,
		WriteTimeout: w.cfg.WriteTimeout,
	}

	w.logger.Info("WAFCore starting",
		zap.String("listen_addr", w.cfg.ListenAddr),
		zap.String("backend_url", w.cfg.BackendURL),
	)

	return w.server.ListenAndServe()
}

// Stop корректно завершает работу сервера.
func (w *WAFCore) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), w.cfg.ShutdownTimeout)
	defer cancel()

	w.cfg.Unsubscribe(w)

	if err := w.server.Shutdown(ctx); err != nil {
		w.logger.Error("server shutdown error", zap.Error(err))
	}

	w.eventPub.Stop()
	w.logger.Info("event publisher stopped")

	if err := w.rateLimiter.Close(); err != nil {
		w.logger.Error("rate limiter close error", zap.Error(err))
	}

	close(w.quit)
	w.logger.Info("WAFCore stopped gracefully")
	return nil
}

// OnConfigChanged обрабатывает перезагрузку конфигурации.
func (w *WAFCore) OnConfigChanged(oldCfg, newCfg *config.Config) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.logger.Info("config changed, reloading subsystems",
		zap.String("old_backend", oldCfg.BackendURL),
		zap.String("new_backend", newCfg.BackendURL),
	)

	if oldCfg.BackendURL != newCfg.BackendURL {
		backendURL, err := url.Parse(newCfg.BackendURL)
		if err != nil {
			return fmt.Errorf("core: invalid new backend URL: %w", err)
		}
		w.backendURL = backendURL
		w.proxy = httputil.NewSingleHostReverseProxy(backendURL)
	}

	return nil
}

func (w *WAFCore) handleHealth(resp http.ResponseWriter, req *http.Request) {
	resp.WriteHeader(http.StatusOK)
	fmt.Fprintln(resp, "OK")
}

func (w *WAFCore) handleMetrics(resp http.ResponseWriter, req *http.Request) {
	w.metrics.ServeHTTP(resp, req)
}

func (w *WAFCore) handleRequest(resp http.ResponseWriter, req *http.Request) {
	start := time.Now()
	w.metrics.IncRequests()

	ctx := w.buildContext(req)

	if !w.rateLimiter.Allow(ctx.TenantID, req.RemoteAddr, req.URL.Path) {
		w.metrics.IncRateLimited()
		w.metrics.IncBlocked()
		resp.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintln(resp, "429 Too Many Requests")
		w.eventPub.Publish("waf.security.rate_limit.exceeded", map[string]interface{}{
			"request_id": ctx.RequestID,
			"tenant_id":  ctx.TenantID,
			"ip":         req.RemoteAddr,
			"path":       req.URL.Path,
		})
		w.logger.Warn("rate limit exceeded",
			zap.String("request_id", ctx.RequestID),
			zap.String("tenant_id", ctx.TenantID),
			zap.String("ip", req.RemoteAddr),
		)
		return
	}

	result, err := w.security.Evaluate(ctx)
	if err != nil {
		w.logger.Error("security evaluation failed", zap.Error(err))
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	ctx.RiskScore = result.Score
	if result.Blocked {
		w.metrics.IncBlocked()
		resp.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(resp, "403 Forbidden: %s\n", result.Reason)
		w.eventPub.Publish("waf.security.attack.blocked", map[string]interface{}{
			"request_id":   ctx.RequestID,
			"tenant_id":    ctx.TenantID,
			"ip":           req.RemoteAddr,
			"path":         req.URL.Path,
			"risk_score":   ctx.RiskScore,
			"threat_level": result.Level.String(),
			"reason":       result.Reason,
		})
		w.logger.Warn("request blocked",
			zap.String("request_id", ctx.RequestID),
			zap.Float64("risk_score", ctx.RiskScore),
			zap.String("reason", result.Reason),
		)
		return
	}

	w.proxy.ServeHTTP(resp, req)

	latency := time.Since(start)
	w.metrics.AddLatency(latency)
	w.metrics.IncProxied()

	w.logger.Info("request proxied",
		zap.String("request_id", ctx.RequestID),
		zap.String("method", req.Method),
		zap.String("path", req.URL.Path),
		zap.Float64("risk_score", ctx.RiskScore),
		zap.Duration("latency", latency),
	)
}

func (w *WAFCore) buildContext(req *http.Request) *RequestContext {
	requestID := req.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = uuid.New().String()
	}

	tenantID := req.Header.Get("X-Tenant-Id")
	if tenantID == "" {
		tenantID = w.cfg.Tenant.TenantID
	}

	fp := fmt.Sprintf("%x", md5.Sum([]byte(req.RemoteAddr+req.UserAgent())))

	headers := make(map[string]string)
	for k, v := range req.Header {
		headers[k] = v[0]
	}

	return &RequestContext{
		RequestID:   requestID,
		TenantID:    tenantID,
		IP:          req.RemoteAddr,
		Method:      req.Method,
		URL:         req.URL.String(),
		Headers:     headers,
		JWTClaims:   map[string]interface{}{},
		Fingerprint: fp,
		SessionID:   req.Header.Get("Cookie"),
	}
}

package middleware

import (
	"context"
	"fmt"
	"sync"
	"time"

	"waf/internal/config"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
)

type RateLimiterConfig struct {
	Limit  int
	Window time.Duration
}

func NewRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		Limit:  100,
		Window: 60 * time.Second,
	}
}

func (c *RateLimiterConfig) UpdateFromEnv() {
	if limit := config.GetEnvInt("WAF_RATE_LIMIT", 0); limit > 0 {
		c.Limit = limit
	}
	if window := config.GetEnvDuration("WAF_RATE_WINDOW", 0); window > 0 {
		c.Window = window
	}
}

type RateLimiter struct {
	client *redis.Client
	logger *zap.Logger
	cfg    *RateLimiterConfig
	mu     sync.RWMutex
}

func NewRateLimiter(cfg config.RedisConfig, logger *zap.Logger) (*RateLimiter, error) {
	rlCfg := NewRateLimiterConfig()
	rlCfg.UpdateFromEnv()

	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     10,
		MinIdleConns: 2,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		logger.Warn("redis not available, using in-memory fallback", zap.Error(err))
		return &RateLimiter{
			client: nil,
			logger: logger,
			cfg:    rlCfg,
		}, nil
	}

	logger.Info("rate limiter connected to Redis", zap.String("addr", cfg.Addr))
	return &RateLimiter{
		client: client,
		logger: logger,
		cfg:    rlCfg,
	}, nil
}

func (rl *RateLimiter) Allow(tenantID, ip, path string) bool {
	key := fmt.Sprintf("ratelimit:%s:%s", tenantID, ip)

	if rl.client == nil {
		return rl.fallbackAllow(key)
	}

	return rl.redisAllow(key)
}

func (rl *RateLimiter) redisAllow(key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	pipe := rl.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, rl.cfg.Window)

	_, err := pipe.Exec(ctx)
	if err != nil {
		rl.logger.Error("redis rate limit error", zap.Error(err))
		return rl.fallbackAllow(key)
	}

	return incr.Val() <= int64(rl.cfg.Limit)
}

type memEntry struct {
	count       int
	windowStart time.Time
}

type fallbackStoreType struct {
	mu   sync.RWMutex
	data map[string]*memEntry
}

var fallbackStore = fallbackStoreType{data: make(map[string]*memEntry)}

func (rl *RateLimiter) fallbackAllow(key string) bool {
	fallbackStore.mu.Lock()
	defer fallbackStore.mu.Unlock()

	now := time.Now()
	entry, exists := fallbackStore.data[key]

	if !exists || now.Sub(entry.windowStart) > rl.cfg.Window {
		fallbackStore.data[key] = &memEntry{
			count:       1,
			windowStart: now,
		}
		return true
	}

	entry.count++
	return entry.count <= rl.cfg.Limit
}

func (rl *RateLimiter) Close() error {
	if rl.client != nil {
		return rl.client.Close()
	}
	return nil
}

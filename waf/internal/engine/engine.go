package engine

import (
	"fmt"
	"os"

	"waf/internal/core"
	"waf/internal/detectors"
	"waf/pkg/cel"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Rule описывает отдельное правило безопасности, загруженное из YAML-файла
type Rule struct {
	Name        string  `yaml:"name"`
	Description string  `yaml:"description"`
	Severity    string  `yaml:"severity"`
	Expression  string  `yaml:"expression"`
	Action      string  `yaml:"action"`
	Score       float64 `yaml:"score"`
}

// RuleSet набор правил
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// RuleManager управляет и оценивает правила, основанные на CEL
type RuleManager struct {
	rules  []Rule
	logger *zap.Logger
}

// NewRuleManager создает объект RuleManager и загружает правила из файла
func NewRuleManager(rulesFile string, logger *zap.Logger) (*RuleManager, error) {
	rm := &RuleManager{logger: logger}
	if err := rm.LoadRules(rulesFile); err != nil {
		return nil, fmt.Errorf("rulemanager: load rules: %w", err)
	}
	return rm, nil
}

// LoadRules читает и анализирует файл правил YAML.
func (rm *RuleManager) LoadRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("load rules file: %w", err)
	}

	var set RuleSet
	if err := yaml.Unmarshal(data, &set); err != nil {
		return fmt.Errorf("parse rules: %w", err)
	}
	rm.rules = set.Rules
	rm.logger.Info("rules loaded", zap.Int("count", len(rm.rules)))
	return nil
}

// функция evaluate выполняет проверку всех правил в контексте запроса и возвращает результат
func (rm *RuleManager) Evaluate(ctx *core.RequestContext) *core.SecurityResult {
	result := &core.SecurityResult{
		Score: 0,
		Level: core.ThreatLevelLow,
	}

	for _, rule := range rm.rules {
		match, err := cel.Evaluate(rule.Expression, map[string]interface{}{
			"request": map[string]interface{}{
				"method":  ctx.Method,
				"url":     ctx.URL,
				"path":    extractPath(ctx.URL),
				"query":   extractQuery(ctx.URL),
				"headers": ctx.Headers,
				"body":    "",
			},
			"ip":        ctx.IP,
			"tenant_id": ctx.TenantID,
		})
		if err != nil {
			rm.logger.Debug("rule eval error", zap.String("rule", rule.Name), zap.Error(err))
			continue
		}

		if match {
			result.Score += rule.Score
			rm.logger.Debug("rule matched",
				zap.String("rule", rule.Name),
				zap.Float64("score", rule.Score),
			)

			if rule.Action == "BLOCK" {
				result.Blocked = true
				result.Reason = rule.Description
				result.Level = severityToLevel(rule.Severity)
				return result
			}
		}
	}

	result.Level = scoreToLevel(result.Score)
	if result.Score > 0.85 {
		result.Blocked = true
		result.Reason = "risk score threshold exceeded"
	}
	return result
}

// SecurityEngine координирует оценку правил. Он реализует core.SecurityEvaluator
type SecurityEngine struct {
	ruleManager *RuleManager
	detectors   []detectors.Detector
	logger      *zap.Logger
}

// NewSecurityEngine создаёт объект SecurityEngine с правилами, загруженными из файла
func NewSecurityEngine(rulesFile string, logger *zap.Logger) (*SecurityEngine, error) {
	rm, err := NewRuleManager(rulesFile, logger)
	if err != nil {
		return nil, err
	}
	return &SecurityEngine{
		ruleManager: rm,
		detectors:   detectors.All(),
		logger:      logger,
	}, nil
}

// Evaluate запускает конвейер безопасности: детекторы + правила CEL.
func (se *SecurityEngine) Evaluate(ctx *core.RequestContext) (*core.SecurityResult, error) {
	result := &core.SecurityResult{
		Score: 0,
		Level: core.ThreatLevelLow,
	}

	// этап 1: запуск детектеров
	for _, d := range se.detectors {
		if d.IsTriggered(ctx) {
			result.Score += d.Score()
			se.logger.Debug("detector triggered",
				zap.String("detector", d.Name()),
				zap.String("category", d.Category()),
				zap.Float64("score", d.Score()),
			)
			if d.Severity() == "CRITICAL" || d.Severity() == "HIGH" {
				result.Blocked = true
				result.Reason = fmt.Sprintf("%s: %s", d.Category(), d.Name())
				result.Level = severityToLevel(d.Severity())
				return result, nil
			}
		}
	}

	// этап 2: запуск CEL правил
	ruleResult := se.ruleManager.Evaluate(ctx)
	result.Score += ruleResult.Score

	if ruleResult.Blocked && !result.Blocked {
		result.Blocked = ruleResult.Blocked
		result.Reason = ruleResult.Reason
		result.Level = ruleResult.Level
	}

	if result.Score >= 0.85 && !result.Blocked {
		result.Blocked = true
		result.Reason = "cumulative risk score threshold exceeded"
		result.Level = core.ThreatLevelCritical
	}

	if result.Level == core.ThreatLevelLow {
		result.Level = scoreToLevel(result.Score)
	}

	return result, nil
}

func extractPath(rawURL string) string {
	for i, c := range rawURL {
		if c == '?' {
			return rawURL[:i]
		}
	}
	return rawURL
}

func extractQuery(rawURL string) string {
	for i, c := range rawURL {
		if c == '?' {
			return rawURL[i+1:]
		}
	}
	return ""
}

func severityToLevel(s string) core.ThreatLevel {
	switch s {
	case "CRITICAL":
		return core.ThreatLevelCritical
	case "HIGH":
		return core.ThreatLevelHigh
	case "MEDIUM":
		return core.ThreatLevelMedium
	default:
		return core.ThreatLevelLow
	}
}

func scoreToLevel(score float64) core.ThreatLevel {
	switch {
	case score >= 0.85:
		return core.ThreatLevelCritical
	case score >= 0.65:
		return core.ThreatLevelHigh
	case score >= 0.30:
		return core.ThreatLevelMedium
	default:
		return core.ThreatLevelLow
	}
}

package cel

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

// функция evaluate компилирует и вычисляет выражение CEL, используя заданные переменные
// возвращает true, если выражение оценивается как истинное (совпадение), false в противном случае
func Evaluate(expression string, vars map[string]interface{}) (bool, error) {
	if expression == "" {
		return false, nil
	}

	env, err := cel.NewEnv(
		ext.Strings(),
		cel.Variable("request", cel.DynType),
		cel.Variable("ip", cel.DynType),
		cel.Variable("tenant_id", cel.DynType),
	)
	if err != nil {
		return false, fmt.Errorf("cel: env creation: %w", err)
	}

	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return false, fmt.Errorf("cel: compile %q: %w", expression, issues.Err())
	}

	prg, err := env.Program(ast)
	if err != nil {
		return false, fmt.Errorf("cel: program: %w", err)
	}

	out, _, err := prg.Eval(vars)
	if err != nil {
		return false, fmt.Errorf("cel: eval: %w", err)
	}

	switch v := out.Value().(type) {
	case bool:
		return v, nil
	case string:
		return v != "", nil
	default:
		return false, nil
	}
}

// ContainsAny проверяет, содержит ли строка какие-либо из подстрок (регистр не учитывается)
func ContainsAny(s string, substrings []string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrings {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// HasPrefix проверяет, имеет ли s какой-либо из заданных префиксов
func HasPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// энтропия вычисляет энтропию шеннона для строки
func Entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	var ent float64
	n := float64(len(s))
	for _, count := range freq {
		p := float64(count) / n
		ent -= p * log2(p)
	}
	return ent
}

// функция log2 вычисляет логарифм по основанию 2, используя целочисленное приближение
func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	result := 0.0
	for x < 1 {
		x *= 2
		result--
	}
	for x >= 2 {
		x /= 2
		result++
	}
	return result
}

package detectors

import (
	"regexp"
	"strings"
	"sync"

	"waf/internal/core"
)

type Detector interface {
	Name() string
	Category() string
	Severity() string
	Score() float64
	IsTriggered(ctx *core.RequestContext) bool
}

type compiledPattern struct {
	re   *regexp.Regexp
	once sync.Once
}

var patterns = struct {
	sqlInjection    compiledPattern
	xss             compiledPattern
	cmdi            compiledPattern
	ssrf            compiledPattern
	xxe             compiledPattern
	pathTraversal   compiledPattern
	fileInclusion   compiledPattern
	cookieTampering compiledPattern
}{
	sqlInjection:    compiledPattern{},
	xss:             compiledPattern{},
	cmdi:            compiledPattern{},
	ssrf:            compiledPattern{},
	xxe:             compiledPattern{},
	pathTraversal:   compiledPattern{},
	fileInclusion:   compiledPattern{},
	cookieTampering: compiledPattern{},
}

func getSQLiPattern() *regexp.Regexp {
	patterns.sqlInjection.once.Do(func() {
		patterns.sqlInjection.re = regexp.MustCompile(`(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|exec\s+|xp_cmdshell)`)
	})
	return patterns.sqlInjection.re
}

func getXSSPattern() *regexp.Regexp {
	patterns.xss.once.Do(func() {
		patterns.xss.re = regexp.MustCompile(`(?i)(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)`)
	})
	return patterns.xss.re
}

func getCmdIPattern() *regexp.Regexp {
	patterns.cmdi.once.Do(func() {
		patterns.cmdi.re = regexp.MustCompile(`(?i)(whoami|cat\s+/etc|rm\s+-rf|wget\s+http|curl\s+http|/bin/sh)`)
	})
	return patterns.cmdi.re
}

func getSSRFPattern() *regexp.Regexp {
	patterns.ssrf.once.Do(func() {
		patterns.ssrf.re = regexp.MustCompile(`(?i)(127\.0\.0\.1|localhost|169\.254\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)`)
	})
	return patterns.ssrf.re
}

func getXXEPattern() *regexp.Regexp {
	patterns.xxe.once.Do(func() {
		patterns.xxe.re = regexp.MustCompile(`(?i)(<!DOCTYPE|<!ENTITY|SYSTEM\s+)`)
	})
	return patterns.xxe.re
}

func getPathTraversalPattern() *regexp.Regexp {
	patterns.pathTraversal.once.Do(func() {
		patterns.pathTraversal.re = regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e)`)
	})
	return patterns.pathTraversal.re
}

func getFileInclusionPattern() *regexp.Regexp {
	patterns.fileInclusion.once.Do(func() {
		patterns.fileInclusion.re = regexp.MustCompile(`(?i)(file://|php://|expect://|data://)`)
	})
	return patterns.fileInclusion.re
}

func getCookieTamperingPattern() *regexp.Regexp {
	patterns.cookieTampering.once.Do(func() {
		patterns.cookieTampering.re = regexp.MustCompile(`(?i)(admin\s*=\s*true|role\s*=\s*admin|is_admin\s*=\s*1)`)
	})
	return patterns.cookieTampering.re
}

type SQLInjectionDetector struct{}

func (d *SQLInjectionDetector) Name() string     { return "SQLInjectionDetector" }
func (d *SQLInjectionDetector) Category() string { return "SQL Injection" }
func (d *SQLInjectionDetector) Severity() string { return "CRITICAL" }
func (d *SQLInjectionDetector) Score() float64   { return 0.9 }

func (d *SQLInjectionDetector) IsTriggered(ctx *core.RequestContext) bool {
	re := getSQLiPattern()
	return re.MatchString(ctx.URL) || re.MatchString(queryString(ctx.URL))
}

type XSSDetector struct{}

func (d *XSSDetector) Name() string     { return "XSSDetector" }
func (d *XSSDetector) Category() string { return "XSS" }
func (d *XSSDetector) Severity() string { return "HIGH" }
func (d *XSSDetector) Score() float64   { return 0.85 }

func (d *XSSDetector) IsTriggered(ctx *core.RequestContext) bool {
	re := getXSSPattern()
	return re.MatchString(ctx.URL) || re.MatchString(queryString(ctx.URL))
}

type CommandInjectionDetector struct{}

func (d *CommandInjectionDetector) Name() string     { return "CommandInjectionDetector" }
func (d *CommandInjectionDetector) Category() string { return "Command Injection" }
func (d *CommandInjectionDetector) Severity() string { return "CRITICAL" }
func (d *CommandInjectionDetector) Score() float64   { return 0.95 }

func (d *CommandInjectionDetector) IsTriggered(ctx *core.RequestContext) bool {
	payloads := []string{";", "&&", "||", "`", "$(", "|", ">", "<"}
	for _, p := range payloads {
		if strings.Contains(queryString(ctx.URL), p) {
			if p == ";" {
				if !strings.Contains(queryString(ctx.URL), "\\;") {
					return true
				}
			} else {
				return true
			}
		}
	}
	re := getCmdIPattern()
	return re.MatchString(queryString(ctx.URL))
}

type SSRFDetector struct{}

func (d *SSRFDetector) Name() string     { return "SSRFDetector" }
func (d *SSRFDetector) Category() string { return "SSRF" }
func (d *SSRFDetector) Severity() string { return "HIGH" }
func (d *SSRFDetector) Score() float64   { return 0.85 }

func (d *SSRFDetector) IsTriggered(ctx *core.RequestContext) bool {
	re := getSSRFPattern()
	return re.MatchString(ctx.URL)
}

type XXEDetector struct{}

func (d *XXEDetector) Name() string     { return "XXEDetector" }
func (d *XXEDetector) Category() string { return "XXE" }
func (d *XXEDetector) Severity() string { return "HIGH" }
func (d *XXEDetector) Score() float64   { return 0.85 }

func (d *XXEDetector) IsTriggered(ctx *core.RequestContext) bool {
	ct := strings.ToLower(ctx.Headers["Content-Type"])
	if strings.Contains(ct, "xml") {
		re := getXXEPattern()
		return re.MatchString(ctx.URL)
	}
	return false
}

type PathTraversalDetector struct{}

func (d *PathTraversalDetector) Name() string     { return "PathTraversalDetector" }
func (d *PathTraversalDetector) Category() string { return "Path Traversal" }
func (d *PathTraversalDetector) Severity() string { return "HIGH" }
func (d *PathTraversalDetector) Score() float64   { return 0.8 }

func (d *PathTraversalDetector) IsTriggered(ctx *core.RequestContext) bool {
	re := getPathTraversalPattern()
	return re.MatchString(ctx.URL)
}

type FileInclusionDetector struct{}

func (d *FileInclusionDetector) Name() string     { return "FileInclusionDetector" }
func (d *FileInclusionDetector) Category() string { return "File Inclusion" }
func (d *FileInclusionDetector) Severity() string { return "HIGH" }
func (d *FileInclusionDetector) Score() float64   { return 0.85 }

func (d *FileInclusionDetector) IsTriggered(ctx *core.RequestContext) bool {
	re := getFileInclusionPattern()
	return re.MatchString(ctx.URL) || re.MatchString(queryString(ctx.URL))
}

type CookieTamperingDetector struct{}

func (d *CookieTamperingDetector) Name() string     { return "CookieTamperingDetector" }
func (d *CookieTamperingDetector) Category() string { return "Cookie Tampering" }
func (d *CookieTamperingDetector) Severity() string { return "MEDIUM" }
func (d *CookieTamperingDetector) Score() float64   { return 0.7 }

func (d *CookieTamperingDetector) IsTriggered(ctx *core.RequestContext) bool {
	re := getCookieTamperingPattern()
	return re.MatchString(ctx.SessionID)
}

func All() []Detector {
	return []Detector{
		&SQLInjectionDetector{},
		&XSSDetector{},
		&CommandInjectionDetector{},
		&SSRFDetector{},
		&XXEDetector{},
		&PathTraversalDetector{},
		&FileInclusionDetector{},
		&CookieTamperingDetector{},
	}
}

func queryString(rawURL string) string {
	for i, c := range rawURL {
		if c == '?' {
			return rawURL[i+1:]
		}
	}
	return ""
}

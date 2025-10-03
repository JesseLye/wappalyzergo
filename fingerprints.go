package wappalyzer

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Fingerprints contains a map of fingerprints for tech detection
type Fingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*Fingerprint `json:"apps"`
}

// Fingerprint is a single piece of information about a tech validated and normalized
type Fingerprint struct {
	Cats        []int                             `json:"cats"`
	CSS         []string                          `json:"css"`
	Cookies     map[string]string                 `json:"cookies"`
	Dom         map[string]map[string]interface{} `json:"dom"`
	JS          map[string]string                 `json:"js"`
	Headers     map[string]string                 `json:"headers"`
	HTML        []string                          `json:"html"`
	Script      []string                          `json:"scripts"`
	ScriptSrc   []string                          `json:"scriptSrc"`
	Meta        map[string][]string               `json:"meta"`
	Implies     []string                          `json:"implies"`
	Description string                            `json:"description"`
	Website     string                            `json:"website"`
	CPE         string                            `json:"cpe"`
	Icon        string                            `json:"icon"`
}

// CompiledFingerprints contains a map of fingerprints for tech detection
type CompiledFingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*CompiledFingerprint
}

// CompiledFingerprint contains the compiled fingerprints from the tech json
type CompiledFingerprint struct {
	// cats contain categories that are implicit with this tech
	cats []int
	// implies contains technologies that are implicit with this tech
	implies []string
	// description contains fingerprint description
	description string
	// website contains a URL associated with the fingerprint
	website string
	// icon contains a Icon associated with the fingerprint
	icon string
	// cookies contains fingerprints for target cookies
	cookies []ParsedFingerprintPair
	// js contains fingerprints for the js file
	js map[string]*ParsedPattern
	// dom contains fingerprints for the target dom
	dom map[string]map[string]*ParsedPattern
	// headers contains fingerprints for target headers
	headers []ParsedFingerprintPair
	// html contains fingerprints for the target HTML
	html []*ParsedPattern
	// script contains fingerprints for scripts
	script []*ParsedPattern
	// scriptSrc contains fingerprints for script srcs
	scriptSrc []*ParsedPattern
	// meta contains fingerprints for meta tags
	meta map[string][]*ParsedPattern
	// cpe contains the cpe for a fingerpritn
	cpe string
}

func (f *CompiledFingerprint) GetJSRules() map[string]*ParsedPattern {
	return f.js
}

func (f *CompiledFingerprint) GetDOMRules() map[string]map[string]*ParsedPattern {
	return f.dom
}

type FingerprintPair struct {
	Key   string
	Value string
}

type ParsedFingerprintPair struct {
	Key     string
	Pattern *ParsedPattern
}

// AppInfo contains basic information about an App.
type AppInfo struct {
	Description string
	Website     string
	CPE         string
	Icon        string
	Categories  []string
}

// CatsInfo contains basic information about an App.
type CatsInfo struct {
	Cats []int
}

// part is the part of the fingerprint to match
type part int

// parts that can be matched
const (
	cookiesPart part = iota + 1
	jsPart
	headersPart
	htmlPart
	scriptPart
	metaPart
)

// identify substrings for sorting (hack)
const (
	versionSubstring    = "version:"
	confidenceSubstring = "confidence:"
)

func extractConfidence(s string) int {
	if !strings.Contains(s, confidenceSubstring) {
		return -1
	}
	parts := strings.Split(s, confidenceSubstring)
	if len(parts) < 2 {
		return -1
	}
	val, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return -1
	}
	return val
}

func getFingerprintOrder(a string, b string) bool {
	aHasVersion := strings.Contains(a, versionSubstring)
	bHasVersion := strings.Contains(b, versionSubstring)

	aConf := extractConfidence(a)
	bConf := extractConfidence(b)

	// 1. Version without confidence comes first
	if aHasVersion && aConf == -1 && (!bHasVersion || bConf != -1) {
		return true
	}
	if bHasVersion && bConf == -1 && (!aHasVersion || aConf != -1) {
		return false
	}

	// 2. Version with confidence, ordered by descending confidence
	if aHasVersion && bHasVersion && aConf != -1 && bConf != -1 {
		return aConf > bConf
	}

	// 3. Version with confidence vs version without confidence
	if aHasVersion && aConf != -1 && bHasVersion && bConf == -1 {
		return false
	}
	if bHasVersion && bConf != -1 && aHasVersion && aConf == -1 {
		return true
	}

	// 4. Detection only goes last
	if !aHasVersion && bHasVersion {
		return false
	}
	if aHasVersion && !bHasVersion {
		return true
	}

	// 5. Tie-breaker: alphabetical
	return a < b
}

func sortFingerprintPairs(headers []FingerprintPair) []FingerprintPair {
	newHeaders := make([]FingerprintPair, len(headers))
	copy(newHeaders, headers)

	sort.Slice(newHeaders, func(i int, j int) bool {
		return getFingerprintOrder(newHeaders[i].Value, newHeaders[j].Value)
	})

	return newHeaders
}

func mapToFingerprintPairs(inputMap map[string]string) []FingerprintPair {
	headers := make([]FingerprintPair, 0, len(inputMap))
	for key, value := range inputMap {
		newHeader := FingerprintPair{
			Key:   key,
			Value: value,
		}
		headers = append(headers, newHeader)
	}
	return headers
}

func parseHeaders(headers []FingerprintPair) ([]ParsedFingerprintPair, error) {
	parsedHeaders := make([]ParsedFingerprintPair, 0, len(headers))
	for _, header := range headers {
		fingerprint, err := ParsePattern(header.Value)
		if err != nil {
			return nil, err
		}
		newParsedHeader := ParsedFingerprintPair{
			Key:     header.Key,
			Pattern: fingerprint,
		}
		parsedHeaders = append(parsedHeaders, newParsedHeader)
	}
	return parsedHeaders, nil
}

// loadPatterns loads the fingerprint patterns and compiles regexes
func compileFingerprint(fingerprint *Fingerprint) *CompiledFingerprint {
	compiled := &CompiledFingerprint{
		cats:        fingerprint.Cats,
		implies:     fingerprint.Implies,
		description: fingerprint.Description,
		website:     fingerprint.Website,
		icon:        fingerprint.Icon,
		dom:         make(map[string]map[string]*ParsedPattern),
		cookies:     make([]ParsedFingerprintPair, 0),
		js:          make(map[string]*ParsedPattern),
		headers:     make([]ParsedFingerprintPair, 0),
		html:        make([]*ParsedPattern, 0, len(fingerprint.HTML)),
		script:      make([]*ParsedPattern, 0, len(fingerprint.Script)),
		scriptSrc:   make([]*ParsedPattern, 0, len(fingerprint.ScriptSrc)),
		meta:        make(map[string][]*ParsedPattern),
		cpe:         fingerprint.CPE,
	}

	for dom, patterns := range fingerprint.Dom {
		compiled.dom[dom] = make(map[string]*ParsedPattern)

		for attr, value := range patterns {
			switch attr {
			case "exists", "text":
				pattern, err := ParsePattern(value.(string))
				if err != nil {
					continue
				}
				compiled.dom[dom]["main"] = pattern
			case "attributes":
				attrMap, ok := value.(map[string]interface{})
				if !ok {
					continue
				}
				compiled.dom[dom] = make(map[string]*ParsedPattern)
				for attrName, value := range attrMap {
					pattern, err := ParsePattern(value.(string))
					if err != nil {
						continue
					}
					compiled.dom[dom][attrName] = pattern
				}
			}
		}
	}

	cookieHeaders := mapToFingerprintPairs(fingerprint.Cookies)
	sortedCookieHeaders := sortFingerprintPairs(cookieHeaders)
	parsedCookieHeaders, err := parseHeaders(sortedCookieHeaders)
	// Don't worry about the error, just carry along
	if err == nil {
		compiled.cookies = parsedCookieHeaders
	}

	for k, pattern := range fingerprint.JS {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.js[k] = fingerprint
	}

	headers := mapToFingerprintPairs(fingerprint.Headers)
	sortedHeaders := sortFingerprintPairs(headers)
	parsedHeaders, err := parseHeaders(sortedHeaders)
	if err == nil {
		compiled.headers = parsedHeaders
	}

	for _, pattern := range fingerprint.HTML {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.html = append(compiled.html, fingerprint)
	}

	for _, pattern := range fingerprint.Script {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.script = append(compiled.script, fingerprint)
	}

	for _, pattern := range fingerprint.ScriptSrc {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.scriptSrc = append(compiled.scriptSrc, fingerprint)
	}

	for meta, patterns := range fingerprint.Meta {
		var compiledList []*ParsedPattern

		sortedPatterns := make([]string, len(patterns))
		copy(sortedPatterns, patterns)

		sort.Slice(sortedPatterns, func(i int, j int) bool {
			return getFingerprintOrder(sortedPatterns[i], sortedPatterns[j])
		})

		for _, pattern := range sortedPatterns {
			fingerprint, err := ParsePattern(pattern)
			if err != nil {
				continue
			}
			compiledList = append(compiledList, fingerprint)
		}
		compiled.meta[meta] = compiledList
	}
	return compiled
}

// matchString matches a string for the fingerprints
func (f *CompiledFingerprints) matchString(data string, part part) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		confidence := 100

		switch part {
		case jsPart:
			for _, pattern := range fingerprint.js {
				if valid, versionString := pattern.Evaluate(data); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
				}
			}
		case scriptPart:
			for _, pattern := range fingerprint.scriptSrc {
				if valid, versionString := pattern.Evaluate(data); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
				}
			}
		case htmlPart:
			for _, pattern := range fingerprint.html {
				if valid, versionString := pattern.Evaluate(data); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

// matchKeyValue matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchKeyValueString(key, value string, part part) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		confidence := 100

		switch part {
		case cookiesPart:
			for _, header := range fingerprint.cookies {
				if header.Key != key {
					continue
				}

				if valid, versionString := header.Pattern.Evaluate(value); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = header.Pattern.Confidence
					break
				}
			}
		case headersPart:
			for _, header := range fingerprint.headers {
				if header.Key != key {
					continue
				}

				if valid, versionString := header.Pattern.Evaluate(value); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = header.Pattern.Confidence
					break
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				if data != key {
					continue
				}

				for _, pattern := range patterns {
					if valid, versionString := pattern.Evaluate(value); valid {
						matched = true
						if version == "" && versionString != "" {
							version = versionString
						}
						confidence = pattern.Confidence
						break
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

// matchMapString matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchMapString(keyValue map[string]string, part part) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		confidence := 100

		switch part {
		case cookiesPart:
			for _, header := range fingerprint.cookies {
				value, ok := keyValue[header.Key]
				if !ok {
					continue
				}
				if header.Pattern == nil {
					matched = true
				}

				if valid, versionString := header.Pattern.Evaluate(value); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = header.Pattern.Confidence
					break
				}
			}
		case headersPart:
			for _, header := range fingerprint.headers {
				value, ok := keyValue[header.Key]
				if !ok {
					continue
				}
				if header.Pattern == nil {
					matched = true
				}

				if valid, versionString := header.Pattern.Evaluate(value); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = header.Pattern.Confidence
					break
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				value, ok := keyValue[data]
				if !ok {
					continue
				}

				for _, pattern := range patterns {
					if valid, versionString := pattern.Evaluate(value); valid {
						matched = true
						if version == "" && versionString != "" {
							version = versionString
						}
						confidence = pattern.Confidence
						break
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

func FormatAppVersion(app, version string) string {
	if version == "" {
		return app
	}
	return fmt.Sprintf("%s:%s", app, version)
}

// GetFingerprints returns the fingerprint string from wappalyzer
func GetFingerprints() string {
	return fingerprints
}

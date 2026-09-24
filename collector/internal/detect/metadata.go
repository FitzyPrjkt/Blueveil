// Detection-engineering metadata (13F.4): static, code-derived facts about
// every rule — no runtime code loading, no remote rules, no arbitrary
// execution. Describe works for any Rule (unknown ids get an honest
// "general" fallback); stateful threshold/window come from the instance
// via Thresholded. Enabled is set by the engine health view; Describe
// alone reports the registration default (true).
package detect

import (
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/threatintel"
)

// Thresholded is implemented by stateful rules to expose their configured
// threshold and window for metadata and health views.
type Thresholded interface {
	ThresholdWindow() (threshold int, window time.Duration)
}

// Metadata is the engineering record for one rule.
type Metadata struct {
	ID              string
	Version         string
	Title           string
	Description     string
	Domain          string
	EventTypes      []string
	SeverityBasis   string
	ConfidenceBasis string
	Stateful        bool
	Threshold       int
	Window          time.Duration
	HasThreshold    bool
	Enabled         bool
}

type staticMeta struct {
	domain        string
	eventTypes    []string
	severityBasis string
}

var metadataTable = map[string]staticMeta{
	"waf-block-high-severity":         {"waf", []string{"waf.request_blocked"}, "source"},
	"waf-block-burst":                 {"waf", []string{"waf.request_blocked"}, "source-peak"},
	"source-declared-critical":        {"general", []string{}, "source"},
	"net-disallowed-destination":      {"network", []string{"net.connection"}, "policy"},
	"net-connection-burst":            {"network", []string{"net.connection"}, "source-peak"},
	"net-denied-repeated":             {"network", []string{"net.connection"}, "source-peak"},
	"http-error-burst":                {"application", []string{"http.request"}, "source-peak"},
	"auth-failure-burst":              {"application", []string{"http.request"}, "source-peak"},
	"app-policy-violation":            {"application", []string{"http.request"}, "policy"},
	"endpoint-privilege-change":       {"endpoint", []string{"endpoint.activity"}, "source"},
	"server-service-failure-burst":    {"server", []string{"server.activity"}, "source-peak"},
	"container-risky-runtime-policy":  {"container", []string{"container.activity"}, "policy"},
	"cloud-denied-action-burst":       {"cloud", []string{"cloud.activity"}, "source-peak"},
	"identity-privilege-change":       {"identity", []string{"identity.activity"}, "source"},
	"ident-auth-failure-burst":        {"authentication", []string{"auth.activity"}, "source-peak"},
	"ident-auth-denied-burst":         {"authentication", []string{"auth.activity"}, "source-peak"},
	"sensitive-data-policy-violation": {"data", []string{"data.activity"}, "policy"},
	"configured-ioc-match":            {"threat-intel", []string{"*"}, "policy"},
	"multi-stage-correlated-activity": {"siem", []string{"auth.activity", "identity.activity"}, "source-peak"},
	"detection-rule-error-burst":      {"engine-health", []string{}, "source-peak"},
	"repeated-cross-domain-principal-activity": {
		"investigation", []string{"auth.activity", "identity.activity", "data.activity", "net.connection", "http.request", "endpoint.activity", "server.activity", "container.activity", "cloud.activity"}, "source-peak",
	},
	"multi-stage-asset-timeline": {"investigation", []string{"net.connection", "http.request", "endpoint.activity", "server.activity"}, "source-peak"},
	"forensic-integrity-failure": {"investigation", []string{}, "policy"},
}

// Catalogue returns engineering records for every known statically
// implemented rule in a fixed order. Stateful entries report Stateful=true
// but carry no threshold/window: those are per-deployment configuration,
// visible on live engine health — never invented here.
func mustEngine() *Engine {
	eng, err := NewEngine(time.Now)
	if err != nil {
		panic("detect: catalogue engine: " + err.Error())
	}
	return eng
}

func Catalogue() []Metadata {
	must := func(r Rule, err error) Rule {
		if err != nil {
			panic("detect: catalogue construction: " + err.Error())
		}
		return r
	}
	rules := []Rule{
		BlockHighSeverityRule{},
		SourceCriticalRule{},
		IdentityPrivilegeChangeRule{},
		EndpointPrivilegeChangeRule{},
		must(NewBlockBurstRule(3, 5*time.Minute, time.Now)),
		must(NewNetDisallowedDestinationRule([]DisallowedTarget{
			{Label: "catalogue-placeholder", DstIP: "127.0.0.1", Severity: v1.Severity_SEVERITY_LOW},
		})),
		must(NewNetConnectionBurstRule(3, 5*time.Minute, time.Now)),
		must(NewNetDeniedActivityRule(3, 5*time.Minute, time.Now)),
		must(NewHTTPErrorBurstRule(3, 5*time.Minute, time.Now)),
		must(NewAuthFailureBurstRule(3, 5*time.Minute, time.Now)),
		must(NewAppPolicyViolationRule(AppPolicy{DisallowedMethods: []string{"TRACE"}, Severity: v1.Severity_SEVERITY_LOW})),
		must(NewServerServiceFailureBurstRule(3, 5*time.Minute, time.Now)),
		must(NewContainerRiskyRuntimePolicyRule(ContainerPolicy{Privileged: true, Severity: v1.Severity_SEVERITY_LOW})),
		must(NewCloudDeniedActionBurstRule(3, 5*time.Minute, time.Now)),
		must(NewIdentAuthFailureBurstRule(3, 5*time.Minute, time.Now)),
		must(NewIdentAuthDeniedBurstRule(3, 5*time.Minute, time.Now)),
		must(NewSensitiveDataPolicyRule(SensitiveDataPolicy{
			Label: "catalogue-placeholder", Severity: v1.Severity_SEVERITY_LOW, Actions: []string{"export"},
		})),
		must(NewConfiguredIOCMatchRule(
			threatintel.Set{ID: "catalogue", Version: "0", Entries: []threatintel.Entry{{Kind: "ip", Value: "127.0.0.1", Source: "catalogue"}}},
			v1.Severity_SEVERITY_LOW, "catalogue-placeholder")),
		must(NewMultiStageCorrelatedRule(2, 10*time.Minute, time.Now)),
		must(NewRuleErrorBurstRule(mustEngine(), 3, 5*time.Minute)),
		must(NewCrossDomainPrincipalRule(2, 30*time.Minute, time.Now)),
		must(NewMultiStageAssetTimelineRule(10*time.Minute, time.Now)),
		must(NewForensicIntegrityFailureRule()),
	}
	out := make([]Metadata, 0, len(rules))
	for _, r := range rules {
		m := Describe(r)
		m.Threshold, m.Window, m.HasThreshold = 0, 0, false
		out = append(out, m)
	}
	return out
}

// Describe returns the engineering record for a rule. Unknown rule ids
// (e.g. test doubles) get domain "general" rather than a fabricated entry.
func Describe(rule Rule) Metadata {
	m := Metadata{
		ID: rule.ID(), Version: rule.Version(),
		Title: rule.Name(), Description: rule.Description(),
		ConfidenceBasis: ConfidenceBasis, Enabled: true,
	}
	if s, ok := metadataTable[rule.ID()]; ok {
		m.Domain = s.domain
		m.EventTypes = append([]string(nil), s.eventTypes...)
		m.SeverityBasis = s.severityBasis
	} else {
		m.Domain = "general"
		m.SeverityBasis = "source"
	}
	if t, ok := rule.(Thresholded); ok {
		m.Stateful = true
		m.Threshold, m.Window = t.ThresholdWindow()
		m.HasThreshold = true
	}
	return m
}

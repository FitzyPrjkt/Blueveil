// Continuous security checks C1–C5 (13J.13): deterministic, bounded,
// policy-driven observations over persisted supply-chain state. Each
// check has a stable rule ID, version, description, and domain, with an
// enabled flag consistent with detection metadata patterns. Outcomes are
// PASS/FAIL/NOT_APPLICABLE/DISABLED — observations about policy posture,
// never compromise verdicts, never scores. This is not a second
// detection engine: checks evaluate stored state on demand, they do not
// consume telemetry streams.
package supplychain

import (
	"fmt"
	"sort"
	"time"
)

// CheckID values are stable rule identifiers.
type CheckID string

const (
	CheckIDMissingSBOM          CheckID = "supply-missing-sbom"
	CheckIDUnverifiedProvenance CheckID = "supply-unverified-provenance"
	CheckIDPolicyViolation      CheckID = "supply-policy-violation"
	CheckIDStaleVendor          CheckID = "supply-stale-vendor-assessment"
	CheckIDRegression           CheckID = "supply-posture-regression"
)

// CheckVersion pins all continuous-check semantics.
const CheckVersion = "1"

// CheckOutcome bounds check outputs.
type CheckOutcome string

const (
	CheckPass          CheckOutcome = "PASS"
	CheckFail          CheckOutcome = "FAIL"
	CheckNotApplicable CheckOutcome = "NOT_APPLICABLE"
	CheckDisabled      CheckOutcome = "DISABLED"
)

// CheckResult is one deterministic check observation with basis.
type CheckResult struct {
	RuleID    CheckID
	Version   string
	SubjectID string
	Outcome   CheckOutcome
	Basis     string
}

// CheckConfig is the explicit declarative configuration. Zero values
// disable dimensions (never defaults that imply verdicts).
type CheckConfig struct {
	RequireSBOM       bool
	RequireProvenance bool
	AllowedProvenance []Provenance
	Policies          []SupplyPolicy
	VendorWindow      time.Duration
	Enabled           map[CheckID]bool
}

func checkEnabled(cfg CheckConfig, id CheckID) (CheckResult, bool) {
	if cfg.Enabled != nil {
		if on, ok := cfg.Enabled[id]; ok && !on {
			return CheckResult{RuleID: id, Version: CheckVersion, Outcome: CheckDisabled, Basis: "check disabled by configuration"}, true
		}
	}
	return CheckResult{}, false
}

// CheckIDMissingSBOM (C1): a component explicitly requiring SBOM coverage
// has none observed. SBOM coverage is exact component-id membership.
func CheckMissingSBOM(c Component, sboms []SBOM, cfg CheckConfig) CheckResult {
	if disabled, ok := checkEnabled(cfg, CheckIDMissingSBOM); ok {
		disabled.SubjectID = c.ID()
		return disabled
	}
	if !cfg.RequireSBOM {
		return CheckResult{RuleID: CheckIDMissingSBOM, Version: CheckVersion, SubjectID: c.ID(), Outcome: CheckNotApplicable, Basis: "SBOM coverage not required by configuration"}
	}
	for _, s := range sboms {
		for _, id := range s.ComponentIDs {
			if id == c.ID() {
				return CheckResult{RuleID: CheckIDMissingSBOM, Version: CheckVersion, SubjectID: c.ID(), Outcome: CheckPass, Basis: "component covered by observed SBOM"}
			}
		}
	}
	return CheckResult{RuleID: CheckIDMissingSBOM, Version: CheckVersion, SubjectID: c.ID(), Outcome: CheckFail, Basis: "SBOM required but no SBOM references this component"}
}

// CheckIDUnverifiedProvenance (C2): a component under provenance policy
// lacks required provenance.
func CheckUnverifiedProvenance(c Component, cfg CheckConfig) CheckResult {
	if disabled, ok := checkEnabled(cfg, CheckIDUnverifiedProvenance); ok {
		disabled.SubjectID = c.ID()
		return disabled
	}
	if !cfg.RequireProvenance && len(cfg.AllowedProvenance) == 0 {
		return CheckResult{RuleID: CheckIDUnverifiedProvenance, Version: CheckVersion, SubjectID: c.ID(), Outcome: CheckNotApplicable, Basis: "provenance policy not configured"}
	}
	if len(cfg.AllowedProvenance) > 0 {
		for _, p := range cfg.AllowedProvenance {
			if p == c.Provenance {
				return CheckResult{RuleID: CheckIDUnverifiedProvenance, Version: CheckVersion, SubjectID: c.ID(), Outcome: CheckPass, Basis: "provenance " + string(c.Provenance) + " allowed"}
			}
		}
		return CheckResult{RuleID: CheckIDUnverifiedProvenance, Version: CheckVersion, SubjectID: c.ID(), Outcome: CheckFail, Basis: "provenance " + string(c.Provenance) + " not in allowed set"}
	}
	return CheckResult{RuleID: CheckIDUnverifiedProvenance, Version: CheckVersion, SubjectID: c.ID(), Outcome: CheckPass, Basis: "provenance recorded"}
}

// CheckIDPolicyViolation (C3): a component violates an explicitly
// configured policy. First violating policy wins, deterministically by
// policy id order.
func CheckPolicyViolation(c Component, cfg CheckConfig) CheckResult {
	if disabled, ok := checkEnabled(cfg, CheckIDPolicyViolation); ok {
		disabled.SubjectID = c.ID()
		return disabled
	}
	if len(cfg.Policies) == 0 {
		return CheckResult{RuleID: CheckIDPolicyViolation, Version: CheckVersion, SubjectID: c.ID(), Outcome: CheckNotApplicable, Basis: "no policies configured"}
	}
	pols := append([]SupplyPolicy(nil), cfg.Policies...)
	sort.Slice(pols, func(i, j int) bool { return pols[i].ID < pols[j].ID })
	for _, p := range pols {
		res := EvaluatePolicy(c, p)
		if res.Verdict == PolicyViolation {
			reasons := append([]string(nil), res.Reasons...)
			sort.Strings(reasons)
			basis := "policy " + p.ID + " violated"
			if len(reasons) > 0 {
				basis += ": " + reasons[0]
			}
			return CheckResult{RuleID: CheckIDPolicyViolation, Version: CheckVersion, SubjectID: c.ID(), Outcome: CheckFail, Basis: basis}
		}
	}
	return CheckResult{RuleID: CheckIDPolicyViolation, Version: CheckVersion, SubjectID: c.ID(), Outcome: CheckPass, Basis: "no configured policy violated"}
}

// CheckIDStaleVendor (C4): the newest assessment for a vendor is past the
// configured window. No assessment at all is NOT_APPLICABLE, not failure.
func CheckStaleVendor(vendorID string, assessments []VendorAssessment, cfg CheckConfig, now time.Time) CheckResult {
	if disabled, ok := checkEnabled(cfg, CheckIDStaleVendor); ok {
		disabled.SubjectID = vendorID
		return disabled
	}
	if cfg.VendorWindow <= 0 {
		return CheckResult{RuleID: CheckIDStaleVendor, Version: CheckVersion, SubjectID: vendorID, Outcome: CheckNotApplicable, Basis: "vendor window not configured"}
	}
	var newest *VendorAssessment
	for i, a := range assessments {
		if a.VendorID != vendorID {
			continue
		}
		if newest == nil || a.ObservedAt.After(newest.ObservedAt) {
			newest = &assessments[i]
		}
	}
	if newest == nil {
		return CheckResult{RuleID: CheckIDStaleVendor, Version: CheckVersion, SubjectID: vendorID, Outcome: CheckNotApplicable, Basis: "no assessment recorded for vendor"}
	}
	if IsAssessmentStale(newest.ObservedAt, cfg.VendorWindow, now) {
		return CheckResult{RuleID: CheckIDStaleVendor, Version: CheckVersion, SubjectID: vendorID, Outcome: CheckFail, Basis: fmt.Sprintf("newest assessment %s past window %s", newest.ObservedAt.UTC().Format(time.RFC3339), cfg.VendorWindow)}
	}
	return CheckResult{RuleID: CheckIDStaleVendor, Version: CheckVersion, SubjectID: vendorID, Outcome: CheckPass, Basis: "assessment within window"}
}

// statusRank orders known statuses from weaker to stronger for
// regression comparison. Unranked states never participate.
func statusRank(s ComponentStatus) (int, bool) {
	switch s {
	case StatusUnknown, StatusNotAssessed:
		return 0, true
	case StatusObserved:
		return 1, true
	case StatusOutdated, StatusUnsupported:
		return 2, true
	case StatusPolicyViolation:
		return 3, true
	case StatusVerified:
		return 4, true
	default:
		return 0, false
	}
}

// CheckIDRegression (C5): the current status is strictly weaker than the
// previously recorded status for the same subject. Unknown previous
// state is NOT_APPLICABLE — regression is never inferred from telemetry
// or from nothing.
func CheckRegression(subjectID string, current Component, previous map[string]ComponentStatus, cfg CheckConfig) CheckResult {
	if disabled, ok := checkEnabled(cfg, CheckIDRegression); ok {
		disabled.SubjectID = subjectID
		return disabled
	}
	prev, ok := previous[subjectID]
	if !ok {
		return CheckResult{RuleID: CheckIDRegression, Version: CheckVersion, SubjectID: subjectID, Outcome: CheckNotApplicable, Basis: "no previous status recorded"}
	}
	oldRank, oldOK := statusRank(prev)
	newRank, newOK := statusRank(current.Status)
	if !oldOK || !newOK || oldRank == 0 {
		return CheckResult{RuleID: CheckIDRegression, Version: CheckVersion, SubjectID: subjectID, Outcome: CheckNotApplicable, Basis: "unranked state cannot regress"}
	}
	if newRank < oldRank {
		return CheckResult{RuleID: CheckIDRegression, Version: CheckVersion, SubjectID: subjectID, Outcome: CheckFail, Basis: fmt.Sprintf("status moved %s to %s", prev, current.Status)}
	}
	return CheckResult{RuleID: CheckIDRegression, Version: CheckVersion, SubjectID: subjectID, Outcome: CheckPass, Basis: "status not weaker than recorded"}
}

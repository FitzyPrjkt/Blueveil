package response

import (
	"testing"

	v1 "blueveil/collector/internal/contract/v1"
)

func req(actor string, op v1.OperationType, risk v1.RiskLevel) ActionRequest {
	return ActionRequest{Actor: actor, Operation: op, Target: "asset-1", Risk: risk}
}

func TestDefaultPolicyAllowDenyApproval(t *testing.T) {
	p := DefaultPolicy{}
	if d, _ := p.Decide(req("analyst", v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_LOW)); d != DecisionAllow {
		t.Fatal("read-only low-risk must allow")
	}
	if d, _ := p.Decide(req("analyst", v1.OperationType_OPERATION_TYPE_RECOMMEND, v1.RiskLevel_RISK_LEVEL_MEDIUM)); d != DecisionAllow {
		t.Fatal("recommend/medium must allow")
	}
	if d, _ := p.Decide(req("analyst", v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_HIGH)); d != DecisionRequireApproval {
		t.Fatal("high risk must require approval")
	}
	if d, _ := p.Decide(req("analyst", v1.OperationType_OPERATION_TYPE_ANALYZE, v1.RiskLevel_RISK_LEVEL_CRITICAL)); d != DecisionRequireApproval {
		t.Fatal("critical risk must require approval")
	}
	for _, op := range []v1.OperationType{
		v1.OperationType_OPERATION_TYPE_BLOCK,
		v1.OperationType_OPERATION_TYPE_ISOLATE,
		v1.OperationType_OPERATION_TYPE_DELETE,
		v1.OperationType_OPERATION_TYPE_EXECUTE,
	} {
		if d, _ := p.Decide(req("analyst", op, v1.RiskLevel_RISK_LEVEL_LOW)); d != DecisionRequireApproval {
			t.Fatalf("destructive %v must require approval even at LOW", op)
		}
	}
}

func TestDefaultPolicyFailClosed(t *testing.T) {
	p := DefaultPolicy{}
	// Unknown operation → deny (never allow).
	if d, _ := p.Decide(req("analyst", v1.OperationType(999), v1.RiskLevel_RISK_LEVEL_LOW)); d != DecisionDeny {
		t.Fatal("unknown operation must deny")
	}
	if d, _ := p.Decide(req("analyst", v1.OperationType_OPERATION_TYPE_UNSPECIFIED, v1.RiskLevel_RISK_LEVEL_LOW)); d != DecisionDeny {
		t.Fatal("unspecified operation must deny")
	}
	// Unknown risk → deny (never allow, never bare approval).
	if d, _ := p.Decide(req("analyst", v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel(999))); d != DecisionDeny {
		t.Fatal("unknown risk must deny")
	}
	if d, _ := p.Decide(req("analyst", v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_UNSPECIFIED)); d != DecisionDeny {
		t.Fatal("unspecified risk must deny")
	}
	// Empty actor → deny with error.
	if d, err := p.Decide(req("", v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_LOW)); d != DecisionDeny || err == nil {
		t.Fatal("anonymous request must deny with error")
	}
}

func TestStaticPolicies(t *testing.T) {
	r := req("analyst", v1.OperationType_OPERATION_TYPE_OBSERVE, v1.RiskLevel_RISK_LEVEL_LOW)
	if d, _ := StaticAllowAll().Decide(r); d != DecisionAllow {
		t.Fatal("allow-all must allow")
	}
	if d, _ := StaticDenyAll().Decide(r); d != DecisionDeny {
		t.Fatal("deny-all must deny")
	}
	if d, _ := StaticRequireApproval().Decide(r); d != DecisionRequireApproval {
		t.Fatal("require-approval must park")
	}
}

// Command seed writes a deterministic, labeled-synthetic lab dataset into
// a SQLite database for the Security Workstation UI. It reuses the real
// pipeline, response engine, and validation providers with a fixed clock —
// no fabricated findings. Probe fixtures (e.g. the rule-error probe) are
// explicit synthetic telemetry, validated downstream like everything else.
// Refuses non-empty databases unless --force is given.
package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"blueveil/collector/internal/asset"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/detect"
	"blueveil/collector/internal/enrich"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/grc"
	"blueveil/collector/internal/httpobs"
	"blueveil/collector/internal/identobs"
	"blueveil/collector/internal/incident"
	"blueveil/collector/internal/infraobs"
	"blueveil/collector/internal/netobs"
	"blueveil/collector/internal/pipeline"
	"blueveil/collector/internal/response"
	"blueveil/collector/internal/source"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/store/postgres"
	"blueveil/collector/internal/store/sqlite"
	"blueveil/collector/internal/supplychain"
	"blueveil/collector/internal/threatintel"
	"blueveil/collector/internal/validation"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// seedIOCSet is the offline lab IOC set: TEST-NET documentation values
// only, clearly synthetic, never fetched from anywhere. It must stay
// byte-identical to testdata/lab-iocs.json (the file serve --ioc-set
// consumes); seed_test.go enforces this.
const seedIOCSet = `[
  {"kind":"ip","value":"203.0.113.7","source":"lab-ioc-v1"},
  {"kind":"domain","value":"Test-IOC-Sink.EXAMPLE.","source":"lab-ioc-v1"},
  {"kind":"sha256","value":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","source":"lab-ioc-v1"}
]`

// errorProbeRule is a seed-only controlled fixture: it errors loudly on
// the synthetic probe type so T3 has a deterministic error burst to
// aggregate. It matches nothing and corrupts no production state.
type errorProbeRule struct{}

func (errorProbeRule) ID() string      { return "seed-error-probe" }
func (errorProbeRule) Version() string { return "1" }
func (errorProbeRule) Name() string    { return "Seed error probe" }
func (errorProbeRule) Description() string {
	return "Seed-only fixture that errors on test.rule-error-probe events for T3 lab coverage."
}
func (errorProbeRule) Evaluate(event *v1.TelemetryEvent) (detect.Outcome, error) {
	if event.GetEventType() == "test.rule-error-probe" {
		return detect.Outcome{}, fmt.Errorf("seed-error-probe: controlled fixture error")
	}
	return detect.Outcome{}, nil
}

var seedClock = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

func seedClockFn() time.Time { return seedClock }

func runSeed(dbPath string, force bool) error {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: dbPath})
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	return runSeedOnBackend(ctx, db.Backend(), dbPath, force, func(out sqlite.PipelineOutputs) error {
		return sqlite.PersistRunTx(ctx, db, out)
	})
}

// runSeedPG seeds the deterministic lab dataset into PostgreSQL (Step 15
// smoke/ops path). Same dataset, same functions — only the persistence
// boundary differs.
func runSeedPG(ctx context.Context, pgCfg postgres.Config, force bool) error {
	db, err := postgres.Open(ctx, pgCfg)
	if err != nil {
		return err
	}
	defer db.Close()
	label := "postgres@" + pgCfg.Host + "/" + pgCfg.DBName
	return runSeedOnBackend(ctx, db.Backend(), label, force, func(out sqlite.PipelineOutputs) error {
		return postgres.PersistRunTx(ctx, db, postgres.PipelineOutputs{
			Telemetry:  out.Telemetry,
			Detections: out.Detections,
			Alerts:     out.Alerts,
			Incidents:  out.Incidents,
			Evidence:   out.Evidence,
		})
	})
}

func runSeedOnBackend(ctx context.Context, be store.Backend, dbPath string, force bool, persist func(sqlite.PipelineOutputs) error) error {
	if !force {
		existing, err := be.Incident.List(ctx)
		if err != nil {
			return err
		}
		if len(existing) > 0 {
			return fmt.Errorf("database %s already holds %d incident(s): refuse without --force", dbPath, len(existing))
		}
	}

	// Lab events: four WAF (self-test parity) plus eight deterministic
	// network observations that exercise the full 13B chain:
	//  normal (accepted) → nothing, disallow → detection, burst 3 →
	//  burst detection, denied 3 → denied-repeat detection. All synthetic,
	//  labeled, loopback or TEST-NET / RFC1918 only — never a real scan.
	now := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	mk := func(id, typ, sev string, minute int) source.RawEvent {
		return source.RawEvent{
			ID: id, Source: "seed-lab", AssetID: "asset-seed-01",
			EventType: typ, Severity: sev,
			Attributes: map[string]string{
				"_note":   "synthetic seed data, not a finding",
				"rule_id": "SEED-WAF-01",
			},
			OccurredAt: now.Add(time.Duration(minute) * time.Minute),
		}
	}
	mkNet := func(id string, minute int, sev string, attrs map[string]string) source.RawEvent {
		merged := map[string]string{
			"_note":   "synthetic seed data, not a finding",
			"rule_id": "SEED-NET-01",
		}
		for k, v := range attrs {
			merged[k] = v
		}
		return source.RawEvent{
			ID: id, Source: "seed-lab-net", AssetID: "seed-net-01",
			EventType: netobs.EventTypeConnection, Severity: sev,
			Attributes: merged,
			OccurredAt: now.Add(time.Duration(minute) * time.Minute),
		}
	}
	mkHTTP := func(id string, minute int, sev string, attrs map[string]string) source.RawEvent {
		merged := map[string]string{
			"_note":   "synthetic seed data, not a finding",
			"rule_id": "SEED-HTTP-01",
		}
		for k, v := range attrs {
			merged[k] = v
		}
		return source.RawEvent{
			ID: id, Source: "seed-lab-http", AssetID: "seed-http-01",
			EventType: httpobs.EventTypeHTTPRequest, Severity: sev,
			Attributes: merged,
			OccurredAt: now.Add(time.Duration(minute) * time.Minute),
		}
	}
	mkInfra := func(id string, minute int, typ string, sev string, attrs map[string]string) source.RawEvent {
		merged := map[string]string{
			"_note":   "synthetic seed data, not a finding",
			"rule_id": "SEED-INFRA-01",
		}
		for k, v := range attrs {
			merged[k] = v
		}
		return source.RawEvent{
			ID: id, Source: "seed-lab-infra", AssetID: "seed-infra-01",
			EventType: typ, Severity: sev,
			Attributes: merged,
			OccurredAt: now.Add(time.Duration(minute) * time.Minute),
		}
	}
	mkIdent := func(id string, minute int, typ string, sev string, attrs map[string]string) source.RawEvent {
		merged := map[string]string{
			"_note":   "synthetic seed data, not a finding",
			"rule_id": "SEED-IDENT-01",
		}
		for k, v := range attrs {
			merged[k] = v
		}
		return source.RawEvent{
			ID: id, Source: "seed-lab-identity", AssetID: "seed-ident-01",
			EventType: typ, Severity: sev,
			Attributes: merged,
			OccurredAt: now.Add(time.Duration(minute) * time.Minute),
		}
	}
	mkMon := func(id string, minute int, typ string, sev string, asset string, attrs map[string]string) source.RawEvent {
		merged := map[string]string{
			"_note":   "synthetic seed data, not a finding",
			"rule_id": "SEED-MON-01",
		}
		for k, v := range attrs {
			merged[k] = v
		}
		return source.RawEvent{
			ID: id, Source: "seed-lab-monitoring", AssetID: asset,
			EventType: typ, Severity: sev,
			Attributes: merged,
			OccurredAt: now.Add(time.Duration(minute) * time.Minute),
		}
	}
	mkInv := func(id string, minute int, typ string, sev string, attrs map[string]string) source.RawEvent {
		merged := map[string]string{
			"_note":   "synthetic seed data, not a finding",
			"rule_id": "SEED-INV-01",
		}
		for k, v := range attrs {
			merged[k] = v
		}
		return source.RawEvent{
			ID: id, Source: "seed-lab-investigation", AssetID: "seed-inv-01",
			EventType: typ, Severity: sev,
			Attributes: merged,
			OccurredAt: now.Add(time.Duration(minute) * time.Minute),
		}
	}
	src := source.NewChannelSource(128)
	sink := &pipeline.InMemorySink{}
	en, err := enrich.New("seed", seedClockFn)
	if err != nil {
		return err
	}
	eng, err := detect.NewEngine(seedClockFn)
	if err != nil {
		return err
	}
	for _, r := range []detect.Rule{detect.BlockHighSeverityRule{}, detect.SourceCriticalRule{}} {
		if err := eng.RegisterRule(r); err != nil {
			return err
		}
	}
	burst, err := detect.NewBlockBurstRule(3, 5*time.Minute, seedClockFn)
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(burst); err != nil {
		return err
	}
	// Network defense: explicit policy (no hard-coded malicious ports),
	// burst and denied thresholds — all construction-validated.
	disallow, err := detect.NewNetDisallowedDestinationRule([]detect.DisallowedTarget{
		{DstIP: "203.0.113.7", DstPort: 4444, HasPort: true, Protocol: "TCP", Severity: v1.Severity_SEVERITY_HIGH, Label: "lab-disallow-203.0.113.7:4444"},
	})
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(disallow); err != nil {
		return err
	}
	netBurst, err := detect.NewNetConnectionBurstRule(3, 5*time.Minute, seedClockFn)
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(netBurst); err != nil {
		return err
	}
	netDenied, err := detect.NewNetDeniedActivityRule(3, 5*time.Minute, seedClockFn)
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(netDenied); err != nil {
		return err
	}
	// Application defense: HTTP error burst, auth failure burst, policy violation
	httpBurst, err := detect.NewHTTPErrorBurstRule(3, 5*time.Minute, seedClockFn)
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(httpBurst); err != nil {
		return err
	}
	authBurst, err := detect.NewAuthFailureBurstRule(3, 5*time.Minute, seedClockFn)
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(authBurst); err != nil {
		return err
	}
	appPolicy, err := detect.NewAppPolicyViolationRule(detect.AppPolicy{
		DisallowedMethods: []string{"TRACE"}, DisallowedRoutes: []string{"/admin"}, DisallowedContentTypes: []string{"text/html"},
		Severity: v1.Severity_SEVERITY_MEDIUM,
	})
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(appPolicy); err != nil {
		return err
	}
	if err := eng.RegisterRule(detect.EndpointPrivilegeChangeRule{}); err != nil {
		return err
	}
	serverBurst, err := detect.NewServerServiceFailureBurstRule(3, 5*time.Minute, seedClockFn)
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(serverBurst); err != nil {
		return err
	}
	containerPolicy, err := detect.NewContainerRiskyRuntimePolicyRule(detect.ContainerPolicy{Privileged: true, HostNetwork: true, HostPID: true, Severity: v1.Severity_SEVERITY_MEDIUM})
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(containerPolicy); err != nil {
		return err
	}
	cloudBurst, err := detect.NewCloudDeniedActionBurstRule(3, 5*time.Minute, seedClockFn)
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(cloudBurst); err != nil {
		return err
	}
	// Identity, authentication & data-security defense: privilege change,
	// auth failure/denied bursts, sensitive-data policy — all explicit.
	if err := eng.RegisterRule(detect.IdentityPrivilegeChangeRule{}); err != nil {
		return err
	}
	identFailure, err := detect.NewIdentAuthFailureBurstRule(3, 5*time.Minute, seedClockFn)
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(identFailure); err != nil {
		return err
	}
	identDenied, err := detect.NewIdentAuthDeniedBurstRule(3, 5*time.Minute, seedClockFn)
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(identDenied); err != nil {
		return err
	}
	dataPolicy, err := detect.NewSensitiveDataPolicyRule(detect.SensitiveDataPolicy{
		Classifications: []string{"restricted"},
		Actions:         []string{"export"},
		Severity:        v1.Severity_SEVERITY_HIGH,
		Label:           "lab-restricted-export",
	})
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(dataPolicy); err != nil {
		return err
	}
	// Monitoring / threat-intel defense: offline IOC set (Python-
	// normalized, local file only), IOC-match and multi-stage rules,
	// plus the controlled error-probe fixture for T3 lab coverage.
	iocSet, err := threatintel.LoadSetBytes([]byte(seedIOCSet), "seedIOCSet", "lab-ioc-set", "v1")
	if err != nil {
		return err
	}
	iocRule, err := detect.NewConfiguredIOCMatchRule(iocSet, v1.Severity_SEVERITY_MEDIUM, "lab-ioc-policy")
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(iocRule); err != nil {
		return err
	}
	multiStage, err := detect.NewMultiStageCorrelatedRule(2, 10*time.Minute, seedClockFn)
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(multiStage); err != nil {
		return err
	}
	if err := eng.RegisterRule(errorProbeRule{}); err != nil {
		return err
	}
	// Investigation signals: cross-domain principal (H1) and multi-stage
	// asset timeline (H2) evaluate per event; integrity failures (H3) are
	// filed batch-style after the run (see seedIntegrityCheck).
	crossDomain, err := detect.NewCrossDomainPrincipalRule(2, 30*time.Minute, seedClockFn)
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(crossDomain); err != nil {
		return err
	}
	assetTimeline, err := detect.NewMultiStageAssetTimelineRule(10*time.Minute, seedClockFn)
	if err != nil {
		return err
	}
	if err := eng.RegisterRule(assetTimeline); err != nil {
		return err
	}
	mgr, err := incident.NewManager(seedClockFn)
	if err != nil {
		return err
	}
	evStore := evidence.NewStore()
	detStore := &detect.Store{}
	stage, err := pipeline.NewIncidentSink(eng, mgr, evStore, detStore, sink, sink)
	if err != nil {
		return err
	}
	// Asset correlation for network + HTTP + infra observations.
	assetMgrEarly, err := asset.NewManager(be.Assets, storeAssetRelStore{be.Relationships}, seedClockFn)
	if err != nil {
		return err
	}
	netCorr, err := netobs.NewCorrelator(assetMgrEarly, be.Relationships, netobs.CorrelateConfig{
		AllowAutoCreate: true, LocalPrefixes: []string{"127.0.0.0/8", "10.0.0.0/8"},
	})
	if err != nil {
		return err
	}
	netSink, err := netobs.NewCorrelatingSink(netCorr, stage)
	if err != nil {
		return err
	}
	httpCorr, err := httpobs.NewHTTPCorrelator(assetMgrEarly, be.Relationships, httpobs.HTTPCorrelateConfig{
		AllowAutoCreate: true, AllowedHosts: []string{"seed-lab.example", "example.com"},
	})
	if err != nil {
		return err
	}
	httpSink, err := httpobs.NewCorrelatingSink(httpCorr, netSink)
	if err != nil {
		return err
	}
	infraCorr, err := infraobs.NewInfraCorrelator(assetMgrEarly, be.Relationships, infraobs.InfraCorrelateConfig{
		AllowAutoCreate: true, AllowedHosts: []string{"web01", "srv-01", "cluster-01", "aws", "seed-lab.example"},
	})
	if err != nil {
		return err
	}
	infraSink, err := infraobs.NewCorrelatingSink(infraCorr, httpSink)
	if err != nil {
		return err
	}
	identCorr, err := identobs.NewIdentCorrelator(assetMgrEarly, be.Relationships, identobs.IdentCorrelateConfig{
		AllowAutoCreate: true, AllowedPrincipals: []string{"alice", "bob", "carol", "dave"},
	})
	if err != nil {
		return err
	}
	identSink, err := identobs.NewCorrelatingSink(identCorr, infraSink)
	if err != nil {
		return err
	}
	pipe, err := pipeline.NewPipeline(pipeline.Config{QueueSize: 64}, src, identSink)
	if err != nil {
		return err
	}
	pipe.WithEnricher(en).WithCorrelation(true)
	go func() {
		_ = src.Inject(ctx, mk("evt-seed-001", "waf.request_blocked", "SEVERITY_HIGH", 0))
		_ = src.Inject(ctx, mk("evt-seed-002", "waf.request_allowed", "SEVERITY_INFO", 1))
		_ = src.Inject(ctx, mk("evt-seed-003", "waf.request_blocked", "SEVERITY_LOW", 2))
		_ = src.Inject(ctx, mk("evt-seed-004", "waf.request_blocked", "SEVERITY_MEDIUM", 3))
		// Network lab fixture (deterministic, synthetic).
		_ = src.Inject(ctx, mkNet("evt-seed-net-001", 4, "SEVERITY_INFO", map[string]string{
			"net.src_ip": "127.0.0.1", "net.dst_ip": "127.0.0.1",
			"net.src_port": "43110", "net.dst_port": "8080", "net.protocol": "TCP", "net.verdict": "allowed",
		}))
		_ = src.Inject(ctx, mkNet("evt-seed-net-002", 5, "SEVERITY_MEDIUM", map[string]string{
			"net.src_ip": "10.0.0.9", "net.dst_ip": "203.0.113.7",
			"net.dst_port": "4444", "net.protocol": "TCP", "net.verdict": "allowed",
		}))
		for i, id := range []string{"evt-seed-net-003", "evt-seed-net-004", "evt-seed-net-005"} {
			_ = src.Inject(ctx, mkNet(id, 6+i, "SEVERITY_LOW", map[string]string{
				"net.src_ip": "10.0.0.20", "net.dst_ip": "10.0.0.1",
				"net.dst_port": "80", "net.protocol": "TCP", "net.verdict": "allowed",
			}))
		}
		for i, id := range []string{"evt-seed-net-006", "evt-seed-net-007", "evt-seed-net-008"} {
			_ = src.Inject(ctx, mkNet(id, 9+i, "SEVERITY_MEDIUM", map[string]string{
				"net.src_ip": "10.0.0.30", "net.dst_ip": "10.0.0.1",
				"net.dst_port": "22", "net.protocol": "TCP", "net.verdict": "denied",
			}))
		}
		// HTTP lab fixture: normal, 5xx burst, auth failures, policy violation, redacted sensitive
		_ = src.Inject(ctx, mkHTTP("evt-seed-http-001", 12, "SEVERITY_INFO", map[string]string{
			"http.method": "GET", "http.host": "seed-lab.example", "http.path": "/api/users", "http.status_code": "200", "http.route": "/api/users",
		}))
		for i, id := range []string{"evt-seed-http-002", "evt-seed-http-003", "evt-seed-http-004"} {
			_ = src.Inject(ctx, mkHTTP(id, 13+i, "SEVERITY_INFO", map[string]string{
				"http.method": "GET", "http.host": "seed-lab.example", "http.path": "/api/users", "http.status_code": "500", "http.route": "/api/users",
			}))
		}
		for i, id := range []string{"evt-seed-http-005", "evt-seed-http-006", "evt-seed-http-007"} {
			_ = src.Inject(ctx, mkHTTP(id, 16+i, "SEVERITY_INFO", map[string]string{
				"http.method": "POST", "http.host": "seed-lab.example", "http.path": "/login", "http.status_code": "401", "http.auth_outcome": "failure",
			}))
		}
		_ = src.Inject(ctx, mkHTTP("evt-seed-http-008", 19, "SEVERITY_INFO", map[string]string{
			"http.method": "TRACE", "http.host": "seed-lab.example", "http.path": "/admin", "http.status_code": "200",
		}))
		_ = src.Inject(ctx, mkHTTP("evt-seed-http-009", 20, "SEVERITY_INFO", map[string]string{
			"http.method": "GET", "http.host": "seed-lab.example", "http.path": "/api/users", "http.status_code": "200", "http.authorization": "Bearer secret-token-should-be-redacted",
		}))
		// Infra lab: endpoint / server / container / cloud
		_ = src.Inject(ctx, mkInfra("evt-seed-endpoint-001", 21, infraobs.EventTypeEndpointActivity, "SEVERITY_INFO", map[string]string{
			"endpoint.host": "web01", "endpoint.process": "explorer.exe", "endpoint.action": "process_start", "endpoint.user": "alice",
		}))
		_ = src.Inject(ctx, mkInfra("evt-seed-endpoint-002", 22, infraobs.EventTypeEndpointActivity, "SEVERITY_INFO", map[string]string{
			"endpoint.host": "web01", "endpoint.process": "cmd.exe", "endpoint.action": "privilege_transition", "endpoint.integrity_level": "high", "endpoint.user": "SYSTEM",
		}))
		_ = src.Inject(ctx, mkInfra("evt-seed-endpoint-003", 23, infraobs.EventTypeEndpointActivity, "SEVERITY_INFO", map[string]string{
			"endpoint.host": "web01", "endpoint.process": "powershell.exe", "endpoint.action": "process_start", "endpoint.command": "run --password hunter2 --token abc",
		}))
		_ = src.Inject(ctx, mkInfra("evt-seed-server-001", 24, infraobs.EventTypeServerActivity, "SEVERITY_INFO", map[string]string{
			"server.hostname": "srv-01", "server.service": "nginx", "server.service_action": "restart", "server.result": "success",
		}))
		for i, id := range []string{"evt-seed-server-002", "evt-seed-server-003", "evt-seed-server-004"} {
			_ = src.Inject(ctx, mkInfra(id, 25+i, infraobs.EventTypeServerActivity, "SEVERITY_INFO", map[string]string{
				"server.hostname": "srv-01", "server.service": "nginx", "server.service_action": "failure", "server.result": "failure",
			}))
		}
		_ = src.Inject(ctx, mkInfra("evt-seed-container-001", 28, infraobs.EventTypeContainerActivity, "SEVERITY_INFO", map[string]string{
			"container.container_id": "cnt-001", "container.image": "nginx:1.25", "container.action": "start", "container.privileged": "false",
		}))
		_ = src.Inject(ctx, mkInfra("evt-seed-container-002", 29, infraobs.EventTypeContainerActivity, "SEVERITY_INFO", map[string]string{
			"container.container_id": "cnt-002", "container.image": "redis:7", "container.action": "start", "container.privileged": "true", "container.host_network": "true",
		}))
		_ = src.Inject(ctx, mkInfra("evt-seed-cloud-001", 30, infraobs.EventTypeCloudActivity, "SEVERITY_INFO", map[string]string{
			"cloud.provider": "aws", "cloud.action": "s3:GetObject", "cloud.result": "success", "cloud.principal": "user-01", "cloud.resource": "bucket-01",
		}))
		for i, id := range []string{"evt-seed-cloud-002", "evt-seed-cloud-003", "evt-seed-cloud-004"} {
			_ = src.Inject(ctx, mkInfra(id, 31+i, infraobs.EventTypeCloudActivity, "SEVERITY_INFO", map[string]string{
				"cloud.provider": "aws", "cloud.action": "s3:GetObject", "cloud.result": "denied", "cloud.principal": "user-02", "cloud.resource": "bucket-02", "cloud.account": "123456789012",
			}))
		}
		_ = src.Inject(ctx, mkInfra("evt-seed-cloud-005", 34, infraobs.EventTypeCloudActivity, "SEVERITY_INFO", map[string]string{
			"cloud.provider": "aws", "cloud.action": "sts:AssumeRole", "cloud.result": "success", "cloud.access_key": "AKIAIOSFODNN7SECRET",
		}))
		// Identity lab: normal login, role change (I1), group activity.
		_ = src.Inject(ctx, mkIdent("evt-seed-ident-001", 35, identobs.EventTypeIdentityActivity, "SEVERITY_INFO", map[string]string{
			"identity.principal": "alice", "identity.action": "login", "identity.target": "webapp:443", "identity.result": "success",
		}))
		_ = src.Inject(ctx, mkIdent("evt-seed-ident-002", 36, identobs.EventTypeIdentityActivity, "SEVERITY_INFO", map[string]string{
			"identity.principal": "alice", "identity.action": "role_change", "identity.target": "admin-role", "identity.result": "success",
		}))
		_ = src.Inject(ctx, mkIdent("evt-seed-ident-003", 37, identobs.EventTypeIdentityActivity, "SEVERITY_INFO", map[string]string{
			"identity.principal": "bob", "identity.action": "group_change", "identity.target": "ops-team", "identity.result": "success",
		}))
		// Auth lab: success, 3x failure (A1), 3x denied (A2), secret redaction.
		_ = src.Inject(ctx, mkIdent("evt-seed-auth-001", 38, identobs.EventTypeAuthActivity, "SEVERITY_INFO", map[string]string{
			"auth.principal": "alice", "auth.outcome": "success", "auth.authentication_method": "sso",
		}))
		for i, id := range []string{"evt-seed-auth-002", "evt-seed-auth-003", "evt-seed-auth-004"} {
			_ = src.Inject(ctx, mkIdent(id, 39+i, identobs.EventTypeAuthActivity, "SEVERITY_INFO", map[string]string{
				"auth.principal": "carol", "auth.outcome": "failure", "auth.authentication_method": "password",
			}))
		}
		for i, id := range []string{"evt-seed-auth-005", "evt-seed-auth-006", "evt-seed-auth-007"} {
			_ = src.Inject(ctx, mkIdent(id, 42+i, identobs.EventTypeAuthActivity, "SEVERITY_INFO", map[string]string{
				"auth.principal": "dave", "auth.outcome": "denied", "auth.authentication_method": "password",
			}))
		}
		_ = src.Inject(ctx, mkIdent("evt-seed-auth-008", 45, identobs.EventTypeAuthActivity, "SEVERITY_INFO", map[string]string{
			"auth.principal": "carol", "auth.outcome": "failure", "auth.password": "hunter2-should-be-redacted",
		}))
		// Data lab: normal read, policy-matching export (D1), non-matching export, secret redaction.
		_ = src.Inject(ctx, mkIdent("evt-seed-data-001", 46, identobs.EventTypeDataActivity, "SEVERITY_INFO", map[string]string{
			"data.resource": "blog", "data.action": "read", "data.classification": "public", "data.principal": "alice",
		}))
		_ = src.Inject(ctx, mkIdent("evt-seed-data-002", 47, identobs.EventTypeDataActivity, "SEVERITY_INFO", map[string]string{
			"data.resource": "customers", "data.action": "export", "data.classification": "restricted", "data.principal": "alice",
		}))
		_ = src.Inject(ctx, mkIdent("evt-seed-data-003", 48, identobs.EventTypeDataActivity, "SEVERITY_INFO", map[string]string{
			"data.resource": "blog", "data.action": "export", "data.classification": "public", "data.principal": "bob",
		}))
		_ = src.Inject(ctx, mkIdent("evt-seed-data-004", 49, identobs.EventTypeDataActivity, "SEVERITY_INFO", map[string]string{
			"data.resource": "customers", "data.action": "read", "data.api_key": "key-should-be-redacted",
		}))
		// Monitoring lab (seed-lab-monitoring): SIEM-C1 sequence (erin
		// failures + privilege change), SIEM-C2 (net+http shared asset),
		// SIEM-C3 (endpoint+server shared host), unlinked lookalike,
		// IOC domain/sha256 matches.
		for i, id := range []string{"evt-seed-mon-auth-001", "evt-seed-mon-auth-002"} {
			_ = src.Inject(ctx, mkMon(id, 50+i, identobs.EventTypeAuthActivity, "SEVERITY_INFO", "seed-mon-01", map[string]string{
				"auth.principal": "erin", "auth.outcome": "failure",
			}))
		}
		_ = src.Inject(ctx, mkMon("evt-seed-mon-ident-001", 52, identobs.EventTypeIdentityActivity, "SEVERITY_INFO", "seed-mon-01", map[string]string{
			"identity.principal": "erin", "identity.action": "role_change", "identity.target": "ops-lead",
		}))
		_ = src.Inject(ctx, mkMon("evt-seed-mon-net-001", 53, "net.connection", "SEVERITY_INFO", "seed-mon-01", map[string]string{
			"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
		}))
		_ = src.Inject(ctx, mkMon("evt-seed-mon-http-001", 54, "http.request", "SEVERITY_INFO", "seed-mon-01", map[string]string{
			"http.method": "GET", "http.host": "seed-lab.example", "http.path": "/health",
		}))
		_ = src.Inject(ctx, mkMon("evt-seed-mon-endpoint-001", 55, infraobs.EventTypeEndpointActivity, "SEVERITY_INFO", "seed-mon-01", map[string]string{
			"endpoint.host": "mon-host-01", "endpoint.process": "agent", "endpoint.action": "process_start",
		}))
		_ = src.Inject(ctx, mkMon("evt-seed-mon-server-001", 56, infraobs.EventTypeServerActivity, "SEVERITY_INFO", "seed-mon-01", map[string]string{
			"server.hostname": "mon-host-01", "server.service": "agentd", "server.service_action": "start", "server.result": "success",
		}))
		// Same-minute lookalikes with no shared linkage: must not correlate.
		_ = src.Inject(ctx, mkMon("evt-seed-mon-auth-003", 57, identobs.EventTypeAuthActivity, "SEVERITY_INFO", "seed-mon-01", map[string]string{
			"auth.principal": "mallory", "auth.outcome": "failure",
		}))
		_ = src.Inject(ctx, mkMon("evt-seed-mon-net-002", 57, "net.connection", "SEVERITY_INFO", "other-asset", map[string]string{
			"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.2",
		}))
		// IOC matches: synthetic domain + synthetic sha256.
		_ = src.Inject(ctx, mkMon("evt-seed-mon-http-002", 58, "http.request", "SEVERITY_INFO", "seed-mon-01", map[string]string{
			"http.method": "GET", "http.host": "test-ioc-sink.example", "http.path": "/",
		}))
		_ = src.Inject(ctx, mkMon("evt-seed-mon-endpoint-002", 59, infraobs.EventTypeEndpointActivity, "SEVERITY_INFO", "seed-mon-01", map[string]string{
			"endpoint.host": "mon-host-01", "endpoint.process": "agent", "endpoint.action": "process_start",
			"endpoint.hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}))
		// Investigation lab (seed-lab-investigation): linked auth →
		// identity → network → application → endpoint timeline with
		// explicit shared asset, plus unlinked lookalikes and a file
		// artifact. H1 fires on frank (auth+identity+data); H2 fires on
		// the linked inv chain.
		for i, id := range []string{"evt-seed-inv-auth-001", "evt-seed-inv-auth-002"} {
			_ = src.Inject(ctx, mkInv(id, 60+i, identobs.EventTypeAuthActivity, "SEVERITY_INFO", map[string]string{
				"auth.principal": "frank", "auth.outcome": "failure",
			}))
		}
		_ = src.Inject(ctx, mkInv("evt-seed-inv-ident-001", 62, identobs.EventTypeIdentityActivity, "SEVERITY_INFO", map[string]string{
			"identity.principal": "frank", "identity.action": "role_change", "identity.target": "ops-lead",
		}))
		_ = src.Inject(ctx, mkInv("evt-seed-inv-data-001", 63, identobs.EventTypeDataActivity, "SEVERITY_INFO", map[string]string{
			"data.principal": "frank", "data.action": "read", "data.resource": "runbook", "data.classification": "internal",
		}))
		_ = src.Inject(ctx, mkInv("evt-seed-inv-net-001", 64, "net.connection", "SEVERITY_INFO", map[string]string{
			"net.src_ip": "10.0.0.9", "net.dst_ip": "10.0.0.1",
		}))
		_ = src.Inject(ctx, mkInv("evt-seed-inv-http-001", 65, "http.request", "SEVERITY_INFO", map[string]string{
			"http.method": "GET", "http.host": "seed-lab.example", "http.path": "/runbook",
		}))
		_ = src.Inject(ctx, mkInv("evt-seed-inv-endpoint-001", 66, infraobs.EventTypeEndpointActivity, "SEVERITY_INFO", map[string]string{
			"endpoint.host": "inv-web-01", "endpoint.process": "agent", "endpoint.action": "file_modify",
			"endpoint.file_path": "/etc/app.conf",
		}))
		// Timestamp-near but unlinked principal: must stay a separate,
		// uncorrelated observation.
		_ = src.Inject(ctx, mkInv("evt-seed-inv-auth-003", 66, identobs.EventTypeAuthActivity, "SEVERITY_INFO", map[string]string{
			"auth.principal": "ghost", "auth.outcome": "failure",
		}))
		_ = src.Stop()
	}()
	if _, err := pipe.Run(ctx); err != nil {
		return err
	}

	// T3 lab: controlled rule-error burst. Probe events persist as
	// telemetry; direct engine evaluation records loud errors without
	// aborting the pipeline run, then the error-burst detection flows
	// through the normal alert → incident → evidence path.
	if err := seedRuleErrorBurst(ctx, eng, mgr, evStore, detStore, sink); err != nil {
		return err
	}

	// H3 lab: verify stored evidence, mutate a lab-only copy (production
	// evidence untouched), and file the resulting integrity failure
	// through the normal alert → incident → evidence path.
	if err := seedIntegrityCheck(ctx, mgr, evStore, detStore, sink); err != nil {
		return err
	}

	// Persist pipeline outputs (validated again at the boundary).
	var out sqlite.PipelineOutputs
	out.Telemetry = sink.Events()
	for _, d := range detStore.Detections() {
		out.Detections = append(out.Detections, d)
	}
	for _, a := range detStore.Alerts() {
		out.Alerts = append(out.Alerts, a)
	}
	out.Incidents = mgr.List()
	out.Evidence = evStore.List()
	if err := persist(out); err != nil {
		return err
	}

	// Asset inventory grows from observations (Step 13A): telemetry asset
	// ids as HOST sightings plus explicit inventory (domain/url/ip/host).
	// All synthetic, all labeled via source.
	assetMgr, err := asset.NewManager(be.Assets, storeAssetRelStore{be.Relationships}, seedClockFn)
	if err != nil {
		return err
	}
	seenIDs := map[string]bool{}
	for _, e := range sink.Events() {
		if seenIDs[e.GetAssetId()] {
			continue
		}
		seenIDs[e.GetAssetId()] = true
		if _, _, err := assetMgr.Ingest(ctx, asset.Observation{
			Source: "seed-telemetry-sweep", Type: v1.AssetType_ASSET_TYPE_HOST,
			Raw: e.GetAssetId(), ObservedAt: seedClockFn(), Environment: "lab",
			Attributes: map[string]string{"_note": "synthetic seed data"},
		}); err != nil {
			return fmt.Errorf("seed telemetry asset %q: %v", e.GetAssetId(), err)
		}
	}
	for _, obs := range []asset.Observation{
		{Source: "seed-inventory", Type: v1.AssetType_ASSET_TYPE_DOMAIN, Raw: "seed-lab.example", ObservedAt: seedClockFn(), Environment: "lab"},
		{Source: "seed-inventory", Type: v1.AssetType_ASSET_TYPE_URL, Raw: "https://seed-lab.example/app", ObservedAt: seedClockFn(), Environment: "lab"},
		{Source: "seed-inventory", Type: v1.AssetType_ASSET_TYPE_IP_ADDRESS, Raw: "127.0.0.1", ObservedAt: seedClockFn(), Environment: "lab"},
		{Source: "seed-inventory", Type: v1.AssetType_ASSET_TYPE_HOST, Raw: "seed-web-01", ObservedAt: seedClockFn(), Environment: "lab"},
	} {
		if _, _, err := assetMgr.Ingest(ctx, obs); err != nil {
			return fmt.Errorf("seed inventory %+v: %v", obs, err)
		}
	}

	// Resolve the incident triple for response + validation: prefer WAF incident for stability.
	var inc *v1.Incident
	alertByID := map[string]*v1.Alert{}
	for _, a := range detStore.Alerts() {
		alertByID[a.GetId()] = a
	}
	detByID := map[string]*v1.Detection{}
	for _, d := range detStore.Detections() {
		detByID[d.GetId()] = d
	}
	// Prefer a waf-rule triple for the response/validation path. Later
	// batch filings (T3, H3) may fold extra alerts into earlier incidents
	// and re-sort AlertIds, so scan every alert of every candidate rather
	// than trusting AlertIds[0].
	var alert *v1.Alert
	var det *v1.Detection
	for _, cand := range out.Incidents {
		for _, aid := range cand.GetAlertIds() {
			a := alertByID[aid]
			if a == nil || len(a.GetDetectionIds()) == 0 {
				continue
			}
			d := detByID[a.GetDetectionIds()[0]]
			if d != nil && strings.Contains(d.GetRuleId(), "waf") {
				inc, alert, det = cand, a, d
				break
			}
		}
		if inc != nil {
			break
		}
	}
	if inc == nil {
		inc = out.Incidents[0]
		alert = alertByID[inc.GetAlertIds()[0]]
		det = detByID[alert.GetDetectionIds()[0]]
	}
	eventByID := map[string]*v1.TelemetryEvent{}
	for _, e := range sink.Events() {
		eventByID[e.GetId()] = e
	}
	var events []*v1.TelemetryEvent
	for _, id := range det.GetTelemetryEventIds() {
		events = append(events, eventByID[id])
	}

	audit := &response.InMemoryAuditLog{}
	exec := &response.SimulatedExecutor{}
	respEng, err := response.NewEngine(response.DefaultPolicy{}, exec,
		response.StaticVerifier{
			Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED,
			Detail:  "seed source confirms",
		}, audit, seedClockFn)
	if err != nil {
		return err
	}
	rec, err := respEng.Recommend(inc, alert, det, events)
	if err != nil {
		return err
	}
	if _, err := respEng.Decide(rec.GetId(), "seed/policy"); err != nil {
		return err
	}
	if _, err := respEng.Approve(rec.GetId(), "test-actor:seed-lead", "proportional", time.Hour); err != nil {
		return err
	}
	executed, err := respEng.Execute(rec.GetId())
	if err != nil || !executed.GetSuccess() {
		return fmt.Errorf("seed execute: %+v %v", executed, err)
	}
	ver, err := respEng.Verify(rec.GetId())
	if err != nil {
		return err
	}
	final, _ := respEng.Get(rec.GetId())
	if err := be.Response.Create(ctx, rec); err != nil {
		return err
	}
	if err := be.Response.Save(ctx, final); err != nil {
		return err
	}
	appr, _ := respEng.Approval(rec.GetId())
	if err := be.ResponseRecords.AppendApproval(ctx, appr); err != nil {
		return err
	}
	if err := be.ResponseRecords.AppendExecution(ctx, executed); err != nil {
		return err
	}
	if err := be.ResponseRecords.AppendVerification(ctx, ver); err != nil {
		return err
	}
	return seedValidations(ctx, be, evStore, detStore, mgr, sink, inc, alert, det, events, audit, dbPath, out)
}

// seedRuleErrorBurst drives three synthetic probe events through direct
// engine evaluation (each aborts loudly by fixture design), aggregates
// the recorded errors into T3 detections, and files them through the
// standard alert → incident → evidence path with provenance.
func seedRuleErrorBurst(ctx context.Context, eng *detect.Engine, mgr *incident.Manager, evStore *evidence.Store, detStore *detect.Store, sink *pipeline.InMemorySink) error {
	base := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC).Add(60 * time.Minute)
	var probes []*v1.TelemetryEvent
	for i, id := range []string{"evt-seed-probe-001", "evt-seed-probe-002", "evt-seed-probe-003"} {
		e := &v1.TelemetryEvent{
			Id: id, OccurredAt: timestamppb.New(base.Add(time.Duration(i) * time.Minute)),
			Source: "seed-lab-monitoring", AssetId: "seed-mon-01", EventType: "test.rule-error-probe",
			Severity: v1.Severity_SEVERITY_INFO,
			Attributes: map[string]string{
				"_note":   "synthetic seed data, not a finding",
				"rule_id": "SEED-MON-01",
			},
		}
		if err := sink.Emit(ctx, e); err != nil {
			return err
		}
		probes = append(probes, e)
		_, _ = eng.Process(e) // loud abort expected; errors recorded
	}
	t3, err := detect.NewRuleErrorBurstRule(eng, 3, 5*time.Minute)
	if err != nil {
		return err
	}
	dets, err := t3.Detections(seedClockFn)
	if err != nil {
		return err
	}
	for _, det := range dets {
		alert, err := detect.BuildAlert(det, seedClockFn())
		if err != nil {
			return err
		}
		detStore.Add(det, alert)
		inc, _, err := mgr.Ingest(alert, det, probes)
		if err != nil {
			return err
		}
		items, err := evidence.BuildForAlert(inc.GetId(), alert, det, probes, seedClockFn())
		if err != nil {
			return err
		}
		for _, item := range items {
			evStore.Add(item)
		}
	}
	return nil
}

// seedIntegrityCheck proves the H3 path without touching production
// evidence: it verifies a stored item, mutates an in-memory clone,
// confirms Verify fails on the clone, and files one forensic-integrity
// detection linked to real incident telemetry.
func seedIntegrityCheck(ctx context.Context, mgr *incident.Manager, evStore *evidence.Store, detStore *detect.Store, sink *pipeline.InMemorySink) error {
	stored := evStore.List()
	if len(stored) == 0 {
		return fmt.Errorf("seed integrity: no evidence to check")
	}
	orig := stored[0]
	if !evidence.Verify(orig) {
		return fmt.Errorf("seed integrity: stored evidence %s must verify", orig.GetId())
	}
	mutated := proto.Clone(orig).(*v1.Evidence)
	mutated.Content = orig.GetContent() + "lab-mutation"
	if evidence.Verify(mutated) {
		return fmt.Errorf("seed integrity: mutated copy must fail verify")
	}
	var linkIDs []string
	for _, d := range detStore.Detections() {
		if len(d.GetTelemetryEventIds()) > 0 {
			linkIDs = d.GetTelemetryEventIds()
			break
		}
	}
	if len(linkIDs) == 0 {
		return fmt.Errorf("seed integrity: no detection linkage available")
	}
	byID := map[string]*v1.TelemetryEvent{}
	for _, e := range sink.Events() {
		byID[e.GetId()] = e
	}
	var linked []*v1.TelemetryEvent
	for _, id := range linkIDs {
		if e, ok := byID[id]; ok {
			linked = append(linked, e)
		}
	}
	if len(linked) == 0 {
		return fmt.Errorf("seed integrity: linked telemetry missing from sink")
	}
	h3, err := detect.NewForensicIntegrityFailureRule()
	if err != nil {
		return err
	}
	dets, err := h3.Detections([]detect.IntegrityFailure{
		{Evidence: mutated, ExpectedDigest: orig.GetSha256(), TelemetryIDs: linkIDs},
	}, seedClockFn)
	if err != nil {
		return err
	}
	for _, det := range dets {
		alert, err := detect.BuildAlert(det, seedClockFn())
		if err != nil {
			return err
		}
		detStore.Add(det, alert)
		inc, _, err := mgr.Ingest(alert, det, linked)
		if err != nil {
			return err
		}
		items, err := evidence.BuildForAlert(inc.GetId(), alert, det, linked, seedClockFn())
		if err != nil {
			return err
		}
		for _, item := range items {
			evStore.Add(item)
		}
	}
	return nil
}

// errLabProvider is a seed-only crashing provider proving provider
// errors stay errors and never become verdicts.
type errLabProvider struct{}

func (errLabProvider) Info() validation.ProviderInfo {
	return validation.ProviderInfo{
		ID: "seed-lab/err", Name: "lab-err", Version: "seed",
		ContractVersion: "blueveil.contracts.v1",
	}
}

func (errLabProvider) Validate(_ context.Context, _ *v1.ValidationRequest) (*v1.ValidationResult, error) {
	return nil, fmt.Errorf("seed-lab/err: controlled provider crash")
}

// seedCampaign runs the Step 13H lab campaign: one case per verdict plus
// a provider-error case, each through RunCase (full safety gate), then
// persists campaign, requests, results, and a purple-team exercise with
// explicit case→result→telemetry→detection→alert→incident→evidence
// linkage. Timestamp-near unrelated telemetry is simply never linked.
func seedCampaign(ctx context.Context, be store.Backend, evStore *evidence.Store, detStore *detect.Store, mgr *incident.Manager, sink *pipeline.InMemorySink, valAudit *response.InMemoryAuditLog) error {
	type triple struct {
		inc    *v1.Incident
		alert  *v1.Alert
		det    *v1.Detection
		events []*v1.TelemetryEvent
	}
	byRule := map[string]*v1.Detection{}
	for _, d := range detStore.Detections() {
		if _, ok := byRule[d.GetRuleId()]; !ok {
			byRule[d.GetRuleId()] = d
		}
	}
	alertByDet := map[string]*v1.Alert{}
	for _, a := range detStore.Alerts() {
		for _, did := range a.GetDetectionIds() {
			if _, ok := alertByDet[did]; !ok {
				alertByDet[did] = a
			}
		}
	}
	incByAlert := map[string]*v1.Incident{}
	for _, inc := range mgr.List() {
		for _, aid := range inc.GetAlertIds() {
			if _, ok := incByAlert[aid]; !ok {
				incByAlert[aid] = inc
			}
		}
	}
	eventByID := map[string]*v1.TelemetryEvent{}
	for _, e := range sink.Events() {
		eventByID[e.GetId()] = e
	}
	resolve := func(ruleID string) (triple, error) {
		var t triple
		det, ok := byRule[ruleID]
		if !ok {
			return t, fmt.Errorf("seed campaign: no detection for rule %q", ruleID)
		}
		alert, ok := alertByDet[det.GetId()]
		if !ok {
			return t, fmt.Errorf("seed campaign: no alert for detection %q", det.GetId())
		}
		inc, ok := incByAlert[alert.GetId()]
		if !ok {
			return t, fmt.Errorf("seed campaign: no incident for alert %q", alert.GetId())
		}
		t = triple{inc: inc, alert: alert, det: det}
		for _, id := range det.GetTelemetryEventIds() {
			e, ok := eventByID[id]
			if !ok {
				return t, fmt.Errorf("seed campaign: telemetry %q missing from sink", id)
			}
			t.events = append(t.events, e)
		}
		return t, nil
	}

	type labCase struct {
		title    string
		domain   validation.CaseDomain
		expected validation.ExpectedBehavior
		ruleID   string
		verdict  v1.ValidationVerdict
	}
	labCases := []labCase{
		{"waf blocks lab probe", validation.DomainWAF, validation.ExpectPrevent, "waf-block-high-severity", v1.ValidationVerdict_VALIDATION_VERDICT_PREVENTED},
		{"net sensor reports lab flow", validation.DomainNetwork, validation.ExpectDetect, "net-disallowed-destination", v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED},
		{"app errors surface in lab", validation.DomainApplication, validation.ExpectPreventAndDetect, "http-error-burst", v1.ValidationVerdict_VALIDATION_VERDICT_PREVENTED_AND_DETECTED},
		{"http auth failures observed", validation.DomainApplication, validation.ExpectDetect, "auth-failure-burst", v1.ValidationVerdict_VALIDATION_VERDICT_ALLOWED_BUT_DETECTED},
		{"identity failures observed", validation.DomainIdentity, validation.ExpectObserve, "ident-auth-failure-burst", v1.ValidationVerdict_VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED},
		{"redveil unavailable in lab", validation.DomainWAF, validation.ExpectObserve, "net-connection-burst", v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED},
		{"correlated lab sequence", validation.DomainNetwork, validation.ExpectDetect, "multi-stage-correlated-activity", v1.ValidationVerdict_VALIDATION_VERDICT_RATE_LIMITED},
		{"container posture observed", validation.DomainContainer, validation.ExpectObserve, "container-risky-runtime-policy", v1.ValidationVerdict_VALIDATION_VERDICT_UNKNOWN},
	}
	// One scripted provider per case (default verdict = the case
	// verdict): no shared scenario map to overwrite, no cross-case
	// interference. Cases sharing a request triple still yield distinct
	// results because the verdict feeds the result id.
	triples := make([]triple, 0, len(labCases))
	providers := make([]validation.Provider, 0, len(labCases))
	for _, c := range labCases {
		t, err := resolve(c.ruleID)
		if err != nil {
			return err
		}
		triples = append(triples, t)
		if c.verdict == v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED {
			red, err := validation.NewUnavailableAdapter("seed", seedClockFn, "no redveil runtime configured")
			if err != nil {
				return err
			}
			providers = append(providers, red)
			continue
		}
		p, err := validation.NewScriptedProvider("seed", seedClockFn, c.verdict)
		if err != nil {
			return err
		}
		providers = append(providers, p)
	}
	// Provider-error triple reuses a real triple; the erroring provider
	// never reaches verdict semantics.
	errTriple, err := resolve("server-service-failure-burst")
	if err != nil {
		return err
	}

	camp := validation.Campaign{
		Name: "seed-lab-validation", Description: "Step 13H synthetic validation campaign",
		Target: "seed-lab", Provider: validation.NativeProviderID,
		Source: "seed-lab-validation", Status: validation.StatusDraft,
		CreatedAt: seedClockFn(),
	}
	if err := camp.Validate(); err != nil {
		return err
	}
	if err := be.Campaigns.Create(ctx, camp); err != nil {
		return err
	}
	camp.Status = validation.StatusRunning
	camp.StartedAt = seedClockFn()
	if err := be.Campaigns.Save(ctx, camp); err != nil {
		return err
	}

	campAudit := &response.InMemoryAuditLog{}
	persistedReq := map[string]bool{}
	var resultIDs []string
	var caseIDs []string
	type entryLink struct {
		caseID, reqID, resID string
		verdict              v1.ValidationVerdict
		triple               triple
		evIDs                []string
	}
	var links []entryLink
	runOne := func(title string, domain validation.CaseDomain, expected validation.ExpectedBehavior, verdict v1.ValidationVerdict, provider validation.Provider, t triple) error {
		before := map[string]bool{}
		for _, e := range evStore.List() {
			before[e.GetId()] = true
		}
		out, err := validation.RunCase(ctx, validation.CaseParams{
			Provider: provider, Incident: t.inc, Alert: t.alert, Detection: t.det, Events: t.events,
			Actor: "test-actor:seed-lead", Reason: "proportional",
			Audit: campAudit, Evidence: evStore, Clock: seedClockFn,
		})
		if err != nil {
			return fmt.Errorf("seed campaign %q: %v", title, err)
		}
		if !persistedReq[out.Request.GetId()] {
			if err := be.Validation.AppendRequest(ctx, out.Request); err != nil {
				// The original triple's request was already persisted
				// by the pre-campaign runs; same deterministic id.
				if !errors.Is(err, store.ErrDuplicate) {
					return err
				}
			}
			persistedReq[out.Request.GetId()] = true
		}
		if out.Result == nil {
			return fmt.Errorf("seed campaign %q: missing result", title)
		}
		if out.Result.GetVerdict() != verdict {
			return fmt.Errorf("seed campaign %q: verdict drift %v", title, out.Result.GetVerdict())
		}
		if err := be.Validation.AppendResult(ctx, out.Result); err != nil {
			return err
		}
		var evIDs []string
		for _, e := range evStore.List() {
			if !before[e.GetId()] {
				evIDs = append(evIDs, e.GetId())
			}
		}
		c := validation.ValidationCase{
			Title: title, Domain: domain, Target: camp.Target, Expected: expected,
			Operation: v1.OperationType_OPERATION_TYPE_OBSERVE, Risk: v1.RiskLevel_RISK_LEVEL_LOW,
			Provider: provider.Info().ID, Source: "seed-lab-validation",
		}
		if err := c.Validate(); err != nil {
			return err
		}
		caseIDs = append(caseIDs, c.ID())
		resultIDs = append(resultIDs, out.Result.GetId())
		links = append(links, entryLink{
			caseID: c.ID(), reqID: out.Request.GetId(), resID: out.Result.GetId(),
			verdict: out.Result.GetVerdict(), triple: t, evIDs: evIDs,
		})
		return nil
	}
	for i, c := range labCases {
		if err := runOne(c.title, c.domain, c.expected, c.verdict, providers[i], triples[i]); err != nil {
			return err
		}
	}
	// Provider-error case: error stays an error, no result persisted.
	if _, err := validation.RunCase(ctx, validation.CaseParams{
		Provider: errLabProvider{}, Incident: errTriple.inc, Alert: errTriple.alert,
		Detection: errTriple.det, Events: errTriple.events,
		Actor: "test-actor:seed-lead", Reason: "proportional",
		Audit: campAudit, Evidence: evStore, Clock: seedClockFn,
	}); err == nil {
		return fmt.Errorf("seed campaign provider-error: expected error")
	}
	camp.Status = validation.StatusCompleted
	camp.CompletedAt = seedClockFn()
	camp.CaseIDs = caseIDs
	camp.ResultIDs = resultIDs
	if err := be.Campaigns.Save(ctx, camp); err != nil {
		return err
	}

	var entries []validation.ExerciseEntryInput
	for _, l := range links {
		var detIDs, alertIDs, incIDs []string
		detIDs = append(detIDs, l.triple.det.GetId())
		alertIDs = append(alertIDs, l.triple.alert.GetId())
		incIDs = append(incIDs, l.triple.inc.GetId())
		var telIDs []string
		for _, e := range l.triple.events {
			telIDs = append(telIDs, e.GetId())
		}
		entries = append(entries, validation.ExerciseEntryInput{
			CaseID: l.caseID, RequestID: l.reqID, ResultID: l.resID,
			Verdict: l.verdict, TelemetryIDs: telIDs, DetectionIDs: detIDs,
			AlertIDs: alertIDs, IncidentIDs: incIDs, EvidenceIDs: l.evIDs,
		})
	}
	ex, err := validation.BuildExercise(validation.ExerciseInput{
		CampaignID: camp.ID(), Name: "seed-lab-validation exercise",
		Source: "seed-lab-validation", Entries: entries,
	})
	if err != nil {
		return err
	}
	if err := be.Exercises.Create(ctx, ex); err != nil {
		return err
	}
	// Merge campaign audit into the validation audit stream with stable IDs.
	n := 0
	for _, entry := range campAudit.Entries() {
		converted, err := store.AuditFromResponse(entry)
		if err != nil {
			return err
		}
		n++
		converted.ID = fmt.Sprintf("audit-camp-%04d", n)
		if err := be.Audit.Append(ctx, converted); err != nil {
			return err
		}
	}
	return nil
}

// seedRedactionCheck scans persisted validation requests, validation
// evidence, AND persisted telemetry for synthetic secret markers. Any hit
// fails the seed: secrets must never reach the store. Telemetry is
// covered because the seed injects markers into telemetry attributes and
// persists pipeline output via PersistRunTx.
func seedRedactionCheck(ctx context.Context, be store.Backend) error {
	markers := []string{"hunter2", "AKIAIOSFODNN7SECRET", "should-be-redacted"}
	// Requests are keyed by deterministic ids; list via results linkage.
	results, err := be.Validation.ListResults(ctx)
	if err != nil {
		return err
	}
	seenReq := map[string]bool{}
	for _, res := range results {
		seenReq[res.GetRequestId()] = true
	}
	for _, id := range sortedKeys(seenReq) {
		req, err := be.Validation.GetRequest(ctx, id)
		if err != nil {
			return err
		}
		blob := req.GetControlId() + "\x1f" + req.GetTarget()
		for k, v := range req.GetContext() {
			blob += "\x1f" + k + "=" + v
		}
		for _, m := range markers {
			if strings.Contains(blob, m) {
				return fmt.Errorf("seed redaction: marker %q in stored request %s", m, id)
			}
		}
	}
	evs, err := be.Evidence.List(ctx)
	if err != nil {
		return err
	}
	for _, e := range evs {
		for _, m := range markers {
			if strings.Contains(e.GetContent(), m) {
				return fmt.Errorf("seed redaction: marker %q in stored evidence %s", m, e.GetId())
			}
		}
	}
	tel, err := be.Telemetry.List(ctx)
	if err != nil {
		return err
	}
	for _, e := range tel {
		blob := e.GetId() + "\x1f" + e.GetRaw()
		for k, v := range e.GetAttributes() {
			blob += "\x1f" + k + "=" + v
		}
		for _, m := range markers {
			if strings.Contains(blob, m) {
				return fmt.Errorf("seed redaction: marker %q in stored telemetry %s", m, e.GetId())
			}
		}
	}
	return nil
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// storeAssetRelStore adapts the relationship repo to the manager's narrow
// interface (identical method set — implicit satisfaction).
type storeAssetRelStore struct {
	repo store.AssetRelationshipRepository
}

func (s storeAssetRelStore) Append(ctx context.Context, rel asset.Relationship) error {
	return s.repo.Append(ctx, rel)
}

// seedValidations runs three providers through the full gate (native
// DETECTED, scripted UNKNOWN, unavailable-Redveil NOT_TESTED), persists
// requests/results/evidence, and prints the summary. Evidence NOTEs hold
// requests/results/evidence, and prints the summary. Evidence NOTEs hold
// the canonical results, so requests/results are re-derived from the same
// deterministic inputs — identical bytes, no second source of truth.
func seedValidations(ctx context.Context, be store.Backend, evStore *evidence.Store, detStore *detect.Store, mgr *incident.Manager, sink *pipeline.InMemorySink, inc *v1.Incident, alert *v1.Alert, det *v1.Detection, events []*v1.TelemetryEvent, audit *response.InMemoryAuditLog, dbPath string, out sqlite.PipelineOutputs) error {
	valAudit := &response.InMemoryAuditLog{}
	persistedReq := map[string]bool{}
	run := func(name string, provider validation.Provider, verdict v1.ValidationVerdict, wantSuccess bool) error {
		vex, err := validation.NewValidationExecutor(provider, inc, alert, det, events, evStore, seedClockFn)
		if err != nil {
			return err
		}
		eng, err := response.NewEngine(response.DefaultPolicy{}, vex,
			response.StaticVerifier{Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED, Detail: "seed source confirms"},
			valAudit, seedClockFn)
		if err != nil {
			return err
		}
		r, err := eng.Recommend(inc, alert, det, events)
		if err != nil {
			return err
		}
		if _, err := eng.Decide(r.GetId(), "seed/policy"); err != nil {
			return err
		}
		if _, err := eng.Approve(r.GetId(), "test-actor:seed-lead", "proportional", time.Hour); err != nil {
			return err
		}
		exec, err := eng.Execute(r.GetId())
		if wantSuccess && (err != nil || !exec.GetSuccess()) {
			return fmt.Errorf("seed %s: %+v %v", name, exec, err)
		}
		if !wantSuccess && err == nil {
			return fmt.Errorf("seed %s: expected execution failure", name)
		}
		if _, err := eng.Verify(r.GetId()); err != nil {
			return err
		}
		// Persist the request once (deterministic id shared across runs)
		// and this run's distinct result.
		req, err := validation.BuildRequest(inc, alert, det, events, seedClockFn())
		if err != nil {
			return err
		}
		if !persistedReq[req.GetId()] {
			if err := be.Validation.AppendRequest(ctx, req); err != nil {
				return err
			}
			persistedReq[req.GetId()] = true
		}
		res, err := provider.Validate(ctx, req)
		if err != nil {
			return fmt.Errorf("seed %s re-validate: %v", name, err)
		}
		if res.GetVerdict() != verdict {
			return fmt.Errorf("seed %s: verdict drift %v", name, res.GetVerdict())
		}
		if err := be.Validation.AppendResult(ctx, res); err != nil {
			return err
		}
		return nil
	}
	nativeDet, err := validation.NewScriptedProvider("seed", seedClockFn, v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED)
	if err != nil {
		return err
	}
	if err := run("native-detected", nativeDet, v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED, true); err != nil {
		return err
	}
	nativeUnk, err := validation.NewScriptedProvider("seed", seedClockFn, v1.ValidationVerdict_VALIDATION_VERDICT_UNKNOWN)
	if err != nil {
		return err
	}
	if err := run("native-unknown", nativeUnk, v1.ValidationVerdict_VALIDATION_VERDICT_UNKNOWN, true); err != nil {
		return err
	}
	red, err := validation.NewUnavailableAdapter("seed", seedClockFn, "no redveil runtime configured")
	if err != nil {
		return err
	}
	if red.Available() {
		return fmt.Errorf("seed: redveil adapter must report unavailable")
	}
	if err := run("redveil-unavailable", red, v1.ValidationVerdict_VALIDATION_VERDICT_NOT_TESTED, false); err != nil {
		return err
	}

	// Step 13H lab campaign: eight verdicts plus a provider error, each
	// through the full safety gate, then a purple-team exercise with
	// explicit linkage. Existing results above stay byte-identical.
	if err := seedCampaign(ctx, be, evStore, detStore, mgr, sink, valAudit); err != nil {
		return err
	}
	if err := seedRedactionCheck(ctx, be); err != nil {
		return err
	}

	// Persist only the validation NOTEs: pipeline evidence went out via
	// PersistRun above; re-appending it would collide on ids.
	persisted := map[string]bool{}
	for _, ev := range out.Evidence {
		persisted[ev.GetId()] = true
	}
	for _, ev := range evStore.List() {
		if persisted[ev.GetId()] {
			continue
		}
		if err := be.Evidence.Append(ctx, ev); err != nil {
			return err
		}
	}
	n := 0
	appendAudit := func(entries []response.AuditEntry) error {
		for _, entry := range entries {
			converted, err := store.AuditFromResponse(entry)
			if err != nil {
				return err
			}
			n++
			converted.ID = fmt.Sprintf("audit-%04d", n)
			if err := be.Audit.Append(ctx, converted); err != nil {
				return err
			}
		}
		return nil
	}
	if err := appendAudit(audit.Entries()); err != nil {
		return err
	}
	if err := appendAudit(valAudit.Entries()); err != nil {
		return err
	}

	// Step 13I lab governance: assessments reference real evidence and
	// validation ids; resilience records carry explicit observations.
	if err := seedGRC(ctx, be); err != nil {
		return err
	}
	// Step 13J lab supply chain: declared components, edges, SBOM
	// metadata, policies, one vendor with assessments, and explicit
	// control links. Nothing installs or contacts anything.
	if err := seedSupplyChain(ctx, be); err != nil {
		return err
	}
	assets, err := be.Assets.List(ctx)
	if err != nil {
		return err
	}
	results, err := be.Validation.ListResults(ctx)
	if err != nil {
		return err
	}
	camps, err := be.Campaigns.List(ctx)
	if err != nil {
		return err
	}
	assessments, err := be.Assessments.List(ctx)
	if err != nil {
		return err
	}
	components, err := be.Components.List(ctx)
	if err != nil {
		return err
	}
	vendors, err := be.Vendors.List(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("seeded %s: telemetry=%d detections=%d alerts=%d incidents=%d evidence=%d validations=%d campaigns=%d assessments=%d audit=%d assets=%d components=%d vendors=%d\n",
		dbPath, len(out.Telemetry), len(out.Detections), len(out.Alerts), len(out.Incidents), len(evStore.List()), len(results), len(camps), len(assessments), n, len(assets), len(components), len(vendors))
	return nil
}

// seedGRC writes the Step 13I synthetic governance lab. Every assessment
// cites real persisted evidence/validation ids; statuses with a decisive
// claim carry an explicit basis. An incident exists in the lab and changes
// nothing automatically — there is no code path from incidents to
// assessments. Secrets never reach the store: notes pass through
// grc.RedactMetadata (proven by the marker scan below).
func seedGRC(ctx context.Context, be store.Backend) error {
	now := seedClockFn()
	evs, err := be.Evidence.List(ctx)
	if err != nil {
		return err
	}
	if len(evs) == 0 {
		return fmt.Errorf("seed GRC: no evidence to cite")
	}
	evID := func(i int) string { return evs[i%len(evs)].GetId() }
	results, err := be.Validation.ListResults(ctx)
	if err != nil {
		return err
	}
	var preventedID, detectedID string
	for _, res := range results {
		switch res.GetVerdict() {
		case v1.ValidationVerdict_VALIDATION_VERDICT_PREVENTED:
			if preventedID == "" {
				preventedID = res.GetId()
			}
		case v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED:
			if detectedID == "" {
				detectedID = res.GetId()
			}
		}
	}
	if preventedID == "" || detectedID == "" {
		return fmt.Errorf("seed GRC: campaign verdicts missing")
	}
	notes := grc.RedactMetadata(map[string]string{
		"owner":         "lab-team",
		"auth.password": "hunter2-should-be-redacted",
	})
	assessments := []grc.Assessment{
		{
			ControlID: "AC-1", Target: "seed-lab", Status: grc.StatusCompliant,
			Assessor: "seed-lab-grc", ObservedAt: now,
			EvidenceIDs: []string{evID(0)}, ValidationIDs: []string{preventedID},
			Basis: "validation " + preventedID + " observed prevention",
			Notes: notes["owner"], Risk: grc.RiskLow,
			RiskBasis: "isolated lab target, prevention observed",
		},
		{
			ControlID: "DT-1", Target: "seed-lab", Status: grc.StatusPartiallyCompliant,
			Assessor: "seed-lab-grc", ObservedAt: now,
			EvidenceIDs: []string{evID(1)}, ValidationIDs: []string{detectedID},
			Basis: "validation " + detectedID + " observed detection without prevention evidence",
			Risk:  grc.RiskMedium, RiskBasis: "detection present, prevention unproven",
		},
		{
			ControlID: "NW-1", Target: "seed-lab", Status: grc.StatusNonCompliant,
			Assessor: "seed-lab-grc", ObservedAt: now,
			EvidenceIDs: []string{evID(2)},
			Basis:       "egress partially implemented and unassessed for prevention; explicit gap",
			Risk:        grc.RiskHigh, RiskBasis: "partial implementation with no prevention evidence",
		},
		{
			ControlID: "RC-1", Target: "seed-lab", Status: grc.StatusNotAssessed,
			Assessor: "seed-lab-grc", ObservedAt: now,
		},
		{
			ControlID: "BK-1", Target: "seed-lab", Status: grc.StatusNotApplicable,
			Assessor: "seed-lab-grc", ObservedAt: now,
			Notes: "lab target out of backup scope",
		},
		{
			ControlID: "AP-1", Target: "seed-lab", Status: grc.StatusUnknown,
			Assessor: "seed-lab-grc", ObservedAt: now,
			EvidenceIDs: []string{evID(3)},
		},
	}
	for _, a := range assessments {
		if err := be.Assessments.Create(ctx, a); err != nil {
			return fmt.Errorf("seed GRC assessment %s: %v", a.ControlID, err)
		}
	}
	resilience := []grc.ResilienceInput{
		{
			Target: "seed-lab", Assessor: "seed-lab-grc", ObservedAt: now,
			BackupObserved: true, BackupAt: now,
			RestoreTestObserved: true, RestoreTestAt: now,
			ProcedureDeclared: true, Dependencies: []string{"seed-lab-store"},
			EvidenceIDs:         []string{evID(4)},
			RetentionConfigured: true, EncryptionObserved: true,
		},
		{
			Target: "seed-lab", Assessor: "seed-lab-grc", ObservedAt: now,
			BackupObserved: true, BackupAt: now,
			EvidenceIDs: []string{evID(5)},
		},
		{
			Target: "seed-lab-edge", Assessor: "seed-lab-grc", ObservedAt: now,
		},
	}
	for _, in := range resilience {
		rec, err := grc.AssessResilience(in)
		if err != nil {
			return fmt.Errorf("seed GRC resilience: %v", err)
		}
		if err := be.Resilience.Create(ctx, rec); err != nil {
			return fmt.Errorf("seed GRC resilience persist: %v", err)
		}
	}
	// Redaction gate: synthetic secret markers must appear nowhere in
	// persisted governance-adjacent stores.
	for _, m := range []string{"hunter2", "should-be-redacted"} {
		for _, a := range assessments {
			blob := a.Basis + "\x1f" + a.Notes
			if strings.Contains(blob, m) {
				return fmt.Errorf("seed GRC redaction: marker %q in assessment notes", m)
			}
		}
	}
	return nil
}

// seedSupplyChain writes the Step 13J synthetic supply-chain lab. Every
// component is declared lab metadata; licenses render verbatim as
// declared (empty means undeclared, never enriched); statuses with a
// decisive claim carry an explicit basis. Vendor assessments cite real
// persisted evidence ids; control links cite real baseline control ids.
func seedSupplyChain(ctx context.Context, be store.Backend) error {
	now := seedClockFn()
	evs, err := be.Evidence.List(ctx)
	if err != nil {
		return err
	}
	if len(evs) == 0 {
		return fmt.Errorf("seed supply chain: no evidence to cite")
	}
	evID := func(i int) string { return evs[i%len(evs)].GetId() }
	src := "seed-lab-supply-chain"

	mkComp := func(typ supplychain.ComponentType, eco, name, version string, prov supplychain.Provenance, lic, licSrc string, status supplychain.ComponentStatus, basis string) supplychain.Component {
		return supplychain.Component{
			Type: typ, Ecosystem: eco, Name: name, Version: version,
			License: lic, LicenseSource: licSrc, Provenance: prov,
			Source: src, ObservedAt: now, Status: status, StatusBasis: basis,
		}
	}
	comps := []supplychain.Component{
		mkComp(supplychain.ComponentSourceRepository, "git", "seed-lab/webapp", "a1b2c3d",
			supplychain.ProvenanceSourceRepository, "", "", supplychain.StatusObserved, ""),
		mkComp(supplychain.ComponentLibrary, "npm", "left-pad", "1.0.0",
			supplychain.ProvenanceLockfile, "MIT", "declared", supplychain.StatusObserved, ""),
		mkComp(supplychain.ComponentLibrary, "pypi", "requests", "2.31.0",
			supplychain.ProvenanceLockfile, "Apache-2.0", "declared", supplychain.StatusVerified, "digest pinned in lockfile"),
		mkComp(supplychain.ComponentPackage, "go", "gin", "1.9.1",
			supplychain.ProvenanceManifest, "MIT", "declared", supplychain.StatusObserved, ""),
		mkComp(supplychain.ComponentBinary, "internal", "backfill-worker", "0.9.0",
			supplychain.ProvenanceDeploymentObservation, "", "", supplychain.StatusOutdated, "version 0.9.0 predates declared minimum 1.0.0"),
		mkComp(supplychain.ComponentContainerImage, "docker", "redis", "7.2",
			supplychain.ProvenanceContainerMetadata, "", "", supplychain.StatusObserved, ""),
		mkComp(supplychain.ComponentInfrastructureModule, "terraform", "internal-auth", "3.4.0",
			supplychain.ProvenanceOperatorDeclaration, "MPL-2.0", "declared", supplychain.StatusNotAssessed, ""),
		mkComp(supplychain.ComponentBinary, "internal", "legacy-agent", "",
			supplychain.ProvenanceOperatorDeclaration, "", "", supplychain.StatusUnknown, ""),
	}
	for _, c := range comps {
		if err := be.Components.Create(ctx, c); err != nil {
			return fmt.Errorf("seed supply chain component %s: %v", c.Name, err)
		}
	}
	idOf := func(name string) string {
		for _, c := range comps {
			if c.Name == name {
				return c.ID()
			}
		}
		return ""
	}
	deps := []supplychain.Dependency{
		{ParentID: idOf("seed-lab/webapp"), ParentKind: "component", ChildID: idOf("left-pad"), Kind: supplychain.DependencyContains, Source: src, ObservedAt: now},
		{ParentID: idOf("seed-lab/webapp"), ParentKind: "component", ChildID: idOf("requests"), Kind: supplychain.DependencyDependsOn, Source: src, ObservedAt: now},
		{ParentID: idOf("seed-lab/webapp"), ParentKind: "component", ChildID: idOf("gin"), Kind: supplychain.DependencyDependsOn, Source: src, ObservedAt: now},
		{ParentID: idOf("seed-lab/webapp"), ParentKind: "component", ChildID: idOf("redis"), Kind: supplychain.DependencyDependsOn, Source: src, ObservedAt: now},
	}
	for _, d := range deps {
		if err := be.Dependencies.Append(ctx, d); err != nil {
			return fmt.Errorf("seed supply chain dependency: %v", err)
		}
	}
	sboms := []supplychain.SBOM{
		{Format: supplychain.SBOMCycloneDX, FormatVersion: "1.5",
			ComponentIDs: []string{idOf("left-pad"), idOf("requests"), idOf("gin")},
			GeneratedAt:  now, Source: src},
		{Format: supplychain.SBOMSPDX, FormatVersion: "2.3",
			ComponentIDs: []string{idOf("seed-lab/webapp")},
			GeneratedAt:  now, Source: src},
	}
	for _, s := range sboms {
		if err := be.SBOMs.Create(ctx, s); err != nil {
			return fmt.Errorf("seed supply chain sbom: %v", err)
		}
	}
	policies := []supplychain.SupplyPolicy{
		{ID: "pol-lab-allowlist", Name: "lab allowlist", Source: src,
			AllowedEcosystems: []string{"npm", "pypi", "go"},
			AllowedLicenses:   []string{"MIT", "Apache-2.0"},
			AllowedProvenance: []supplychain.Provenance{supplychain.ProvenanceLockfile, supplychain.ProvenanceManifest}},
		{ID: "pol-lab-pinned", Name: "lab pinned", Source: src,
			RequireDigest: true, MinVersions: map[string]string{"npm": "1.0.0"}},
	}
	for _, p := range policies {
		if err := be.Policies.Create(ctx, p); err != nil {
			return fmt.Errorf("seed supply chain policy %s: %v", p.ID, err)
		}
	}
	vend := supplychain.Vendor{
		Name: "Example CDN", Service: "edge cache", Category: "hosting",
		Environment: "lab", Status: supplychain.VendorActive,
		Source: src, ObservedAt: now,
	}
	if err := be.Vendors.Create(ctx, vend); err != nil {
		return fmt.Errorf("seed supply chain vendor: %v", err)
	}
	assessments := []supplychain.VendorAssessment{
		{VendorID: vend.ID(), Status: supplychain.VendorReviewed,
			Assessor: src, ObservedAt: now, EvidenceIDs: []string{evID(0)},
			Note: "lab review of declared service scope"},
		{VendorID: vend.ID(), Status: supplychain.VendorRequirementDeclared,
			Assessor: src, ObservedAt: now.Add(-24 * time.Hour),
			Note: "declared requirement: cache purge runbook"},
	}
	for _, a := range assessments {
		if err := be.VendorAssessments.Create(ctx, a); err != nil {
			return fmt.Errorf("seed supply chain vendor assessment: %v", err)
		}
	}
	links := []supplychain.SupplyLink{
		{ControlID: "LG-1", SubjectKind: supplychain.LinkComponent,
			SubjectID: idOf("left-pad"), Basis: "component observed in lab manifest"},
		{ControlID: "DT-1", SubjectKind: supplychain.LinkVendor,
			SubjectID: vend.ID(), Basis: "vendor declared for lab edge traffic"},
		{ControlID: "LG-1", SubjectKind: supplychain.LinkSBOM,
			SubjectID: sboms[0].ID(), Basis: "sbom metadata declared for lab libraries"},
	}
	for _, l := range links {
		if err := be.SupplyLinks.Create(ctx, l); err != nil {
			return fmt.Errorf("seed supply chain link: %v", err)
		}
	}
	return nil
}

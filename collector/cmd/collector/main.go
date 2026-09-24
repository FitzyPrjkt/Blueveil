// Command collector is the minimal executable around the pipeline.
// It does one thing: --self-test wires an in-memory source, four valid raw
// events (two matching detection rules, two negative) and one invalid one,
// runs them through telemetry → detection → alert → incident → evidence,
// then drives one incident through the gated response path (plus a deny
// negative) and one control through gated validation (native provider plus
// honest unavailable-Redveil), prints the accounting, and exits non-zero
// unless every expectation holds. Not a daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"blueveil/collector/internal/asset"
	"blueveil/collector/internal/config"
	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/detect"
	"blueveil/collector/internal/enrich"
	"blueveil/collector/internal/evidence"
	"blueveil/collector/internal/incident"
	"blueveil/collector/internal/netobs"
	"blueveil/collector/internal/pipeline"
	"blueveil/collector/internal/response"
	"blueveil/collector/internal/source"
	"blueveil/collector/internal/store"
	"blueveil/collector/internal/validation"
)

func main() {
	versionCmd := flag.Bool("version", false, "print binary identity (module, Go toolchain) and exit")
	selfTest := flag.Bool("self-test", false, "run the in-memory verification flow and exit")
	emitJSONL := flag.String("emit-jsonl", "", "with --self-test: also write accepted events as canonical protojson-lines to PATH (0600)")
	seedCmd := flag.Bool("seed", false, "write deterministic labeled-synthetic lab dataset into --db and exit")
	seedPG := flag.Bool("seed-pg", false, "write the lab dataset into the configured PostgreSQL and exit")
	keygen := flag.Bool("keygen", false, "print a JSON API-key config fragment; reads the secret from stdin")
	keyID := flag.String("key-id", "", "with --keygen: stable key label")
	keyRole := flag.String("key-role", "", "with --keygen: READ|RESPOND|VALIDATE|ADMIN")
	backupCmd := flag.Bool("backup", false, "write a versioned backup of the configured database and exit")
	backupOut := flag.String("backup-out", "", "with --backup: parent directory for the timestamped backup")
	restoreCmd := flag.Bool("restore", false, "restore a backup directory into an isolated target and exit")
	restoreFrom := flag.String("restore-from", "", "with --restore: backup directory")
	restoreDB := flag.String("restore-dbname", "", "with --restore (postgres): target database (defaults to config)")
	// NOTE: --force is shared with --seed/--restore: explicit destructive
	// confirmation, never a default.
	pruneCmd := flag.Bool("prune-backups", false, "delete old backups keeping --keep newest, then exit")
	pruneDir := flag.String("prune-dir", "", "with --prune-backups: backups parent directory")
	pruneKeep := flag.Int("keep", 7, "with --prune-backups: newest backups to keep")
	serveCmd := flag.Bool("serve", false, "serve the API + built UI and block")
	dbPath := flag.String("db", "", "SQLite database path (seed/serve with sqlite backend)")
	force := flag.Bool("force", false, "with --seed: overwrite non-empty database")
	addr := flag.String("addr", "", "with --serve: bind address (default from environment)")
	uiDir := flag.String("ui-dir", "", "with --serve: built UI directory (default from environment)")
	iocSetPath := flag.String("ioc-set", "", "with --serve: offline IOC set JSON file (id + version flags required with it)")
	iocSetID := flag.String("ioc-set-id", "", "with --serve --ioc-set: IOC set identifier")
	iocSetVersion := flag.String("ioc-set-version", "", "with --serve --ioc-set: IOC set version")
	envName := flag.String("env", "", "with --serve: lab|production (default from environment)")
	dbBackend := flag.String("db-backend", "", "with --serve: sqlite|postgres (default from environment)")
	tlsEnabled := flag.Bool("tls", false, "with --serve: enable TLS (cert/key from environment or config file)")
	tlsCert := flag.String("tls-cert", "", "with --serve --tls: certificate file")
	tlsKey := flag.String("tls-key", "", "with --serve --tls: private key file")
	authEnabled := flag.Bool("auth", false, "with --serve: enable API authentication (keys from environment or config file)")
	configFile := flag.String("config", "", "JSON config file (see internal/config)")
	logLevel := flag.String("log-level", "", "with --serve: debug|info|warn|error")
	logFormat := flag.String("log-format", "", "with --serve: text|json")
	flag.Parse()
	switch {
	case *versionCmd:
		printVersion()
		return
	case *seedCmd:
		if *dbPath == "" {
			fmt.Fprintln(os.Stderr, "usage: collector --seed --db PATH [--force]")
			os.Exit(2)
		}
		if err := runSeed(*dbPath, *force); err != nil {
			fmt.Fprintln(os.Stderr, "seed FAIL:", err)
			os.Exit(1)
		}
		fmt.Println("seed PASS")
	case *seedPG:
		cfg, err := serveConfig(*configFile, serveFlags{})
		if err != nil {
			fmt.Fprintln(os.Stderr, "seed-pg FAIL:", err)
			os.Exit(2)
		}
		if cfg.Database.Backend != config.BackendPostgres {
			fmt.Fprintln(os.Stderr, "seed-pg FAIL: database backend is not postgres")
			os.Exit(2)
		}
		if err := runSeedPG(context.Background(), pgConfigFrom(cfg), *force); err != nil {
			fmt.Fprintln(os.Stderr, "seed-pg FAIL:", err)
			os.Exit(1)
		}
		fmt.Println("seed PASS")
	case *keygen:
		if *keyID == "" || *keyRole == "" {
			fmt.Fprintln(os.Stderr, "usage: collector --keygen --key-id ID --key-role ROLE < secret.txt")
			os.Exit(2)
		}
		if err := runKeygen(*keyID, strings.ToUpper(*keyRole), os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "keygen FAIL:", err)
			os.Exit(1)
		}
	case *backupCmd:
		if *backupOut == "" {
			fmt.Fprintln(os.Stderr, "usage: collector --backup --config CONFIG --backup-out DIR")
			os.Exit(2)
		}
		if err := runBackup(*configFile, serveFlags{}, *backupOut); err != nil {
			fmt.Fprintln(os.Stderr, "backup FAIL:", err)
			os.Exit(1)
		}
		fmt.Println("backup PASS")
	case *restoreCmd:
		if *restoreFrom == "" {
			fmt.Fprintln(os.Stderr, "usage: collector --restore --config CONFIG --restore-from BACKUPDIR [--restore-dbname NAME] [--force]")
			os.Exit(2)
		}
		if err := runRestore(*configFile, serveFlags{}, *restoreFrom, *restoreDB, *force); err != nil {
			fmt.Fprintln(os.Stderr, "restore FAIL:", err)
			os.Exit(1)
		}
		fmt.Println("restore PASS")
	case *pruneCmd:
		if *pruneDir == "" {
			fmt.Fprintln(os.Stderr, "usage: collector --prune-backups --prune-dir DIR [--keep N]")
			os.Exit(2)
		}
		if err := runPrune(*pruneDir, *pruneKeep); err != nil {
			fmt.Fprintln(os.Stderr, "prune FAIL:", err)
			os.Exit(1)
		}
		fmt.Println("prune PASS")
	case *serveCmd:
		cfg, err := serveConfig(*configFile, serveFlags{
			addr: *addr, uiDir: *uiDir, iocSetPath: *iocSetPath, iocSetID: *iocSetID,
			iocSetVersion: *iocSetVersion, envName: *envName, dbBackend: *dbBackend,
			tlsEnabled: *tlsEnabled, tlsCert: *tlsCert, tlsKey: *tlsKey,
			authEnabled: *authEnabled, logLevel: *logLevel, logFormat: *logFormat,
			dbPath: *dbPath,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "serve FAIL:", err)
			os.Exit(2)
		}
		if err := runServe(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "serve FAIL:", err)
			os.Exit(1)
		}
	case *selfTest:
		if err := runSelfTest(*emitJSONL); err != nil {
			fmt.Fprintln(os.Stderr, "self-test FAIL:", err)
			os.Exit(1)
		}
		fmt.Println("self-test PASS")
	default:
		fmt.Fprintln(os.Stderr, "usage: collector --self-test [--emit-jsonl PATH] | --seed --db PATH [--force] | --serve --db PATH [--addr ADDR] [--ui-dir DIR] [--ioc-set PATH --ioc-set-id ID --ioc-set-version VER]")
		os.Exit(2)
	}
}

// teeSink fans one emission out to two sinks; the first error wins.
type teeSink struct {
	a, b pipeline.Sink
}

func (t teeSink) Emit(ctx context.Context, e *v1.TelemetryEvent) error {
	if err := t.a.Emit(ctx, e); err != nil {
		return err
	}
	return t.b.Emit(ctx, e)
}

func runSelfTest(emitPath string) error {
	ctx := context.Background()
	src := source.NewChannelSource(16)
	sink := &pipeline.InMemorySink{}
	var out pipeline.Sink = sink
	if emitPath != "" {
		f, err := os.OpenFile(emitPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		lines, err := pipeline.NewLineSink(f)
		if err != nil {
			return err
		}
		out = teeSink{a: sink, b: lines}
	}
	en, err := enrich.New("self-test", time.Now)
	if err != nil {
		return err
	}

	// Detection stage: three WAF rules plus three network-defense rules,
	// in-memory stores. Positive path (matching → detection → alert) and
	// negative path (non-matching → nothing) both asserted; network lab
	// fixture runs through the same engine and proves disallow / burst
	// (incl re-arm) / denied-repeat via synthetic local observations.
	engine, err := detect.NewEngine(time.Now)
	if err != nil {
		return err
	}
	for _, r := range []detect.Rule{detect.BlockHighSeverityRule{}, detect.SourceCriticalRule{}} {
		if err := engine.RegisterRule(r); err != nil {
			return err
		}
	}
	burst, err := detect.NewBlockBurstRule(3, 5*time.Minute, time.Now)
	if err != nil {
		return err
	}
	if err := engine.RegisterRule(burst); err != nil {
		return err
	}
	disallow, err := detect.NewNetDisallowedDestinationRule([]detect.DisallowedTarget{
		{DstIP: "203.0.113.7", DstPort: 4444, HasPort: true, Protocol: "TCP", Severity: v1.Severity_SEVERITY_HIGH, Label: "lab-disallow-203.0.113.7:4444"},
	})
	if err != nil {
		return err
	}
	if err := engine.RegisterRule(disallow); err != nil {
		return err
	}
	netBurst, err := detect.NewNetConnectionBurstRule(3, 5*time.Minute, time.Now)
	if err != nil {
		return err
	}
	if err := engine.RegisterRule(netBurst); err != nil {
		return err
	}
	netDenied, err := detect.NewNetDeniedActivityRule(3, 5*time.Minute, time.Now)
	if err != nil {
		return err
	}
	if err := engine.RegisterRule(netDenied); err != nil {
		return err
	}
	detStore := &detect.Store{}
	incidents, err := incident.NewManager(time.Now)
	if err != nil {
		return err
	}
	evStore := evidence.NewStore()
	chained, err := pipeline.NewIncidentSink(engine, incidents, evStore, detStore, sink, out)
	if err != nil {
		return err
	}
	// Asset correlation for synthetic network observations: local prefixes
	// cover loopback + RFC1918 lab traffic; TEST-NET stays unresolved.
	memBackend := store.NewMemoryBackend()
	assetMgrST, err := asset.NewManager(memBackend.Assets, memBackend.Relationships, time.Now)
	if err != nil {
		return err
	}
	corrST, err := netobs.NewCorrelator(assetMgrST, memBackend.Relationships, netobs.CorrelateConfig{
		AllowAutoCreate: true, LocalPrefixes: []string{"127.0.0.0/8", "10.0.0.0/8"},
	})
	if err != nil {
		return err
	}
	netStage, err := netobs.NewCorrelatingSink(corrST, chained)
	if err != nil {
		return err
	}
	pipe, err := pipeline.NewPipeline(pipeline.Config{QueueSize: 16}, src, netStage)
	if err != nil {
		return err
	}
	pipe.WithEnricher(en).WithCorrelation(true)

	now := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	mk := func(id, typ, sev string, minute int) source.RawEvent {
		return source.RawEvent{
			ID: id, Source: "self-test", AssetID: "asset-selftest-01",
			EventType: typ, Severity: sev,
			Attributes: map[string]string{
				"_note":   "synthetic self-test data, not a finding",
				"rule_id": "SELFTEST-WAF-01", // simulated control under test, labeled as such
			},
			OccurredAt: now.Add(time.Duration(minute) * time.Minute),
		}
	}
	valid := []source.RawEvent{
		mk("evt-selftest-001", "waf.request_blocked", "SEVERITY_HIGH", 0),   // R1 fires
		mk("evt-selftest-002", "waf.request_allowed", "SEVERITY_INFO", 1),   // negative: nothing
		mk("evt-selftest-003", "waf.request_blocked", "SEVERITY_LOW", 2),    // burst 2/3
		mk("evt-selftest-004", "waf.request_blocked", "SEVERITY_MEDIUM", 3), // burst 3/3 → R2 fires
	}
	invalid := source.RawEvent{ID: "", Source: "self-test"} // missing asset/type: must be rejected

	go func() {
		for _, e := range valid {
			_ = src.Inject(ctx, e)
		}
		_ = src.Inject(ctx, invalid)
		_ = src.Stop()
	}()

	report, err := pipe.Run(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("accepted=%d rejected=%d sunk=%d\n", report.Accepted, len(report.Rejected), len(sink.Events()))
	for _, r := range report.Rejected {
		fmt.Printf("rejected id=%q cause=%v\n", r.Raw.ID, r.Err)
	}
	if report.Accepted != 4 || len(report.Rejected) != 1 || len(sink.Events()) != 4 {
		return fmt.Errorf("unexpected telemetry report: %+v", report)
	}
	dets, alerts := detStore.Counts()
	fmt.Printf("detections=%d alerts=%d\n", dets, alerts)
	for _, d := range detStore.Detections() {
		if err := contract.ValidateDetection(d); err != nil {
			return fmt.Errorf("stored detection invalid: %v", err)
		}
		fmt.Printf("detection %s rule=%s severity=%s events=%d\n",
			d.GetId(), d.GetRuleId(), d.GetSeverity(), len(d.GetTelemetryEventIds()))
	}
	for _, a := range detStore.Alerts() {
		if err := contract.ValidateAlert(a); err != nil {
			return fmt.Errorf("stored alert invalid: %v", err)
		}
	}
	if dets != 2 || alerts != 2 {
		return fmt.Errorf("unexpected detection report: %d detections %d alerts", dets, alerts)
	}
	list := incidents.List()
	fmt.Printf("incidents=%d evidence=%d\n", len(list), evStore.Count())
	for _, inc := range list {
		if err := contract.ValidateIncident(inc); err != nil {
			return fmt.Errorf("stored incident invalid: %v", err)
		}
		fmt.Printf("incident %s status=%s alerts=%d summary=%q\n",
			inc.GetId(), inc.GetStatus(), len(inc.GetAlertIds()), inc.GetSummary())
	}
	for _, ev := range evStore.List() {
		if err := contract.ValidateEvidence(ev); err != nil {
			return fmt.Errorf("stored evidence invalid: %v", err)
		}
		if !evidence.Verify(ev) {
			return fmt.Errorf("stored evidence failed verify: %s", ev.GetId())
		}
	}
	// Both alerts share one correlation group → one incident; evidence:
	// 3 (first alert) + 4 new (second alert, shared event deduped) = 7.
	if len(list) != 1 || evStore.Count() != 7 {
		return fmt.Errorf("unexpected incident report: %d incidents %d evidence", len(list), evStore.Count())
	}
	return driveResponse(list[0], detStore, sink, evStore)
}

// driveResponse proves the gated path end to end on the self-test incident:
// recommend → decide → approve → execute → verify, plus a deny negative.
// Actors are synthetic and labeled as such; the executor is simulated.
func driveResponse(inc *v1.Incident, store *detect.Store, sink *pipeline.InMemorySink, evStore *evidence.Store) error {
	alertByID := map[string]*v1.Alert{}
	for _, a := range store.Alerts() {
		alertByID[a.GetId()] = a
	}
	detByID := map[string]*v1.Detection{}
	for _, d := range store.Detections() {
		detByID[d.GetId()] = d
	}
	eventByID := map[string]*v1.TelemetryEvent{}
	for _, e := range sink.Events() {
		eventByID[e.GetId()] = e
	}
	alert := alertByID[inc.GetAlertIds()[0]]
	det := detByID[alert.GetDetectionIds()[0]]
	var events []*v1.TelemetryEvent
	for _, id := range det.GetTelemetryEventIds() {
		events = append(events, eventByID[id])
	}

	exec := &response.SimulatedExecutor{}
	audit := &response.InMemoryAuditLog{}
	eng, err := response.NewEngine(response.DefaultPolicy{}, exec,
		response.StaticVerifier{
			Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED,
			Detail:  "self-test source confirms",
		}, audit, time.Now)
	if err != nil {
		return err
	}
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		return err
	}
	if _, err := eng.Decide(rec.GetId(), "self-test/policy"); err != nil {
		return err
	}
	if _, err := eng.Approve(rec.GetId(), "test-actor:self-test-lead", "proportional", time.Hour); err != nil {
		return err
	}
	executed, err := eng.Execute(rec.GetId())
	if err != nil || !executed.GetSuccess() {
		return fmt.Errorf("self-test execute: %+v %v", executed, err)
	}
	ver, err := eng.Verify(rec.GetId())
	if err != nil || ver.GetOutcome() != v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED {
		return fmt.Errorf("self-test verify: %+v %v", ver, err)
	}
	final, _ := eng.Get(rec.GetId())
	fmt.Printf("response %s status=%s operation=%s approvals=1 audit=%d\n",
		final.GetId(), final.GetStatus(), final.GetOperation(), len(audit.Entries()))
	if final.GetStatus() != v1.ResponseStatus_RESPONSE_STATUS_VERIFIED {
		return fmt.Errorf("unexpected response status: %v", final.GetStatus())
	}

	// Negative: deny policy decides, records, and never executes.
	denyExec := &response.SimulatedExecutor{}
	denyEng, err := response.NewEngine(response.StaticDenyAll(), denyExec,
		response.UnknownVerifier{}, &response.InMemoryAuditLog{}, time.Now)
	if err != nil {
		return err
	}
	rec2, err := denyEng.Recommend(inc, alert, det, events)
	if err != nil {
		return err
	}
	if _, err := denyEng.Decide(rec2.GetId(), "self-test/policy"); err == nil {
		return fmt.Errorf("self-test deny: expected refusal")
	}
	if _, err := denyEng.Execute(rec2.GetId()); err == nil {
		return fmt.Errorf("self-test deny: execution must refuse")
	}
	if len(denyExec.Calls()) != 0 {
		return fmt.Errorf("self-test deny: executor must stay untouched")
	}
	fmt.Println("response-deny: refused, recorded, executor untouched")
	return driveValidation(inc, alert, det, events, evStore)
}

// driveValidation proves the §9 path on live self-test data: a native
// scripted provider validates the named control through the full gate, and
// the unavailable Redveil adapter records honest NOT_TESTED. Both leave
// evidence; neither fabricates security.
func driveValidation(inc *v1.Incident, alert *v1.Alert, det *v1.Detection, events []*v1.TelemetryEvent, evStore *evidence.Store) error {
	before := evStore.Count()

	native, err := validation.NewScriptedProvider("self-test", time.Now,
		v1.ValidationVerdict_VALIDATION_VERDICT_DETECTED)
	if err != nil {
		return err
	}
	vex, err := validation.NewValidationExecutor(native, inc, alert, det, events, evStore, time.Now)
	if err != nil {
		return err
	}
	audit := &response.InMemoryAuditLog{}
	eng, err := response.NewEngine(response.DefaultPolicy{}, vex,
		response.StaticVerifier{
			Outcome: v1.VerificationOutcome_VERIFICATION_OUTCOME_VERIFIED,
			Detail:  "self-test source confirms",
		}, audit, time.Now)
	if err != nil {
		return err
	}
	rec, err := eng.Recommend(inc, alert, det, events)
	if err != nil {
		return err
	}
	if _, err := eng.Decide(rec.GetId(), "self-test/policy"); err != nil {
		return err
	}
	if _, err := eng.Approve(rec.GetId(), "test-actor:self-test-lead", "proportional", time.Hour); err != nil {
		return err
	}
	executed, err := eng.Execute(rec.GetId())
	if err != nil || !executed.GetSuccess() {
		return fmt.Errorf("self-test validation execute: %+v %v", executed, err)
	}
	if _, err := eng.Verify(rec.GetId()); err != nil {
		return err
	}
	fmt.Printf("validation provider=%s verdict=DETECTED evidence=%d audit=%d\n",
		validation.NativeProviderID, evStore.Count()-before, len(audit.Entries()))

	// Unavailable Redveil: NOT_TESTED recorded as evidence, never success.
	red, err := validation.NewUnavailableAdapter("self-test", time.Now, "no redveil runtime configured")
	if err != nil {
		return err
	}
	if red.Available() {
		return fmt.Errorf("self-test: redveil adapter must report unavailable")
	}
	rev, err := validation.NewValidationExecutor(red, inc, alert, det, events, evStore, time.Now)
	if err != nil {
		return err
	}
	reng, err := response.NewEngine(response.StaticAllowAll(), rev,
		response.UnknownVerifier{}, &response.InMemoryAuditLog{}, time.Now)
	if err != nil {
		return err
	}
	// LOW... the incident is HIGH: StaticAllowAll parks at PENDING under the
	// gate rule, so approve explicitly before executing.
	rrec, err := reng.Recommend(inc, alert, det, events)
	if err != nil {
		return err
	}
	if _, err := reng.Decide(rrec.GetId(), "self-test/policy"); err != nil {
		return err
	}
	if _, err := reng.Approve(rrec.GetId(), "test-actor:self-test-lead", "ok", 0); err != nil {
		return err
	}
	rexec, err := reng.Execute(rrec.GetId())
	if !errors.Is(err, response.ErrExecutionFailed) {
		return fmt.Errorf("self-test redveil: unavailable validation must fail execution, got %+v %v", rexec, err)
	}
	if rexec.GetSuccess() {
		return fmt.Errorf("self-test redveil: NOT_TESTED must not report success")
	}
	fmt.Printf("validation provider=%s verdict=NOT_TESTED (recorded, not a pass; execution failed as designed)\n",
		validation.RedveilProviderID)
	if evStore.Count()-before != 2 {
		return fmt.Errorf("unexpected validation evidence: %d", evStore.Count()-before)
	}
	for _, ev := range evStore.List() {
		if err := contract.ValidateEvidence(ev); err != nil {
			return fmt.Errorf("stored evidence invalid: %v", err)
		}
		if !evidence.Verify(ev) {
			return fmt.Errorf("stored evidence failed verify: %s", ev.GetId())
		}
	}
	return nil
}

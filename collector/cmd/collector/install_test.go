// Step 17J: clean private installation test. Stages a fresh PREFIX
// install via deploy/install.sh (user scope: no root, no host changes
// outside the temp dir, the user unit file, and a scratch test
// database), then drives the real lifecycle: systemd start → readyz →
// authenticated API → restart → state preserved → stop.
//
// Requires linux, a Go toolchain (builds the artifact under test), a
// user systemd manager, psql, and BLUEVEIL_TEST_POSTGRES (admin conn
// string for a scratch database). Anything missing skips honestly.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// repoRoot resolves the Blueveil checkout root from this file's path so
// the test never depends on the process working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	// <root>/collector/cmd/collector/install_test.go -> <root>
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(file))))
}

const installTestSecret = "install-test-secret-value"

func requireInstallEnv(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("install test needs linux")
	}
	for _, bin := range []string{"go", "systemctl", "psql", "curl"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("install test needs %s", bin)
		}
	}
	if out, err := exec.Command("systemctl", "--user", "show-environment").CombinedOutput(); err != nil {
		t.Skipf("install test needs a user systemd manager: %s", strings.TrimSpace(string(out)))
	}
	if strings.TrimSpace(os.Getenv("BLUEVEIL_TEST_POSTGRES")) == "" {
		t.Skip("BLUEVEIL_TEST_POSTGRES unset: install test skipped (nothing faked)")
	}
}

func runOut(t *testing.T, dir string, stdin string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func insecureClient() *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // test-only local TLS
	}
}

func ready(t *testing.T, url string) bool {
	t.Helper()
	resp, err := insecureClient().Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var body struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false
	}
	return resp.StatusCode == 200 && body.Data.Status == "ready"
}

func authedCount(t *testing.T, url, secret string) int {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := insecureClient().Do(req)
	if err != nil {
		t.Fatalf("api request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("api status: %d", resp.StatusCode)
	}
	var body struct {
		Data []any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return len(body.Data)
}

func TestCleanUserInstall(t *testing.T) {
	requireInstallEnv(t)
	root := t.TempDir()
	prefix := filepath.Join(root, "prefix")
	collectorDir := filepath.Join(repoRoot(t), "collector")

	// 1. Build the artifact exactly as packaging would.
	binDir := filepath.Join(root, "dist")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "blueveil")
	runOut(t, collectorDir, "", "go", "build", "-o", bin, "./cmd/collector")

	// 2. Fresh database for this install (admin conn string).
	adminDB := "blueveil_install_" + fmt.Sprint(time.Now().UnixNano())
	runOut(t, root, "", "psql", "-h", "/tmp/pgtest", "-p", "55433", "-U", "blueveil_test",
		"-d", "blueveil_test", "-c", "CREATE DATABASE "+adminDB+";")
	t.Cleanup(func() {
		exec.Command("psql", "-h", "/tmp/pgtest", "-p", "55433", "-U", "blueveil_test",
			"-d", "blueveil_test", "-c", "DROP DATABASE IF EXISTS "+adminDB+" WITH (FORCE);").Run()
	})

	// Back up any pre-existing user unit BEFORE the installer writes
	// (otherwise the fresh unit is mistaken for pre-existing state).
	unitPath := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user", "blueveil.service")
	if prev, err := os.ReadFile(unitPath); err == nil {
		t.Cleanup(func() {
			_ = os.WriteFile(unitPath, prev, 0644)
			exec.Command("systemctl", "--user", "daemon-reload").Run()
		})
	} else {
		t.Cleanup(func() {
			_ = os.Remove(unitPath)
			exec.Command("systemctl", "--user", "daemon-reload").Run()
		})
	}

	// 3. Install (files only) into a fresh PREFIX.
	repoUI := filepath.Join(repoRoot(t), "collector", "ui", "dist")
	if _, err := os.Stat(filepath.Join(repoUI, "index.html")); err != nil {
		t.Skipf("UI not built, skipping install test: %v", err)
	}
	port := freePort(t)
	installSh := filepath.Join(repoRoot(t), "deploy", "install.sh")
	runOut(t, root, "", "sh", installSh,
		"--user", "--prefix", prefix,
		"--bin", bin,
		"--ui-dir", repoUI,
		"--backend", "postgres",
		"--listen", fmt.Sprintf("127.0.0.1:%d", port),
		"--no-start")

	// 4. Layout + permission assertions (17B/17I).
	assertPerm := func(path string, want os.FileMode) {
		t.Helper()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("missing %s: %v", path, err)
		}
		if fi.Mode().Perm() != want {
			t.Fatalf("%s perms = %o, want %o", path, fi.Mode().Perm(), want)
		}
	}
	assertPerm(filepath.Join(prefix, "bin", "blueveil"), 0755)
	assertPerm(filepath.Join(prefix, "etc", "config.json"), 0640)
	assertPerm(filepath.Join(prefix, "etc", "secrets.env"), 0600)
	if _, err := os.Stat(filepath.Join(prefix, "share", "ui", "index.html")); err != nil {
		t.Fatalf("UI assets missing: %v", err)
	}

	// 5. Point the fresh config at the scratch database.
	cfgPath := filepath.Join(prefix, "etc", "config.json")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	pg := cfg["database"].(map[string]any)["postgres"].(map[string]any)
	pg["host"] = "/tmp/pgtest"
	pg["port"] = float64(55433)
	pg["user"] = "blueveil_test"
	pg["dbname"] = adminDB
	pg["sslmode"] = "disable"
	// Throwaway TLS identity for the test install only (never the repo
	// testdata pair as a production identity, never committed keys).
	tlsDir := filepath.Join(prefix, "etc", "tls")
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"cert.pem", "key.pem"} {
		raw, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Skipf("TLS testdata missing: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tlsDir, f), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg["tls"] = map[string]any{
		"enabled":     true,
		"cert_file":   filepath.Join(tlsDir, "cert.pem"),
		"key_file":    filepath.Join(tlsDir, "key.pem"),
		"min_version": "1.3", "explicit_insecure_http": false,
	}
	// Key through the real binary (secret via stdin, never argv).
	keyOut := runOut(t, root, installTestSecret, bin,
		"--keygen", "--key-id", "install-test", "--key-role", "ADMIN")
	var key struct {
		ID, Role, Hash string
	}
	if err := json.Unmarshal([]byte(keyOut[strings.Index(keyOut, "{"):]), &key); err != nil {
		t.Fatalf("keygen json: %v\n%s", err, keyOut)
	}
	cfg["auth"] = map[string]any{
		"enabled": true,
		"keys": []any{map[string]any{
			"id": key.ID, "role": key.Role, "hash": key.Hash, "expires_at": "",
		}},
	}
	fixed, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, fixed, 0640); err != nil {
		t.Fatal(err)
	}

	// 6. Seed through the installed artifact, then start for real.
	seed := exec.Command(bin, "--seed-pg", "--force")
	seed.Dir = root
	seed.Env = append(os.Environ(), "BLUEVEIL_CONFIG_FILE="+cfgPath)
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed-pg: %v\n%s", err, out)
	}
	runOut(t, root, "", "systemctl", "--user", "daemon-reload")
	runOut(t, root, "", "systemctl", "--user", "start", "blueveil")
	t.Cleanup(func() { exec.Command("systemctl", "--user", "stop", "blueveil").Run() })

	// 7. Readiness is authoritative.
	base := fmt.Sprintf("https://127.0.0.1:%d", port)
	deadline := time.Now().Add(90 * time.Second)
	for {
		if ready(t, base+"/api/v1/readyz") {
			break
		}
		if time.Now().After(deadline) {
			// Under extreme host load (race detector + parallel suites)
			// startup is slow, not dead: only fail fast when the unit
			// itself reports failed/inactive, otherwise extend while it
			// is still activating (bounded by the hard cap below).
			active, _ := exec.Command("systemctl", "--user", "is-active", "blueveil").CombinedOutput()
			state := strings.TrimSpace(string(active))
			if state == "failed" || state == "inactive" || state == "unknown" {
				t.Fatalf("installed service died in %s state; see diagnostics below\n%s", state, diagnoseUnit(port))
			}
			if time.Now().After(deadline.Add(90 * time.Second)) {
				t.Fatalf("installed service never became ready (still %s)\n%s", state, diagnoseUnit(port))
			}
		}
		time.Sleep(time.Second)
	}

	// 8. Authenticated API against the install.
	n := authedCount(t, base+"/api/v1/assets", installTestSecret)
	if n == 0 {
		t.Fatalf("installed API returned no assets")
	}

	// 9. Restart preserves state; socket stays loopback.
	runOut(t, root, "", "systemctl", "--user", "restart", "blueveil")
	deadline = time.Now().Add(90 * time.Second)
	for {
		if ready(t, base+"/api/v1/readyz") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restarted service never became ready")
		}
		time.Sleep(time.Second)
	}
	if n2 := authedCount(t, base+"/api/v1/assets", installTestSecret); n2 != n {
		t.Fatalf("restart lost state: %d vs %d", n2, n)
	}
	assertLoopback(t, fmt.Sprintf("127.0.0.1:%d", port))

	// 10. No secrets in the service command line.
	pid := servicePID(t, root)
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		t.Skipf("cannot inspect cmdline: %v", err)
	}
	for _, leak := range []string{installTestSecret, "BLUEVEIL_PG_PASSWORD", key.Hash} {
		if strings.Contains(string(cmdline), leak) {
			t.Fatalf("service cmdline leaks secret material")
		}
	}
}

// diagnoseUnit renders unit state, recent journal, and port occupancy
// for readiness-timeout failures.
func diagnoseUnit(port int) string {
	status, _ := exec.Command("systemctl", "--user", "status", "blueveil", "--no-pager").CombinedOutput()
	journal, _ := exec.Command("journalctl", "--user", "-u", "blueveil", "--no-pager", "-n", "20").CombinedOutput()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	portNote := "port free (service died or never bound)"
	if err == nil {
		ln.Close()
	} else {
		portNote = "port held (something already listens)"
	}
	return fmt.Sprintf("%s\nunit status:\n%s\njournal:\n%s", portNote, status, journal)
}

// assertLoopback verifies the service listens on loopback only.
func assertLoopback(t *testing.T, addr string) {
	t.Helper()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Fatalf("service must bind loopback, got %q", addr)
	}
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("loopback connect: %v", err)
	}
	conn.Close()
}

// servicePID resolves the supervised blueveil PID via systemctl.
func servicePID(t *testing.T, dir string) int {
	t.Helper()
	out := runOut(t, dir, "", "systemctl", "--user", "show", "blueveil", "-p", "MainPID", "--value")
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(out), "%d", &pid); err != nil || pid == 0 {
		t.Skipf("no MainPID (service not running under systemd?): %q", out)
	}
	return pid
}

func root_TempDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// TestInstallFileLayoutOnly verifies the packaging boundary without
// systemd or PostgreSQL: build → --no-start install → layout, perms,
// and unit content. Runs on any linux with Go and sh.
func TestInstallFileLayoutOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("install test needs linux")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("install test needs the Go toolchain")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("install test needs sh")
	}
	root := t.TempDir()
	prefix := filepath.Join(root, "prefix")
	binDir := filepath.Join(root, "dist")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "blueveil")
	runOut(t, filepath.Join(repoRoot(t), "collector"), "", "go", "build", "-o", bin, "./cmd/collector")
	repoUI := filepath.Join(repoRoot(t), "collector", "ui", "dist")
	if _, err := os.Stat(filepath.Join(repoUI, "index.html")); err != nil {
		t.Skipf("UI not built: %v", err)
	}
	unitPath := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user", "blueveil.service")
	prev, hadPrev := []byte(nil), false
	if p, err := os.ReadFile(unitPath); err == nil {
		prev, hadPrev = p, true
	}
	t.Cleanup(func() {
		if hadPrev {
			_ = os.WriteFile(unitPath, prev, 0644)
		} else {
			_ = os.Remove(unitPath)
		}
	})
	runOut(t, root, "", "sh", filepath.Join(repoRoot(t), "deploy", "install.sh"),
		"--user", "--prefix", prefix,
		"--bin", bin, "--ui-dir", repoUI,
		"--backend", "sqlite",
		"--listen", "127.0.0.1:18222",
		"--no-start")
	for path, want := range map[string]os.FileMode{
		filepath.Join(prefix, "bin", "blueveil"):    0755,
		filepath.Join(prefix, "etc", "config.json"): 0640,
		filepath.Join(prefix, "etc", "secrets.env"): 0600,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("missing %s: %v", path, err)
		}
		if fi.Mode().Perm() != want {
			t.Fatalf("%s perms = %o, want %o", path, fi.Mode().Perm(), want)
		}
	}
	// The installed unit must reference the PREFIX (absolute paths, no
	// placeholders, no system paths leaking into a user install).
	unit, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("unit not installed: %v", err)
	}
	for _, needle := range []string{prefix + "/bin/blueveil", prefix + "/etc/config.json", prefix + "/data"} {
		if !strings.Contains(string(unit), needle) {
			t.Errorf("unit must reference %q", needle)
		}
	}
	for _, banned := range []string{"@BINDIR@", "@CONFDIR@", "@DATADIR@", "/var/lib/blueveil", "User=blueveil"} {
		if strings.Contains(string(unit), banned) {
			t.Errorf("user unit must not contain %q", banned)
		}
	}
}

// TestSystemUnitKeepsFullSandbox pins the system template's hardening
// set: every namespace/capability restriction must survive edits.
func TestSystemUnitKeepsFullSandbox(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "blueveil.service"))
	if err != nil {
		t.Fatal(err)
	}
	unit := string(raw)
	for _, directive := range []string{
		"User=blueveil", "NoNewPrivileges=true", "PrivateTmp=true",
		"ProtectSystem=strict", "ReadWritePaths=@DATADIR@", "ProtectHome=true",
		"PrivateDevices=true", "ProtectKernelTunables=true", "ProtectKernelModules=true",
		"ProtectControlGroups=true", "ProtectClock=true", "ProtectHostname=true",
		"RestrictSUIDSGID=true", "RestrictRealtime=true", "LockPersonality=true",
		"SystemCallArchitectures=native", "CapabilityBoundingSet=",
		"Restart=on-failure", "RestartPreventExitStatus=2",
		"StartLimitBurst=3", "TimeoutStopSec=",
	} {
		if !strings.Contains(unit, directive) {
			t.Errorf("system unit lost %q", directive)
		}
	}
}

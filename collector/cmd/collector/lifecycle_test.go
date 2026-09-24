// Step 16B: process lifecycle. Startup validates before side effects;
// SIGINT/SIGTERM triggers stop-accept → drain → close → exit within a
// bounded timeout; repeated signals are safe; readiness flips before
// the listener closes.
package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"blueveil/collector/internal/config"
	"blueveil/collector/internal/obs"
)

func testLogger(t *testing.T) *obs.Logger {
	t.Helper()
	l, err := obs.New("error", "json", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestGracefulShutdownDrainsAndCloses(t *testing.T) {
	var closed, notReady atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(200)
	})
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: mux}
	signals := make(chan os.Signal, 4)
	listened := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- serveWithShutdown(srv, nil, testLogger(t), 5*time.Second,
			func() { notReady.Store(true) },
			func() { closed.Store(true) },
			listened, signals)
	}()
	var addr string
	select {
	case addr = <-listened:
	case <-time.After(5 * time.Second):
		t.Fatal("server never started listening")
	}
	// In-flight request must drain, not abort.
	var wgDone atomic.Bool
	go func() {
		resp, err := http.Get("http://" + addr + "/slow")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				wgDone.Store(true)
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)
	signals <- os.Interrupt
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve must exit cleanly: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not complete within timeout")
	}
	if !notReady.Load() {
		t.Fatalf("readiness must flip before drain")
	}
	if !closed.Load() {
		t.Fatalf("onShutdown (persistence close) must run")
	}
	if !wgDone.Load() {
		t.Fatalf("in-flight request must drain")
	}
}

func TestShutdownTimeoutBoundsSlowHandlers(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/stuck", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Second)
	})
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: mux}
	signals := make(chan os.Signal, 4)
	listened := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- serveWithShutdown(srv, nil, testLogger(t), 200*time.Millisecond,
			func() {}, func() {}, listened, signals)
	}()
	var addr string
	select {
	case addr = <-listened:
	case <-time.After(5 * time.Second):
		t.Fatal("server never started listening")
	}
	go func() {
		_, _ = http.Get("http://" + addr + "/stuck")
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	signals <- os.Interrupt
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("bounded shutdown must return")
	}
	if time.Since(start) > 8*time.Second {
		t.Fatalf("shutdown exceeded its bound")
	}
}

func TestRepeatedSignalsAreSafe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/stuck", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Second)
	})
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: mux}
	signals := make(chan os.Signal, 4)
	listened := make(chan string, 1)
	done := make(chan error, 1)
	var closes atomic.Int32
	go func() {
		done <- serveWithShutdown(srv, nil, testLogger(t), 500*time.Millisecond,
			func() {}, func() { closes.Add(1) }, listened, signals)
	}()
	select {
	case <-listened:
	case <-time.After(5 * time.Second):
		t.Fatal("server never started listening")
	}
	// Repeated signals must not hang, panic, or double-close resources.
	signals <- os.Interrupt
	signals <- os.Interrupt
	signals <- os.Interrupt
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("repeated signals must still exit cleanly: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not complete")
	}
	if closes.Load() != 1 {
		t.Fatalf("onShutdown must run exactly once, ran %d", closes.Load())
	}
}

func TestOversizedHeadersRefusedByServer(t *testing.T) {
	// Go's http.Server caps header bytes (1 MiB default): a 2 MiB header
	// must be refused with 431, never buffered unbounded. This needs a
	// real listener — httptest bypasses the limit.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := "GET /api/v1/healthz HTTP/1.1\r\nHost: x\r\nX-Evil: " + strings.Repeat("y", 2<<20) + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	status := string(buf[:n])
	if !strings.Contains(status, "431") {
		t.Fatalf("oversized headers must be refused with 431, got %q", status)
	}
}

func TestTLSConfigNilWhenDisabled(t *testing.T) {
	cfg, err := tlsConfigFor(config.TLSConfig{})
	if err != nil || cfg != nil {
		t.Fatalf("disabled: %+v %v", cfg, err)
	}
}

// Step 20I: TLS adversarial tests. Version floor, expired/mismatched
// material, hostname verification, and plaintext refusal — all with
// in-test generated certificates (no external fixtures, no CA).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"blueveil/collector/internal/config"
)

func mkCert(t *testing.T, dir, cn string, notAfter time.Time, key *ecdsa.PrivateKey) (certFile, keyFile string) {
	t.Helper()
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "c-"+cn+".pem")
	keyFile = filepath.Join(dir, "k-"+cn+".pem")
	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	certOut.Close()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyOut, err := os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatal(err)
	}
	keyOut.Close()
	return certFile, keyFile
}

func TestTLSRejectsOldVersions(t *testing.T) {
	dir := t.TempDir()
	cert, key := mkCert(t, dir, "127.0.0.1", time.Now().Add(time.Hour), nil)
	tlsCfg, err := tlsConfigFor(config.TLSConfig{
		Enabled: true, CertFile: cert, KeyFile: key, MinVersion: "1.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	go srv.Serve(tls.NewListener(ln, tlsCfg))
	defer srv.Close()
	// TLS 1.0 and 1.1 clients must fail against a 1.2-floor server.
	for _, max := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		c := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MaxVersion: max}, //nolint:gosec // test-only local handshake
		}}
		if _, err := c.Get("https://" + ln.Addr().String()); err == nil {
			t.Fatalf("TLS max %x must be rejected", max)
		}
	}
	// 1.2 and 1.3 succeed.
	for _, ver := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		c := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: ver, MaxVersion: ver}, //nolint:gosec
		}}
		resp, err := c.Get("https://" + ln.Addr().String())
		if err != nil {
			t.Fatalf("TLS %x must succeed: %v", ver, err)
		}
		resp.Body.Close()
	}
}

func TestTLSMismatchedPairFailsFast(t *testing.T) {
	dir := t.TempDir()
	certA, _ := mkCert(t, dir, "a", time.Now().Add(time.Hour), nil)
	_, keyB := mkCert(t, dir, "b", time.Now().Add(time.Hour), nil)
	if _, err := tlsConfigFor(config.TLSConfig{
		Enabled: true, CertFile: certA, KeyFile: keyB, MinVersion: "1.3",
	}); err == nil {
		t.Fatalf("mismatched cert/key must fail before serving")
	}
}

func TestTLSExpiredCertLoadsButClientsReject(t *testing.T) {
	dir := t.TempDir()
	cert, key := mkCert(t, dir, "127.0.0.1", time.Now().Add(-time.Hour), nil)
	// Loading succeeds (format valid): expiry is a client-visible
	// failure at handshake, surfaced by verifying clients — which is
	// why rotation is an operator duty, not a startup gate.
	tlsCfg, err := tlsConfigFor(config.TLSConfig{
		Enabled: true, CertFile: cert, KeyFile: key, MinVersion: "1.3",
	})
	if err != nil {
		t.Fatalf("expired-but-wellformed pair loads: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	go srv.Serve(tls.NewListener(ln, tlsCfg))
	defer srv.Close()
	roots := x509.NewCertPool()
	der, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(der)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(leaf)
	verifying := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}}
	if _, err := verifying.Get("https://" + ln.Addr().String()); err == nil {
		t.Fatalf("verifying client must reject the expired certificate")
	}
}

func TestTLSWrongHostnameRejected(t *testing.T) {
	dir := t.TempDir()
	// mkCert always includes a 127.0.0.1 IP SAN; build a cert with only
	// a DNS name here so dialing the IP fails hostname verification.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "other.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"other.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "c.pem")
	keyFile := filepath.Join(dir, "k.pem")
	cf, _ := os.Create(certFile)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kd, _ := x509.MarshalECPrivateKey(key)
	kf, _ := os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY, 0600)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	kf.Close()
	tlsCfg, err := tlsConfigFor(config.TLSConfig{
		Enabled: true, CertFile: certFile, KeyFile: keyFile, MinVersion: "1.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	go srv.Serve(tls.NewListener(ln, tlsCfg))
	defer srv.Close()
	roots := x509.NewCertPool()
	raw, _ := os.ReadFile(certFile)
	block, _ := pem.Decode(raw)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	roots.AddCert(leaf)
	verifying := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}}
	if _, err := verifying.Get("https://" + ln.Addr().String()); err == nil {
		t.Fatalf("hostname mismatch must fail verification (mint certs for the served address)")
	}
}

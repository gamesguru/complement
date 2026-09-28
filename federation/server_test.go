package federation

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/matrix-org/complement/config"
	"github.com/matrix-org/complement/internal"
)

type fedDeploy struct {
	cfg     *config.Complement
	tripper http.RoundTripper
}

func (d *fedDeploy) GetConfig() *config.Complement {
	return d.cfg
}
func (d *fedDeploy) RoundTripper() http.RoundTripper {
	return d.tripper
}

func TestComplementServerIsSigned(t *testing.T) {
	cfg := config.NewConfigFromEnvVars("test", "unimportant")
	cfg.HostnameRunningComplement = "localhost"
	srv := NewServer(t, &fedDeploy{
		cfg:     cfg,
		tripper: http.DefaultClient.Transport,
	})
	srv.UnexpectedRequestsAreErrors = false
	cancel := srv.Listen()
	t.Logf("Listening on %s", srv.serverName)
	defer cancel()

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(cfg.CACertificate)

	testCases := []struct {
		config      *tls.Config
		wantSuccess bool
	}{
		{
			config: &tls.Config{
				RootCAs: caCertPool,
			},
			wantSuccess: true,
		},
		{
			config:      &tls.Config{},
			wantSuccess: false,
		},
	}
	for _, tc := range testCases {
		transport := &http.Transport{TLSClientConfig: tc.config}
		client := &http.Client{Transport: transport}

		resp, err := client.Get("https://" + string(srv.ServerName()))
		if err != nil {
			if tc.wantSuccess {
				t.Fatalf("Failed to GET: %s", err)
			} else {
				return // wanted failure, got failure
			}
		}
		defer internal.CloseIO(resp.Body, "server response body")
		if !tc.wantSuccess {
			t.Fatalf("request succeeded when we expected it to fail")
		}

		if resp.StatusCode != 404 {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
	}
}

func TestFederationServersHaveIndependentCertificates(t *testing.T) {
	cfg := config.NewConfigFromEnvVars("test", "unimportant")
	cfg.HostnameRunningComplement = "localhost"
	deployment := &fedDeploy{
		cfg:     cfg,
		tripper: http.DefaultClient.Transport,
	}
	first := NewServer(t, deployment)
	second := NewServer(t, deployment)

	if first.srv.TLSConfig == nil || len(first.srv.TLSConfig.Certificates) != 1 {
		t.Fatal("first federation server does not have an in-memory TLS certificate")
	}
	if second.srv.TLSConfig == nil || len(second.srv.TLSConfig.Certificates) != 1 {
		t.Fatal("second federation server does not have an in-memory TLS certificate")
	}
	firstSerial := first.srv.TLSConfig.Certificates[0].Leaf.SerialNumber
	secondSerial := second.srv.TLSConfig.Certificates[0].Leaf.SerialNumber
	if firstSerial.Cmp(secondSerial) == 0 {
		t.Fatal("separate federation servers unexpectedly share a certificate")
	}
}

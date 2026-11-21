// Package linkproxy sits between the homeservers of a Complement deployment and
// lets a test allow, block, or hold federation traffic on individual
// homeserver-to-homeserver links, and see every request that crossed each link.
//
// How it works: each homeserver's peers resolve to the machine running the
// test. With COMPLEMENT_LINK_PROXY_HOMESERVERS, Docker installs those names
// before the homeserver starts; otherwise New appends them to /etc/hosts.
// The proxy listens on :8448,
// presents a certificate for the requested server name signed by the Complement
// CA (which homeservers already trust), identifies the sending homeserver by
// its container IP, applies the link's mode, and forwards allowed requests to
// the real destination. Because the destination name is unchanged, federation
// request signatures stay valid.
//
// Limits: it only intercepts name-based connections to port 8448, and only
// those started after New returns (existing pooled connections bypass it).
// Homeservers that do not honour /etc/hosts are not intercepted; Verify reports
// whether traffic is flowing through the proxy.
package linkproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	mobyclient "github.com/moby/moby/client"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/ct"
	"github.com/matrix-org/complement/internal/docker"
)

// Mode is how traffic on a link is treated.
type Mode int

const (
	// Allow forwards requests to the destination.
	Allow Mode = iota
	// Block answers 503 immediately, so the sender fails fast and backs off.
	Block
	// Hold keeps requests waiting until the link is changed to Allow (or Block).
	Hold
)

// String returns "allow", "block", or "hold". It panics for an undefined mode.
func (m Mode) String() string { return [...]string{"allow", "block", "hold"}[m] }

type link struct{ src, dst string }

type pathBlock struct{ dst, substr string }

// Entry records one request that reached the proxy.
type Entry struct {
	Time     time.Time
	Src, Dst string
	Method   string
	Path     string
	Mode     Mode
	// Status is the response status sent to the sender.
	Status int
}

// Proxy is a running link proxy.
type Proxy struct {
	deployment complement.Deployment
	ca         *x509.Certificate
	caKey      *rsa.PrivateKey
	ipToHS     map[string]string

	mu    sync.Mutex
	modes map[link]Mode
	// pathBlocks answer 503 to matching requests even on an Allow link.
	pathBlocks []pathBlock
	changed    chan struct{} // closed and replaced whenever a mode changes
	log        []Entry
	certs      map[string]*tls.Certificate
	server     *http.Server
}

// New starts a proxy for the named homeservers (e.g. "hs1", "hs2") and points
// each homeserver's view of the others at it. Call before any federation
// traffic between them, and defer Close. Links initially allow traffic. If :8448
// is in use, New waits up to ten minutes to bind it. Container inspection, host
// mapping, or listener setup failures terminate the test.
func New(t ct.TestLike, deployment complement.Deployment, hsNames ...string) *Proxy {
	t.Helper()
	cfg := deployment.GetConfig()
	p := &Proxy{
		deployment: deployment,
		ca:         cfg.CACertificate,
		caKey:      cfg.CAPrivateKey,
		ipToHS:     map[string]string{},
		modes:      map[link]Mode{},
		changed:    make(chan struct{}),
		certs:      map[string]*tls.Certificate{},
	}
	for _, hs := range hsNames {
		ip := containerIP(t, deployment, hs)
		p.ipToHS[ip] = hs
	}

	ln := listenExclusive(t, &tls.Config{GetCertificate: p.certFor})
	p.server = &http.Server{Handler: p}
	go p.server.Serve(ln) //nolint:errcheck // returns on Close

	if !preMapped(cfg.LinkProxyHomeservers, hsNames) {
		for _, hs := range hsNames {
			var peers []string
			for _, other := range hsNames {
				if other != hs {
					peers = append(peers, other)
				}
			}
			pointAtHost(t, deployment, hs, cfg.HostnameRunningComplement, peers)
		}
	}
	return p
}

// listenTimeout bounds how long New waits for another proxy, possibly in a
// test process for another package, to release :8448.
const listenTimeout = 10 * time.Minute

// listenExclusive binds :8448. The kernel allows one listener per port, so the
// bind is the cross-process reservation: when another proxy holds the port it
// waits for that proxy's Close rather than failing, and gives up after
// listenTimeout. Binding failures other than an occupied port, or a timeout,
// terminate the test.
func listenExclusive(t ct.TestLike, cfg *tls.Config) net.Listener {
	t.Helper()
	deadline := time.Now().Add(listenTimeout)
	for {
		ln, err := tls.Listen("tcp", ":8448", cfg)
		if err == nil {
			return ln
		}
		if !errors.Is(err, syscall.EADDRINUSE) || time.Now().After(deadline) {
			ct.Fatalf(t, "linkproxy: cannot listen on :8448 (is another proxy or homeserver using it?): %s", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// preMapped reports whether Docker already maps every name to the host, which
// COMPLEMENT_LINK_PROXY_HOMESERVERS=n does for hs1 through hsn. Any other name
// is not covered, so New falls back to rewriting /etc/hosts for all of them.
func preMapped(linkProxyHomeservers int, hsNames []string) bool {
	if linkProxyHomeservers == 0 {
		return false
	}
	for _, hs := range hsNames {
		n, err := strconv.Atoi(strings.TrimPrefix(hs, "hs"))
		if err != nil || !strings.HasPrefix(hs, "hs") || hs != fmt.Sprintf("hs%d", n) || n < 1 || n > linkProxyHomeservers {
			return false
		}
	}
	return true
}

// Close stops the proxy. Defer it after New.
func (p *Proxy) Close() { _ = p.server.Close() }

// Set changes the mode of the link src -> dst (both homeserver names like "hs1").
// Changing a held link to Allow releases everything waiting on it.
func (p *Proxy) Set(src, dst string, m Mode) {
	p.mu.Lock()
	p.modes[link{src, dst}] = m
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
}

// SetAll sets the mode of every link out of src.
func (p *Proxy) SetAll(src string, m Mode) {
	p.mu.Lock()
	for _, dst := range p.ipToHS {
		if dst != src {
			p.modes[link{src, dst}] = m
		}
	}
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
}

// SetInto sets the mode of every link into dst.
func (p *Proxy) SetInto(dst string, m Mode) {
	p.mu.Lock()
	for _, src := range p.ipToHS {
		if src != dst {
			p.modes[link{src, dst}] = m
		}
	}
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
}

// BlockPathInto makes every request into dst whose path contains pathSubstr
// fail with 503 once the link is no longer held, until the proxy is closed. A
// test uses it to switch off one delivery mechanism (such as /send/) so that only
// another (reconciliation) can close a gap.
func (p *Proxy) BlockPathInto(dst, pathSubstr string) {
	p.mu.Lock()
	p.pathBlocks = append(p.pathBlocks, pathBlock{dst, pathSubstr})
	p.mu.Unlock()
}

// pathBlocked reports whether a persistent block for dst matches a substring of path.
func (p *Proxy) pathBlocked(dst, path string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, b := range p.pathBlocks {
		if b.dst == dst && strings.Contains(path, b.substr) {
			return true
		}
	}
	return false
}

// Log returns a copy of requests recorded so far, in recording order. Requests
// are recorded after forwarding, rejection, or cancellation while held; requests
// still in progress are absent.
func (p *Proxy) Log() []Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Entry(nil), p.log...)
}

// Count returns how many logged requests went from src to dst with a path
// containing pathSubstr. Empty src, dst or pathSubstr match anything.
func (p *Proxy) Count(src, dst, pathSubstr string) int {
	n := 0
	for _, e := range p.Log() {
		if (src == "" || e.Src == src) && (dst == "" || e.Dst == dst) && strings.Contains(e.Path, pathSubstr) {
			n++
		}
	}
	return n
}

// CountStatus is Count restricted to a response status.
func (p *Proxy) CountStatus(src, dst, pathSubstr string, status int) int {
	n := 0
	for _, e := range p.Log() {
		if (src == "" || e.Src == src) && (dst == "" || e.Dst == dst) && strings.Contains(e.Path, pathSubstr) && e.Status == status {
			n++
		}
	}
	return n
}

// mode returns the link's current mode (Allow if unset) and a channel that closes
// on the next call to Set, SetAll, or SetInto.
func (p *Proxy) mode(l link) (Mode, <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.modes[l], p.changed
}

// record appends a request entry to the proxy log.
func (p *Proxy) record(e Entry) {
	p.mu.Lock()
	p.log = append(p.log, e)
	p.mu.Unlock()
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader records code and forwards it to the underlying response writer.
func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// ServeHTTP routes a request from its source container IP to the destination
// named by TLS SNI. Held requests wait for a mode change or cancellation; canceled
// held requests are recorded with status 0. Blocked links or matching path blocks
// return 503 once the link is no longer held. Allowed requests are forwarded with
// their original Host header, and forwarding errors return 502. Handled requests
// are recorded after forwarding, rejection, or cancellation while held.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remote, _, _ := net.SplitHostPort(r.RemoteAddr)
	src := p.ipToHS[remote]
	if src == "" {
		src = "unknown(" + remote + ")"
	}
	dst := ""
	if r.TLS != nil {
		dst = r.TLS.ServerName
	}
	l := link{src, dst}

	var m Mode
	for {
		var changed <-chan struct{}
		m, changed = p.mode(l)
		if m != Hold {
			break
		}
		select {
		case <-changed:
		case <-r.Context().Done():
			p.record(Entry{Time: time.Now(), Src: src, Dst: dst, Method: r.Method, Path: r.URL.Path, Mode: Hold, Status: 0})
			return
		}
	}

	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	if m == Block || p.pathBlocked(dst, r.URL.Path) {
		sw.WriteHeader(http.StatusServiceUnavailable)
		p.record(Entry{Time: time.Now(), Src: src, Dst: dst, Method: r.Method, Path: r.URL.Path, Mode: Block, Status: sw.status})
		return
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = dst
			pr.Out.Host = r.Host
		},
		Transport: p.deployment.RoundTripper(),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(sw, r)
	p.record(Entry{Time: time.Now(), Src: src, Dst: dst, Method: r.Method, Path: r.URL.Path, Mode: Allow, Status: sw.status})
}

// certFor mints (and caches) a certificate for the requested server name,
// signed by the Complement CA. Key generation and certificate creation errors
// are returned to the TLS handshake; failed certificates are not cached.
func (p *Proxy) certFor(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.certs[name]; ok {
		return c, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, p.ca.Raw}, PrivateKey: key}
	p.certs[name] = c
	return c, nil
}

// dockerExec runs a shell command inside the given container through the
// deployment's Docker client, returning combined stdout+stderr.
func dockerExec(deployment complement.Deployment, containerID string, script string) (string, error) {
	dockerDeployment, ok := deployment.(*docker.Deployment)
	if !ok {
		return "", fmt.Errorf("container exec requires a Docker-backed deployment, got %T", deployment)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	exec, err := dockerDeployment.Deployer.Docker.ExecCreate(ctx, containerID, mobyclient.ExecCreateOptions{
		Cmd:          []string{"sh", "-c", script},
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return "", err
	}

	attach, err := dockerDeployment.Deployer.Docker.ExecAttach(ctx, exec.ID, mobyclient.ExecAttachOptions{})
	if err != nil {
		return "", err
	}
	defer attach.Close()

	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, attach.Reader); err != nil {
		return stdout.String() + stderr.String(), err
	}
	output := stdout.String() + stderr.String()

	inspect, err := dockerDeployment.Deployer.Docker.ExecInspect(ctx, exec.ID, mobyclient.ExecInspectOptions{})
	if err != nil {
		return output, err
	}
	if inspect.ExitCode != 0 {
		return output, fmt.Errorf("command exited with code %d", inspect.ExitCode)
	}
	return output, nil
}

// containerIP returns hs's container IP on the deployment network. Inspection
// has a 20-second timeout; an execution error or empty address terminates the test.
func containerIP(t ct.TestLike, deployment complement.Deployment, hs string) string {
	t.Helper()
	dockerDeployment, ok := deployment.(*docker.Deployment)
	if !ok {
		ct.Fatalf(t, "linkproxy: containerIP requires a Docker-backed deployment, got %T", deployment)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inspect, err := dockerDeployment.Deployer.Docker.ContainerInspect(ctx, deployment.ContainerID(t, hs), mobyclient.ContainerInspectOptions{})
	if err != nil {
		ct.Fatalf(t, "linkproxy: cannot inspect container for %s: %v", hs, err)
	}
	if inspect.Container.NetworkSettings == nil {
		ct.Fatalf(t, "linkproxy: container %s has no network settings", hs)
	}
	netSetting, ok := inspect.Container.NetworkSettings.Networks[deployment.Network()]
	if !ok || !netSetting.IPAddress.IsValid() {
		ct.Fatalf(t, "linkproxy: container %s has no IP on network %q", hs, deployment.Network())
	}
	return netSetting.IPAddress.String()
}

// pointAtHost appends an /etc/hosts mapping in hs for peers, using the first
// address listed for hostName in that container. Docker execution has a 20-second
// timeout, and execution errors terminate the test.
func pointAtHost(t ct.TestLike, deployment complement.Deployment, hs, hostName string, peers []string) {
	t.Helper()
	script := fmt.Sprintf(`set -- $(grep -m1 %s /etc/hosts); echo "$1 %s" >> /etc/hosts`, hostName, strings.Join(peers, " "))
	out, err := dockerExec(deployment, deployment.ContainerID(t, hs), script)
	if err != nil {
		ct.Fatalf(t, "linkproxy: cannot rewrite /etc/hosts in %s: %v %s", hs, err, out)
	}
}

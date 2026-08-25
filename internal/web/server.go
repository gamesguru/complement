package web

import (
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/gorilla/mux"

	"github.com/matrix-org/complement/config"
)

// Server is a lightweight HTTP server used by tests.
type Server struct {
	URL      string
	Port     int
	server   *http.Server
	listener net.Listener
}

// NewServer starts a test HTTP server bound to an ephemeral port.
func NewServer(t *testing.T, comp *config.Complement, configFunc func(router *mux.Router)) *Server {
	t.Helper()

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Could not create listener for web server: %s", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	r := mux.NewRouter()

	configFunc(r)

	server := &http.Server{Addr: ":0", Handler: r}

	go server.Serve(listener)

	return &Server{
		URL:      fmt.Sprintf("http://%s:%d", comp.HostnameRunningComplement, port),
		Port:     port,
		server:   server,
		listener: listener,
	}
}

// Close shuts down the server and its listener.
func (s *Server) Close() {
	s.server.Close()
	s.listener.Close()
}

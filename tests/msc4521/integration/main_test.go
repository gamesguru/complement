package integration

import (
	"os"
	"testing"

	"github.com/matrix-org/complement"
)

// TestMain starts the Complement runner only when one is configured. Without
// COMPLEMENT_BASE_IMAGE the package is a plain `go test` that runs the library
// checks alone; with it, every scenario also runs against a real homeserver.
func TestMain(m *testing.M) {
	if os.Getenv("COMPLEMENT_BASE_IMAGE") == "" {
		os.Exit(m.Run())
	}
	complement.TestMain(m, "msc4521_integration")
}

package integration

import (
	"os"
	"testing"

	"github.com/matrix-org/complement"
)

func TestMain(m *testing.M) {
	// Dirty deployments reuse hs1 from the first subtest. Install all peer
	// mappings before that container starts so the resolver can route through
	// linkproxy when the cluster tests run later.
	if os.Getenv("COMPLEMENT_LINK_PROXY_HOMESERVERS") == "" {
		if err := os.Setenv("COMPLEMENT_LINK_PROXY_HOMESERVERS", "16"); err != nil {
			panic(err)
		}
	}
	complement.TestMain(m, "msc4521_integration")
}

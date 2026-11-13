//go:build !dendrite_blacklist && !venator_blacklist

package linkproxy

import (
	"os"
	"testing"

	"github.com/matrix-org/complement"
)

func TestMain(m *testing.M) {
	// A homeserver reads /etc/hosts when it starts, so the peer mappings the
	// proxy needs must be installed before the container starts, not appended
	// afterwards. Dirty deployments start hs1 and hs2 up front.
	if os.Getenv("COMPLEMENT_LINK_PROXY_HOMESERVERS") == "" {
		if err := os.Setenv("COMPLEMENT_LINK_PROXY_HOMESERVERS", "16"); err != nil {
			panic(err)
		}
	}
	complement.TestMain(m, "linkproxy")
}

//go:build !dendrite_blacklist && !venator_blacklist

package activeedurecon

import (
	"testing"

	"github.com/matrix-org/complement"
)

func TestMain(m *testing.M) {
	complement.TestMain(m, "msc4521_active_edu_recon")
}

//go:build !dendrite_blacklist && !venator_blacklist

package activeedurecon

import (
	"testing"

	"github.com/matrix-org/complement"
)

func TestMain(m *testing.M) {
	complement.TestMain(m, "msc4521/active_edu_recon")
}

//go:build !dendrite_blacklist && !venator_blacklist

package integration

import (
	"testing"

	"github.com/matrix-org/complement"
)

func TestMain(m *testing.M) {
	complement.TestMain(m, "msc4521_integration")
}

//go:build !dendrite_blacklist
// +build !dendrite_blacklist

package tests

import (
	"testing"

	"github.com/matrix-org/complement"
)

func TestMain(m *testing.M) {
	complement.TestMain(m, "msc3757")
}

//go:build !dendrite_blacklist && !venator_blacklist

// Venator does not yet implement federation.

package activeedurecon

import (
	"testing"

	"github.com/matrix-org/gomatrixserverlib/spec"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/helpers"
)

// TestMSC4521DAGBisectionIntegration is the homeserver-level companion to
// TestMSC4521DAGBisectionMatrix. It deliberately deploys two real homeservers
// and creates a federated room before entering the case matrix. Once the
// MSC4521 bisection API and authenticated partial-view boundary are defined,
// each case should mutate the hs1/hs2 views through the supported federation
// test hooks and assert the reported earliest omission or divergence.
//
// The current protocol only exposes digest/strata/sketch reconciliation; it
// has no bisection operation or supported way for Complement to manufacture a
// peer-local partial DAG. Keeping this as an explicit integration scaffold
// prevents the library matrix from becoming the only coverage layer.
func TestMSC4521DAGBisectionIntegration(t *testing.T) {
	t.Skip("MSC4521 DAG-bisection API and authenticated partial-view test hooks are not defined")

	deployment := complement.Deploy(t, 2)
	defer deployment.Destroy(t)

	hs1 := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	hs2 := deployment.Register(t, "hs2", helpers.RegistrationOpts{})
	roomID := hs1.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
	hs2.MustJoinRoom(t, roomID, []spec.ServerName{
		deployment.GetFullyQualifiedHomeserverName(t, "hs1"),
	})

	viewPairs := []string{
		"TotalTotal",
		"TotalPartial",
		"PartialTotal",
		"PartialPartial",
	}
	differences := []string{
		"EventOmission",
		"StateOmission",
		"EventConflict",
		"StateConflict",
	}

	for _, viewPair := range viewPairs {
		viewPair := viewPair
		t.Run(viewPair, func(t *testing.T) {
			for _, difference := range differences {
				difference := difference
				t.Run(difference, func(t *testing.T) {
					t.Skip("MSC4521 DAG-bisection API and authenticated partial-view test hooks are not defined")
				})
			}
		})
	}
}

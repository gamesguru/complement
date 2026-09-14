//go:build !dendrite_blacklist
// +build !dendrite_blacklist

package tests

import (
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/helpers"
)

// slidingSync issues one MSC4186 simplified sliding sync request over a single
// named connection and returns the new pos token plus the parsed response root.
//
// In the MSC4186 request, pos and timeout are query parameters while conn_id
// and the lists live in the body; putting pos in the body instead makes the
// server treat every call as an initial sync and reset the connection, so the
// distinction matters for testing incremental behaviour.
//
// A single list with a wide range selects every room the user is joined to,
// invited to, or knocking on, which is what Element X relies on to populate its
// room list.
func slidingSync(t *testing.T, user *client.CSAPI, connID, pos string, timeoutMS int) (string, gjson.Result) {
	t.Helper()
	query := url.Values{}
	if pos != "" {
		query.Set("pos", pos)
	}
	if timeoutMS > 0 {
		query.Set("timeout", strconv.Itoa(timeoutMS))
	}
	body := map[string]interface{}{
		"conn_id": connID,
		"lists": map[string]interface{}{
			"all": map[string]interface{}{
				"ranges":         [][]int{{0, 99}},
				"required_state": []interface{}{},
				"timeline_limit": 1,
			},
		},
	}
	resp := user.MustDo(t, "POST",
		[]string{"_matrix", "client", "unstable", "org.matrix.simplified_msc3575", "sync"},
		client.WithQueries(query),
		client.WithJSONBody(t, body),
	)
	root := gjson.ParseBytes(client.ParseJSON(t, resp))
	return root.Get("pos").Str, root
}

func roomInList(root gjson.Result, roomID string) gjson.Result {
	return root.Get("rooms." + gjson.Escape(roomID))
}

// inviteAfterRemoval invites bob, retrying while the room-hosting server still
// reports him as joined or banned. A self-leave authored on bob's server has to
// federate back to the room's server before that server will accept a fresh
// invite, so the invite can briefly race the leave.
func inviteAfterRemoval(t *testing.T, alice, bob *client.CSAPI, roomID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp := alice.InviteRoom(t, roomID, bob.UserID)
		if resp.StatusCode == 200 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("could not invite %s after removal: HTTP %d", bob.UserID, resp.StatusCode)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestFederationSlidingSyncReInviteAfterLeave reproduces a room-list bug
// reported against Element X: after a user leaves (or is kicked from) a remote
// room and is then invited back to the same room, the re-invite often fails to
// surface in the simplified sliding sync room list.
//
// The user (bob) lives on hs2; the room lives on hs1, so bob's server receives
// the re-invite over federation as stripped invite state rather than as a local
// timeline event.
func TestFederationSlidingSyncReInviteAfterLeave(t *testing.T) {
	deployment := complement.Deploy(t, 2)
	defer deployment.Destroy(t)

	// removeBob takes bob out of the room in the way the subtest is named for,
	// leaving alice able to invite him again.
	cases := map[string]func(t *testing.T, alice, bob *client.CSAPI, roomID string){
		"leave": func(t *testing.T, alice, bob *client.CSAPI, roomID string) {
			bob.MustLeaveRoom(t, roomID)
		},
		"kick": func(t *testing.T, alice, bob *client.CSAPI, roomID string) {
			alice.MustDo(t, "POST", []string{"_matrix", "client", "v3", "rooms", roomID, "kick"},
				client.WithJSONBody(t, map[string]interface{}{"user_id": bob.UserID}))
		},
	}

	for name, removeBob := range cases {
		t.Run(name+" then reinvite", func(t *testing.T) {
			alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{LocalpartSuffix: "alice"})
			bob := deployment.Register(t, "hs2", helpers.RegistrationOpts{LocalpartSuffix: "bob"})

			roomID := alice.MustCreateRoom(t, map[string]interface{}{
				"preset": "private_chat",
				"invite": []string{bob.UserID},
			})
			bob.MustJoinRoom(t, roomID, []spec.ServerName{"hs1"})

			// Establish bob's sliding-sync connection while joined so it records a
			// non-zero roomsince for the room, then sync once more to commit it.
			connID := "reinvite-" + name
			pos, root := slidingSync(t, bob, connID, "", 0)
			if !roomInList(root, roomID).Exists() {
				t.Fatalf("joined room %s absent from initial sliding sync: %s", roomID, root.Raw)
			}
			pos, _ = slidingSync(t, bob, connID, pos, 0)

			// Remove bob, then sync so the connection advances past the removal.
			removeBob(t, alice, bob, roomID)
			pos, _ = slidingSync(t, bob, connID, pos, 0)

			// Re-invite bob to the same room.
			inviteAfterRemoval(t, alice, bob, roomID)

			// Diagnostic: a brand-new connection (roomsince == 0) bypasses the
			// incremental staleness gate. If the room shows here but not on the
			// existing connection, the bug is the gate; if it is absent here too,
			// bob's server never registered the re-invite as an Invite membership.
			_, fresh := slidingSync(t, bob, connID+"-fresh", "", 0)
			freshHasRoom := roomInList(fresh, roomID).Exists()

			// The reported symptom: poll the existing connection; the re-invited
			// room should appear in the list.
			var last gjson.Result
			for i := 0; i < 10; i++ {
				pos, last = slidingSync(t, bob, connID, pos, 0)
				if roomInList(last, roomID).Exists() {
					return
				}
				time.Sleep(300 * time.Millisecond)
			}

			if freshHasRoom {
				t.Fatalf("re-invited room %s never appeared on the incremental connection, "+
					"but IS present on a fresh connection: the incremental staleness gate is "+
					"dropping it. last incremental response: %s", roomID, last.Raw)
			}
			t.Fatalf("re-invited room %s appeared on neither the incremental nor a fresh "+
				"sliding-sync connection: bob's server did not register the re-invite as an "+
				"Invite membership. fresh response: %s", roomID, fresh.Raw)
		})
	}
}

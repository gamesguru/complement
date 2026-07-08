package msc4500

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"testing"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/match"
	"github.com/matrix-org/complement/must"
	"golang.org/x/crypto/blake2b"
)

// TestMSC4500StateAccumulator verifies that the state_accumulator endpoint
// returns a valid 2048-byte base64url encoded lattice and the matching BLAKE2b-256 digest.
func TestMSC4500StateAccumulator(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
	})

	token := alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(alice.UserID, roomID))

	// Get the last event ID from the sync
	res := alice.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"}, client.WithQueries(url.Values{
		"dir":   {"b"},
		"limit": {"1"},
		"from":  {token},
	}))
	body := must.ParseJSON(t, res.Body)
	eventID := body.Get("chunk.0.event_id").Str

	must.NotEqual(t, eventID, "", "Failed to find event ID")

	// Call the federation endpoint using alice's homeserver
	fedRes := deployment.UnauthenticatedClient(t, "hs1").MustDo(t, "GET", []string{"_matrix", "federation", "unstable", "tk.nutra.msc4500", "state_accumulator", roomID}, client.WithQueries(url.Values{
		"event_id": {eventID},
	}))

	fedBody := must.ParseJSON(t, fedRes.Body)

	must.MatchGJSON(t, fedBody, match.JSONKeyEqual("event_id", eventID))
	must.MatchGJSON(t, fedBody, match.JSONKeyEqual("algorithm", "lthash16"))

	latticeB64 := fedBody.Get("lattice").Str
	digestHex := fedBody.Get("digest").Str

	must.NotEqual(t, latticeB64, "", "Lattice is empty")
	must.Equal(t, len(digestHex), 64, "Digest is not 64 hex characters")

	// Verify the digest matches the lattice
	latticeBytes, err := base64.RawURLEncoding.DecodeString(latticeB64)
	must.NotError(t, "base64 decode", err)
	must.Equal(t, len(latticeBytes), 2048, "Lattice is not 2048 bytes")

	hash := blake2b.Sum256(latticeBytes)
	expectedDigestHex := hex.EncodeToString(hash[:])

	must.Equal(t, digestHex, expectedDigestHex, "Digest does not match BLAKE2b-256 of lattice")
}

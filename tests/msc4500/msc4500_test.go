package msc4500

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/match"
	"github.com/matrix-org/complement/must"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/blake2b"
)

// TestMSC4500StateAccumulator verifies that the state_accumulator endpoint
// returns a valid 2048-byte base64url encoded lattice and the matching BLAKE2b-256 digest.
func TestMSC4500StateAccumulator(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Client(t, "hs1", "")

	roomID := alice.CreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
	})

	_, token := alice.SyncUntil(t, "", "m.room.create", func(ev gjson.Result) bool {
		return ev.Get("room_id").Str == roomID
	})

	// Get the last event ID from the sync
	res := alice.MustDoFunc(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"}, client.WithQueries(map[string]string{
		"dir":   "b",
		"limit": "1",
		"from":  token,
	}))
	body := client.ParseJSON(t, res)
	eventID := body.Get("chunk.0.event_id").Str

	must.NotEqual(t, eventID, "", "Failed to find event ID")

	// Call the federation endpoint using alice's homeserver
	fedRes := deployment.UnauthenticatedClient(t, "hs1").MustDoFunc(t, "GET", []string{"_matrix", "federation", "unstable", "tk.nutra.msc4500", "state_accumulator", roomID}, client.WithQueries(map[string]string{
		"event_id": eventID,
	}))

	fedBody := client.ParseJSON(t, fedRes)

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

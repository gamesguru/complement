//go:build !dendrite_blacklist && !venator_blacklist

// Venator does not yet implement federation.

package edurecon

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/matrix-org/gomatrixserverlib/fclient"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
)

// TestMSC4521ActiveEDUReconciliation verifies the first real wire-level
// operation in the active EDU reconciliation path. A remote federation server
// queries the homeserver under test after
// a presence change and must receive the authoritative versioned snapshot.
//
// This is deliberately an integration test: the reconciliation library tests
// cannot prove that a homeserver stores, authorizes, scopes, and serves EDU
// state correctly.
func TestMSC4521ActiveEDUReconciliation(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	cancel := srv.Listen()
	defer cancel()

	roomID := alice.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
	charlie := srv.UserID("charlie")
	srv.MustJoinRoom(t, deployment, deployment.GetFullyQualifiedHomeserverName(t, "hs1"), roomID, charlie)

	statusMsg := "MSC0502 integration probe"
	alice.MustDo(t, "PUT", []string{"_matrix", "client", "v3", "presence", alice.UserID, "status"},
		client.WithJSONBody(t, map[string]interface{}{
			"presence":   "online",
			"status_msg": statusMsg,
		}),
	)

	path := "/_matrix/federation/unstable/org.matrix.msc0502/edu_digest?edu_type=m.presence&limit=100"
	req := fclient.NewFederationRequest(
		"GET",
		srv.ServerName(),
		deployment.GetFullyQualifiedHomeserverName(t, "hs1"),
		path,
	)
	res, err := srv.DoFederationRequest(context.Background(), t, deployment, req)
	must.NotError(t, "GET /edu_digest", err)
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	must.NotError(t, "read /edu_digest response", err)
	t.Logf("/edu_digest response: %s", body)
	must.Equal(t, res.StatusCode, 200, "MSC0502 /edu_digest status")

	var digest struct {
		EDUType string `json:"edu_type"`
		Users   map[string]struct {
			Version     int64  `json:"version"`
			ContentHash string `json:"content_hash"`
		} `json:"users"`
	}
	must.NotError(t, "decode /edu_digest response", json.Unmarshal(body, &digest))
	must.Equal(t, digest.EDUType, "m.presence", "edu type")
	entry, ok := digest.Users[alice.UserID]
	must.Equal(t, ok, true, "presence digest must include the shared-room user")
	must.Equal(t, entry.Version > 0, true, "presence version must advance")
	hash := entry.ContentHash
	must.Equal(t, len(hash), len("xxh3:0000000000000000"), "presence content hash format")
	must.Equal(t, hash[:5], "xxh3:", "presence content hash prefix")
}

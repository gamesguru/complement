package helpers

import (
	"fmt"
	"strings"

	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/ct"
)

// CreateConduwuitAdminRoom creates a DM with the conduwuit admin bot and returns the room ID.
func CreateConduwuitAdminRoom(t ct.TestLike, c *client.CSAPI) string {
	t.Helper()

	// Extract the server name from the client's UserID (e.g., "@alice:hs1" -> "hs1")
	parts := strings.Split(c.UserID, ":")
	if len(parts) < 2 {
		t.Fatalf("Invalid UserID for client: %s", c.UserID)
	}
	serverName := parts[1]

	// The default admin bot for conduwuit is @conduwuit:server.name
	adminBot := fmt.Sprintf("@conduwuit:%s", serverName)

	// Create a DM room with the admin bot
	return c.MustCreateRoom(t, map[string]interface{}{
		"invite":    []string{adminBot},
		"is_direct": true,
	})
}

// SendConduwuitAdminCommand sends the given command to the specified admin room.
// Example: helpers.SendConduwuitAdminCommand(t, alice, roomID, "server clear-caches")
func SendConduwuitAdminCommand(t ct.TestLike, c *client.CSAPI, roomID string, command string) {
	t.Helper()

	// Ensure the command starts with !admin
	if !strings.HasPrefix(command, "!admin ") {
		command = "!admin " + command
	}

	// Send the command
	c.SendEventSynced(t, roomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    command,
		},
	})

	t.Logf("Sent admin command '%s' via Admin Room %s", command, roomID)
}

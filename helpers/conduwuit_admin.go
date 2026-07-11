package helpers

import (
	"fmt"
	"strings"

	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/ct"
)

// SendConduwuitAdminCommand creates a DM with the conduwuit admin bot and sends the given command.
// Example: helpers.SendConduwuitAdminCommand(t, alice, "server clear-caches")
// Note: The client must be a registered user on the target conduwuit homeserver, typically the first registered user (admin).
// Returns the room ID of the created admin room.
func SendConduwuitAdminCommand(t ct.TestLike, c *client.CSAPI, command string) string {
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
	roomID := c.MustCreateRoom(t, map[string]interface{}{
		"invite":    []string{adminBot},
		"is_direct": true,
	})

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

	return roomID
}

package tests

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/runtime"
)

// TestAdminYoloCommandsUnderStress verifies that conduwuit can handle
// dangerous/heavy "yolo" admin commands concurrently with active user load
// without crashing or deadlocking.
func TestAdminYoloCommandsUnderStress(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)

	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	// Register Alice, who becomes the server admin (first user)
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	// Create a room that we can use for load generation and for the admin commands
	// that require a room ID argument.
	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var errorCount int32

	// --- Start background load generation ---
	// Launch multiple goroutines to spam messages into the room.
	numLoadWorkers := 5
	for i := 0; i < numLoadWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			msgCount := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					msgCount++
					body := fmt.Sprintf("Stress test message %d from worker %d", msgCount, workerID)
					alice.Unsafe_SendEventUnsynced(t, roomID, b.Event{
						Type: "m.room.message",
						Content: map[string]interface{}{
							"msgtype": "m.text",
							"body":    body,
						},
					})
					time.Sleep(10 * time.Millisecond) // Yield slightly so we don't totally saturate the Complement client
				}
			}
		}(i)
	}

	// --- Fire YOLO admin commands under load ---
	yoloCommands := []string{
		fmt.Sprintf("yolo reorder-timeline %s", roomID),
		fmt.Sprintf("yolo force-set-state %s hs1", roomID),
		fmt.Sprintf("yolo compare-room-state %s hs1", roomID),
		"yolo reindex-short",
		fmt.Sprintf("yolo get-room-dag %s", roomID),
		fmt.Sprintf("yolo get-remote-dag %s hs1", roomID),
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		// Wait a brief moment for load generation to start filling the room
		time.Sleep(500 * time.Millisecond)

		commandIndex := 0
		for {
			select {
			case <-ctx.Done():
				return
			default:
				cmd := yoloCommands[commandIndex%len(yoloCommands)]
				t.Logf("Firing YOLO admin command: !admin %s", cmd)

				// Use our new helper to send the command
				// SendConduwuitAdminCommand is blocking and waits for the event to be synced,
				// meaning it will backpressure if the server gets too slow.
				// We wrap in a recover block just in case the client panics on a timeout,
				// though complement typically calls t.Fatal.
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Logf("Panic during admin command %s: %v", cmd, r)
							atomic.AddInt32(&errorCount, 1)
						}
					}()
					helpers.SendConduwuitAdminCommand(t, alice, cmd)
				}()

				commandIndex++
				time.Sleep(200 * time.Millisecond) // Don't overwhelm the admin room with purely commands
			}
		}
	}()

	// Wait for the context timeout (10 seconds of stress testing)
	wg.Wait()

	if atomic.LoadInt32(&errorCount) > 0 {
		t.Fatalf("Test failed with %d errors during admin command execution", errorCount)
	}

	// --- Verify Server is still responsive ---
	t.Log("Stress period complete. Verifying server responsiveness...")

	// Create a final room to prove the server is fully functioning and hasn't deadlocked.
	finalRoomID := alice.MustCreateRoom(t, map[string]interface{}{})
	alice.SendEventSynced(t, finalRoomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "Server survived the yolo commands!",
		},
	})

	// Sync to confirm receipt
	alice.MustSync(t, client.SyncReq{})
	t.Log("Server successfully responded to post-stress verification.")
}

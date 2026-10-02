//go:build !dendrite_blacklist
// +build !dendrite_blacklist

package tests

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/match"
	"github.com/matrix-org/complement/must"
	"github.com/matrix-org/complement/runtime"
	"github.com/matrix-org/complement/should"
)

const hsName = "hs1"
const eventType = "com.example.test"

type DelayedEventAction string

const (
	DelayedEventActionCancel  = "cancel"
	DelayedEventActionRestart = "restart"
	DelayedEventActionSend    = "send"
)

// TODO: Test pagination of `GET /_matrix/client/v1/delayed_events` once
// it is implemented in a homeserver.

func TestDelayedEvents(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	user := deployment.Register(t, hsName, helpers.RegistrationOpts{})
	user2 := deployment.Register(t, hsName, helpers.RegistrationOpts{})
	unauthedClient := deployment.UnauthenticatedClient(t, hsName)

	roomID := user.MustCreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
		"power_level_content_override": map[string]interface{}{
			"events": map[string]int{
				eventType: 0,
			},
		},
	})
	user2.MustJoinRoom(t, roomID, nil)

	t.Run("delayed events are empty on startup", func(t *testing.T) {
		matchDelayedEvents(t, user, delayedEventsNumberEqual(0))
	})

	t.Run("delayed event lookups are authenticated", func(t *testing.T) {
		res := unauthedClient.Do(t, "GET", getPathForDelayedEvents())
		must.MatchResponse(t, res, match.HTTPResponse{
			StatusCode: 401,
		})
	})

	// FIXME: Too much mixing of tests that should be more independent
	t.Run("delayed message events are sent on timeout", func(t *testing.T) {
		var res *http.Response
		var countExpected uint64

		_, token := user.MustSync(t, client.SyncReq{})

		defer cleanupDelayedEvents(t, user)

		txnIdBase := "txn-delayed-msg-timeout-%d"

		countKey := "count"
		numEvents := 3
		for i, delayStr := range []string{"700", "800", "900"} {
			res = user.MustDo(
				t,
				"PUT",
				getPathForSend(roomID, eventType, fmt.Sprintf(txnIdBase, i)),
				client.WithJSONBody(t, map[string]interface{}{
					countKey: i + 1,
				}),
				getDelayQueryParam(delayStr),
			)
			delayID := client.GetJSONFieldStr(t, client.ParseJSON(t, res), "delay_id")

			t.Run("rerequesting delayed event path with the same txnID should have the same response", func(t *testing.T) {
				res := user.MustDo(
					t,
					"PUT",
					getPathForSend(roomID, eventType, fmt.Sprintf(txnIdBase, i)),
					getDelayQueryParam(delayStr),
				)
				must.MatchResponse(t, res, match.HTTPResponse{
					JSON: []match.JSON{
						match.JSONKeyEqual("delay_id", delayID),
					},
				})
			})
		}

		countExpected = 0
		matchDelayedEvents(t, user, delayedEventsNumberEqual(numEvents))

		t.Run("cannot get delayed events of another user", func(t *testing.T) {
			matchDelayedEvents(t, user2, delayedEventsNumberEqual(0))
		})

		// Poll until all three delayed messages have been sent (the longest of
		// the 700/800/900ms delays is 900ms) rather than sleeping a flat second
		// and then hoping the queue has drained.
		matchDelayedEventsWithin(t, user, 15*time.Second, delayedEventsNumberEqual(0))
		queryParams := url.Values{}
		queryParams.Set("dir", "f")
		queryParams.Set("from", token)
		res = user.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"}, client.WithQueries(queryParams))
		countExpected = 0
		must.MatchResponse(t, res, match.HTTPResponse{
			JSON: []match.JSON{
				match.JSONArrayEach("chunk", func(val gjson.Result) error {
					content := val.Get("content").Map()
					if l := len(content); l != 1 {
						return fmt.Errorf("wrong number of content fields: expected 1, got %d", l)
					}
					countExpected++
					if countActual := content[countKey].Uint(); countActual != countExpected {
						return fmt.Errorf("wrong count in delayed event content: expected %v, got %v", countExpected, countActual)
					}
					return nil
				}),
			},
		})
	})

	t.Run("delayed state events are sent on timeout", func(t *testing.T) {
		var res *http.Response

		defer cleanupDelayedEvents(t, user)

		stateKey := "to_send_on_timeout"

		// Schedule a delayed event
		setterKey := "setter"
		setterExpected := "on_timeout"
		user.MustDo(
			t,
			"PUT",
			getPathForState(roomID, eventType, stateKey),
			client.WithJSONBody(t, map[string]interface{}{
				setterKey: setterExpected,
			}),
			getDelayQueryParam("900"),
		)

		// Ensure that a delayed event is now scheduled
		matchDelayedEvents(t, user, delayedEventsNumberEqual(1))
		// And includes the correct content
		//
		// FIXME: This assertion seems superfluous to this test and should be it's own test
		res = getDelayedEvents(t, user)
		must.MatchResponse(t, res, match.HTTPResponse{
			JSON: []match.JSON{
				match.JSONArrayEach("delayed_events", func(val gjson.Result) error {
					content := val.Get("content").Map()
					if l := len(content); l != 1 {
						return fmt.Errorf("wrong number of content fields: expected 1, got %d", l)
					}
					if setterActual := content[setterKey].Str; setterActual != setterExpected {
						return fmt.Errorf("wrong setter in delayed event content: expected %v, got %v", setterExpected, setterActual)
					}
					return nil
				}),
			},
		})

		// Sanity check that the room state hasn't changed yet
		res = user.Do(t, "GET", getPathForState(roomID, eventType, stateKey))
		must.MatchResponse(t, res, match.HTTPResponse{
			StatusCode: 404,
		})

		// No wait needed here: MustSyncUntil below polls until the delayed state
		// event shows up, so the scheduled delay is the natural lower bound and
		// the test proceeds the moment the event actually lands.

		// Check for the state change from the delayed state event (using `MustSyncUntil` to
		// account for any processing or worker replication delays)
		user.MustSyncUntil(t, client.SyncReq{UseStateAfter: true}, client.SyncStateAfterHas(roomID, func(ev gjson.Result) bool {
			return ev.Get("type").Str == eventType && ev.Get("state_key").Str == stateKey
		}))
		// Make sure the state looks as expected after
		res = user.MustDo(t, "GET", getPathForState(roomID, eventType, stateKey))
		must.MatchResponse(t, res, match.HTTPResponse{
			JSON: []match.JSON{
				match.JSONKeyEqual(setterKey, setterExpected),
			},
		})
		// No more delayed events
		matchDelayedEvents(t, user, delayedEventsNumberEqual(0))
	})

	t.Run("cannot update a delayed event without an action", func(t *testing.T) {
		res := unauthedClient.Do(
			t,
			"POST",
			append(getPathForDelayedEvents(), "abc"),
			client.WithJSONBody(t, map[string]interface{}{}),
		)
		// TODO: specify failure as 404 when/if Synapse removes the action-in-body version of this endpoint
		must.MatchFailure(t, res)
	})

	t.Run("cannot update a delayed event with an invalid action", func(t *testing.T) {
		res := unauthedClient.Do(
			t,
			"POST",
			append(getPathForDelayedEvents(), "abc", "oops"),
			client.WithJSONBody(t, map[string]interface{}{}),
		)
		must.MatchResponse(t, res, match.HTTPResponse{
			StatusCode: 404,
		})
	})

	t.Run("parallel", func(t *testing.T) {
		for _, action := range []DelayedEventAction{
			DelayedEventActionCancel,
			DelayedEventActionRestart,
			DelayedEventActionSend,
		} {
			t.Run(fmt.Sprintf("cannot %s a delayed event without a matching delay ID", action), func(t *testing.T) {
				t.Parallel()
				res := unauthedClient.Do(
					t,
					"POST",
					getPathForUpdateDelayedEvent("abc", action),
					client.WithJSONBody(t, map[string]interface{}{}),
				)
				must.MatchResponse(t, res, match.HTTPResponse{
					StatusCode: 404,
				})
			})
		}
	})

	t.Run("delayed state events can be cancelled", func(t *testing.T) {
		var res *http.Response

		stateKey := "to_never_send"

		// The delay this subtest schedules with, plus the moment it was
		// scheduled, so the later waits can target the real deadline instead of
		// a rounded-up constant.
		const delay = 1500 * time.Millisecond
		var scheduledAt time.Time

		// Schedule a delayed event
		setterKey := "setter"
		setterExpected := "none"
		scheduledAt = time.Now()
		res = user.MustDo(
			t,
			"PUT",
			getPathForState(roomID, eventType, stateKey),
			client.WithJSONBody(t, map[string]interface{}{
				setterKey: setterExpected,
			}),
			getDelayQueryParam(fmt.Sprintf("%d", delay.Milliseconds())),
		)
		delayID := client.GetJSONFieldStr(t, client.ParseJSON(t, res), "delay_id")

		// Wait until just before the delayed event's deadline, but not past it: the
		// event must provably still be scheduled right up until we cancel it, and
		// waiting to the last moment is both a stronger check and cheaper than the
		// rounded-up second this used to sleep (the past-deadline wait below is
		// what actually has to cover the full delay).
		awaitDelayedEventDue(t, scheduledAt, delay-100*time.Millisecond)
		// We should still see the scheduled delayed event (hasn't been sent yet)
		matchDelayedEvents(t, user, delayedEventsNumberEqual(1))

		// Sanity check that the room state hasn't changed
		res = user.Do(t, "GET", getPathForState(roomID, eventType, stateKey))
		must.MatchResponse(t, res, match.HTTPResponse{
			StatusCode: 404,
		})

		// Cancel the delayed event
		unauthedClient.MustDo(
			t,
			"POST",
			getPathForUpdateDelayedEvent(delayID, DelayedEventActionCancel),
			client.WithJSONBody(t, map[string]interface{}{}),
		)
		// No more delayed events
		matchDelayedEvents(t, user, delayedEventsNumberEqual(0))

		// Sanity check that the previously scheduled delayed event doesn't end up being sent anyway
		//
		// Wait until the original deadline has actually passed. Counting "we slept
		// for a second twice" was wrong: the requests in between consume part of
		// that budget, so the check could run before the event was ever due.
		awaitDelayedEventDue(t, scheduledAt, delay)
		// Sanity check that the room state hasn't changed
		res = user.Do(t, "GET", getPathForState(roomID, eventType, stateKey))
		must.MatchResponse(t, res, match.HTTPResponse{
			StatusCode: 404,
		})
	})

	t.Run("delayed state events can be sent on request", func(t *testing.T) {
		var res *http.Response

		defer cleanupDelayedEvents(t, user)

		stateKey := "to_send_on_request"

		// Schedule a delayed event
		setterKey := "setter"
		setterExpected := "on_send"
		res = user.MustDo(
			t,
			"PUT",
			getPathForState(roomID, eventType, stateKey),
			client.WithJSONBody(t, map[string]interface{}{
				setterKey: setterExpected,
			}),
			getDelayQueryParam("100000"),
		)
		delayID := client.GetJSONFieldStr(t, client.ParseJSON(t, res), "delay_id")

		// Wait a bit but not long enough for the delayed state event to be sent
		time.Sleep(1 * time.Second)
		// We should still see the scheduled delayed event (hasn't been sent yet)
		matchDelayedEvents(t, user, delayedEventsNumberEqual(1))

		// Sanity check that the room state hasn't changed yet
		res = user.Do(t, "GET", getPathForState(roomID, eventType, stateKey))
		must.MatchResponse(t, res, match.HTTPResponse{
			StatusCode: 404,
		})

		// Force the delayed event to be sent immediately
		unauthedClient.MustDo(
			t,
			"POST",
			getPathForUpdateDelayedEvent(delayID, DelayedEventActionSend),
			client.WithJSONBody(t, map[string]interface{}{}),
		)

		// Check for the state change from the delayed state event (using `MustSyncUntil` to
		// account for any processing or worker replication delays)
		user.MustSyncUntil(t, client.SyncReq{UseStateAfter: true}, client.SyncStateAfterHas(roomID, func(ev gjson.Result) bool {
			return ev.Get("type").Str == eventType && ev.Get("state_key").Str == stateKey
		}))
		// Make sure the state looks as expected after
		res = user.MustDo(t, "GET", getPathForState(roomID, eventType, stateKey))
		must.MatchResponse(t, res, match.HTTPResponse{
			JSON: []match.JSON{
				match.JSONKeyEqual(setterKey, setterExpected),
			},
		})
		// No more delayed events
		matchDelayedEvents(t, user, delayedEventsNumberEqual(0))
	})

	t.Run("delayed state events can be restarted", func(t *testing.T) {
		var res *http.Response

		stateKey := "to_send_on_restarted_timeout"

		defer cleanupDelayedEvents(t, user)

		// Schedule a delayed event
		setterKey := "setter"
		setterExpected := "on_timeout"
		res = user.MustDo(
			t,
			"PUT",
			getPathForState(roomID, eventType, stateKey),
			client.WithJSONBody(t, map[string]interface{}{
				setterKey: setterExpected,
			}),
			getDelayQueryParam("1500"),
		)
		delayID := client.GetJSONFieldStr(t, client.ParseJSON(t, res), "delay_id")

		// Wait a bit but not long enough for the delayed state event to be sent
		time.Sleep(1 * time.Second)
		// We should still see the scheduled delayed event (hasn't been sent yet)
		matchDelayedEvents(t, user, delayedEventsNumberEqual(1))

		// Sanity check that the room state hasn't changed yet
		res = user.Do(t, "GET", getPathForState(roomID, eventType, stateKey))
		must.MatchResponse(t, res, match.HTTPResponse{
			StatusCode: 404,
		})

		// Restart the timer on the delayed event
		unauthedClient.MustDo(
			t,
			"POST",
			getPathForUpdateDelayedEvent(delayID, DelayedEventActionRestart),
			client.WithJSONBody(t, map[string]interface{}{}),
		)

		// Wait a bit but not long enough for the delayed state event to be sent
		time.Sleep(1 * time.Second)
		// We should still see the scheduled delayed event (hasn't been sent yet)
		matchDelayedEvents(t, user, delayedEventsNumberEqual(1))

		// Sanity check that the room state hasn't changed yet
		res = user.Do(t, "GET", getPathForState(roomID, eventType, stateKey))
		must.MatchResponse(t, res, match.HTTPResponse{
			StatusCode: 404,
		})

		// No wait needed here: MustSyncUntil below polls until the delayed state
		// event shows up, so the scheduled delay is the natural lower bound and
		// the test proceeds the moment the event actually lands.

		// Check for the state change from the delayed state event (using `MustSyncUntil` to
		// account for any processing or worker replication delays)
		user.MustSyncUntil(t, client.SyncReq{UseStateAfter: true}, client.SyncStateAfterHas(roomID, func(ev gjson.Result) bool {
			return ev.Get("type").Str == eventType && ev.Get("state_key").Str == stateKey
		}))
		// Make sure the state looks as expected after
		res = user.MustDo(t, "GET", getPathForState(roomID, eventType, stateKey))
		must.MatchResponse(t, res, match.HTTPResponse{
			JSON: []match.JSON{
				match.JSONKeyEqual(setterKey, setterExpected),
			},
		})
		// No more delayed events
		matchDelayedEvents(t, user, delayedEventsNumberEqual(0))
	})

	t.Run("delayed state events are kept on server restart", func(t *testing.T) {
		// Spec cannot enforce server restart behaviour
		runtime.SkipIf(t, runtime.Dendrite)

		defer cleanupDelayedEvents(t, user)

		stateKey1 := "1"
		stateKey2 := "2"

		numberOfDelayedEvents := 0

		// Send an initial delayed event that will be ready to send as soon as the server
		// comes back up.
		const firstEventDelay = 900 * time.Millisecond
		firstEventScheduledAt := time.Now()
		user.MustDo(
			t,
			"PUT",
			getPathForState(roomID, eventType, stateKey1),
			client.WithJSONBody(t, map[string]interface{}{}),
			getDelayQueryParam(fmt.Sprintf("%d", firstEventDelay.Milliseconds())),
		)
		numberOfDelayedEvents++

		// Previously, this was naively using a single delayed event with a 10 second delay.
		// But because we're stopping and starting servers here, it could take up to
		// `deployment.GetConfig().SpawnHSTimeout` (defaults to 30 seconds) for the server
		// to start up again so by the time the server is back up, the delayed event may
		// have already been sent invalidating our assertions below (which expect some
		// delayed events to still be pending and then see one of them be sent after the
		// server is back up).
		//
		// We could account for this by setting the delayed event delay to be longer than
		// `deployment.GetConfig().SpawnHSTimeout` but that would make the test suite take
		// longer to run in all cases even for homeservers that are quick to restart because
		// we have to wait for that large delay.
		//
		// We instead account for this by scheduling many delayed events at short intervals
		// (we chose 10 seconds because that's what the test naively chose before). Then
		// whenever the servers comes back, we can just check until it decrements by 1.
		//
		// We add 1 to the number of intervals to ensure that we have at least one interval
		// to check against no matter how things are configured.
		numberOf10SecondIntervals := int(math.Ceil(deployment.GetConfig().SpawnHSTimeout.Seconds()/10)) + 1
		for i := 0; i < numberOf10SecondIntervals; i++ {
			// +1 as we want to start at 10 seconds and so we don't end up with -100ms delay
			// on the first one.
			delay := time.Duration(i+1)*10*time.Second - 100*time.Millisecond

			user.MustDo(
				t,
				"PUT",
				// Avoid clashing state keys as that would cancel previous delayed events on the
				// same key (start at 2).
				getPathForState(roomID, eventType, fmt.Sprintf("%d", i+2)),
				client.WithJSONBody(t, map[string]interface{}{}),
				getDelayQueryParam(fmt.Sprintf("%d", delay.Milliseconds())),
			)
			numberOfDelayedEvents++
		}
		// We expect all of the delayed events to be scheduled and not sent yet.
		matchDelayedEvents(t, user, delayedEventsNumberEqual(numberOfDelayedEvents))

		// Restart the server and wait until it's back up.
		deployment.StopServer(t, hsName)
		// Hold the server down until the first delayed event is actually due, so
		// it is ready to send the moment the server comes back. Waiting for the
		// real deadline means a StopServer call which already took longer than
		// the delay costs nothing instead of adding a second on top of it.
		awaitDelayedEventDue(t, firstEventScheduledAt, firstEventDelay)
		deployment.StartServer(t, hsName)

		// We should still see some delayed events left after the restart, and we
		// should see at least one fewer than before it (the first delayed event
		// should have been sent). Other delayed events may have been sent by the
		// time the server actually came back up. Poll until that happens rather
		// than sleeping a flat ten seconds first: if the restart already pushed
		// past several deadlines this returns immediately.
		delayedEventResponse := matchDelayedEventsWithin(t, user, 60*time.Second,
			delayedEventsNumberGreaterThan(0),
			delayedEventsNumberLessThan(numberOfDelayedEvents-1),
		)
		// Capture whatever number of delayed events are remaining after the server restart.
		remainingDelayedEventCount := countDelayedEvents(t, delayedEventResponse)
		// Sanity check that the room state was updated correctly with the delayed events
		// that were sent. (using `MustSyncUntil` to account for any processing or worker
		// replication delays)
		user.MustSyncUntil(t, client.SyncReq{UseStateAfter: true}, client.SyncStateAfterHas(roomID, func(ev gjson.Result) bool {
			return ev.Get("type").Str == eventType && ev.Get("state_key").Str == stateKey1
		}))

		// Wait until we see another delayed event being sent (ensure things resumed and
		// are continuing). Poll for it rather than sleeping ten seconds first: the next
		// event is due on a 10s cadence, but if that deadline already passed while the
		// server was down it fires as soon as it is back up.
		matchDelayedEventsWithin(t, user, 60*time.Second,
			delayedEventsNumberLessThan(remainingDelayedEventCount),
		)
		// Sanity check that the other delayed events also updated the room state correctly.
		// (using `MustSyncUntil` to account for any processing or worker replication
		// delays)
		//
		// FIXME: Ideally, we'd check specifically for the last one that was sent but it
		// will be a bit of a juggle and fiddly to get this right so for now we just check
		// one.
		user.MustSyncUntil(t, client.SyncReq{UseStateAfter: true}, client.SyncStateAfterHas(roomID, func(ev gjson.Result) bool {
			return ev.Get("type").Str == eventType && ev.Get("state_key").Str == stateKey2
		}))
	})
}

func getPathForDelayedEvents() []string {
	return []string{"_matrix", "client", "unstable", "org.matrix.msc4140", "delayed_events"}
}

func getPathForUpdateDelayedEvent(delayId string, action DelayedEventAction) []string {
	return append(getPathForDelayedEvents(), delayId, string(action))
}

func getPathForSend(roomID string, eventType string, txnId string) []string {
	return []string{"_matrix", "client", "v3", "rooms", roomID, "send", eventType, txnId}
}

func getPathForState(roomID string, eventType string, stateKey string) []string {
	return []string{"_matrix", "client", "v3", "rooms", roomID, "state", eventType, stateKey}
}

func getDelayQueryParam(delayStr string) client.RequestOpt {
	return client.WithQueries(url.Values{
		"org.matrix.msc4140.delay": []string{delayStr},
	})
}

// awaitDelayedEventDue blocks until the moment a delayed event scheduled at
// `scheduledAt` with the given delay was due. It replaces sleeps which assumed
// "some requests happened plus one more second": those silently ignore the time
// spent on the requests in between, and overshoot when the deadline has already
// passed (for example because StopServer took longer than the delay).
func awaitDelayedEventDue(t *testing.T, scheduledAt time.Time, delay time.Duration) {
	t.Helper()
	helpers.PollUntilf(t, delay+30*time.Second, helpers.DefaultPollInterval, func() bool {
		return !time.Now().Before(scheduledAt.Add(delay))
	}, "delayed event scheduled at %s with delay %s never came due", scheduledAt, delay)
}

func getDelayedEvents(t *testing.T, user *client.CSAPI) *http.Response {
	t.Helper()
	return user.MustDo(t, "GET", getPathForDelayedEvents())
}

// countDelayedEvents counts the number of delayed events in the response. Assumes the
// response is well-formed.
func countDelayedEventsInternal(res *http.Response) (int, error) {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, fmt.Errorf("countDelayedEventsInternal: Failed to read response body: %s", err)
	}

	parsedBody := gjson.ParseBytes(body)
	return len(parsedBody.Get("delayed_events").Array()), nil
}

func countDelayedEvents(t *testing.T, res *http.Response) int {
	t.Helper()
	count, err := countDelayedEventsInternal(res)
	if err != nil {
		t.Fatalf("countDelayedEvents: %s", err)
	}
	return count
}

type delayedEventsCheckOpt func(res *http.Response) error

// delayedEventsNumberEqual returns a check option that checks if the number of delayed events
// is equal to the given number.
func delayedEventsNumberEqual(wantNumber int) delayedEventsCheckOpt {
	return func(res *http.Response) error {
		_, err := should.MatchResponse(res, match.HTTPResponse{
			StatusCode: 200,
			JSON: []match.JSON{
				match.JSONKeyArrayOfSize("delayed_events", wantNumber),
			},
		})
		if err == nil {
			return nil
		}
		return fmt.Errorf("delayedEventsNumberEqual(%d): %s", wantNumber, err)
	}
}

// delayedEventsNumberLessThan returns a check option that checks if the number of delayed events
// is greater than the given number.
func delayedEventsNumberGreaterThan(target int) delayedEventsCheckOpt {
	return func(res *http.Response) error {
		count, err := countDelayedEventsInternal(res)
		if err != nil {
			return fmt.Errorf("delayedEventsNumberGreaterThan(%d): %s", target, err)
		}
		if count > target {
			return nil
		}
		return fmt.Errorf("delayedEventsNumberGreaterThan(%d): got %d", target, count)
	}
}

// delayedEventsNumberLessThan returns a check option that checks if the number of delayed events
// is less than the given number.
func delayedEventsNumberLessThan(target int) delayedEventsCheckOpt {
	return func(res *http.Response) error {
		count, err := countDelayedEventsInternal(res)
		if err != nil {
			return fmt.Errorf("delayedEventsNumberLessThan(%d): %s", target, err)
		}
		if count < target {
			return nil
		}
		return fmt.Errorf("delayedEventsNumberLessThan(%d): got %d", target, count)
	}
}

// matchDelayedEvents will run the given checks on the delayed events response. This will
// retry to handle replication lag.
func matchDelayedEvents(t *testing.T, user *client.CSAPI, checks ...delayedEventsCheckOpt) *http.Response {
	t.Helper()
	return matchDelayedEventsWithin(t, user, 500*time.Millisecond, checks...)
}

// matchDelayedEventsWithin is matchDelayedEvents with a caller-chosen retry
// budget. Prefer it over "sleep a fixed duration, then check once": it returns
// the instant the condition holds instead of always paying the sleep first, and
// it keeps polling for as long as the caller says the condition is allowed to
// take, so a slow homeserver is waited for rather than raced against.
func matchDelayedEventsWithin(t *testing.T, user *client.CSAPI, timeout time.Duration, checks ...delayedEventsCheckOpt) *http.Response {
	t.Helper()

	// We need to retry this as replication can sometimes lag.
	return user.MustDo(t, "GET", getPathForDelayedEvents(),
		client.WithRetryUntil(
			timeout,
			func(res *http.Response) bool {
				for _, check := range checks {
					err := check(res)

					if err != nil {
						t.Log(err)
						return false
					}
				}
				return true
			},
		),
	)
}

// FIXME: Instead of using `cleanupDelayedEvents`, each test should just use their own
// room
func cleanupDelayedEvents(t *testing.T, user *client.CSAPI) {
	t.Helper()
	res := getDelayedEvents(t, user)
	defer res.Body.Close()
	body := must.ParseJSON(t, res.Body)
	for _, delayedEvent := range body.Get("delayed_events").Array() {
		delayID := delayedEvent.Get("delay_id").String()
		user.MustDo(
			t,
			"POST",
			getPathForUpdateDelayedEvent(delayID, DelayedEventActionCancel),
			client.WithJSONBody(t, map[string]interface{}{}),
		)
	}

	matchDelayedEvents(t, user, delayedEventsNumberEqual(0))
}

package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"testing"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/match"
	"github.com/matrix-org/complement/must"
	"github.com/tidwall/gjson"
)

const maxSafeJSONInteger = 1<<53 - 1

type slidingSyncEndpoint struct {
	name   string
	paths  []string
	legacy bool
}

var (
	slidingSyncEndpointCandidates = []slidingSyncEndpoint{
		{
			name:  "v4",
			paths: []string{"_matrix", "client", "v4", "sync"},
		},
		{
			name:  "v5",
			paths: []string{"_matrix", "client", "v5", "sync"},
		},
		{
			name:   "unstable-org.matrix.simplified_msc3575",
			paths:  []string{"_matrix", "client", "unstable", "org.matrix.simplified_msc3575", "sync"},
			legacy: true,
		},
	}
	slidingSyncEndpointCacheMu sync.Mutex
	slidingSyncEndpointCache   = map[string]slidingSyncEndpoint{}
)

type slidingSyncReq struct {
	ConnID            string
	Pos               string
	Lists             map[string]interface{}
	RoomSubscriptions map[string]interface{}
}

func mustDoSlidingSync(t *testing.T, user *client.CSAPI, req slidingSyncReq) (string, gjson.Result) {
	t.Helper()

	endpoints := slidingSyncEndpointCandidates
	slidingSyncEndpointCacheMu.Lock()
	if cachedEndpoint, ok := slidingSyncEndpointCache[user.BaseURL]; ok {
		endpoints = []slidingSyncEndpoint{cachedEndpoint}
	}
	slidingSyncEndpointCacheMu.Unlock()

	var failures []string
	for _, endpoint := range endpoints {
		pos, body, ok, failure := tryDoSlidingSync(t, user, req, endpoint)
		if ok {
			slidingSyncEndpointCacheMu.Lock()
			slidingSyncEndpointCache[user.BaseURL] = endpoint
			slidingSyncEndpointCacheMu.Unlock()
			return pos, body
		}
		failures = append(failures, failure)
	}

	t.Fatalf("no supported sliding sync endpoint found for %s: %v", user.BaseURL, failures)
	panic("unreachable")
}

func tryDoSlidingSync(t *testing.T, user *client.CSAPI, req slidingSyncReq, endpoint slidingSyncEndpoint) (string, gjson.Result, bool, string) {
	t.Helper()

	requestBody := slidingSyncRequestBody(req)
	requestOpts := []client.RequestOpt{client.WithJSONBody(t, requestBody)}
	if endpoint.legacy {
		requestBody = legacySlidingSyncRequestBody(requestBody)
		query := url.Values{}
		if req.Pos != "" {
			query.Set("pos", req.Pos)
			query.Set("timeout", "0")
		}
		requestOpts = []client.RequestOpt{client.WithJSONBody(t, requestBody), client.WithQueries(query)}
	}

	resp := user.Do(t, "POST", endpoint.paths, requestOpts...)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read sliding sync response body from %s: %s", endpoint.name, err)
	}

	if resp.StatusCode == http.StatusNotFound || gjson.GetBytes(respBody, "errcode").Str == "M_UNRECOGNIZED" {
		return "", gjson.Result{}, false, fmt.Sprintf("%s returned %s: %s", endpoint.name, resp.Status, string(respBody))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("sliding sync endpoint %s returned non-2xx code: %s - body: %s", endpoint.name, resp.Status, string(respBody))
	}

	jsonBody := gjson.ParseBytes(respBody)
	if endpoint.legacy {
		jsonBody = normalizeLegacySlidingSyncResponse(t, jsonBody)
	}
	pos := jsonBody.Get("pos").Str
	if pos == "" {
		t.Fatalf("sliding sync endpoint %s response missing pos: %s", endpoint.name, jsonBody.Raw)
	}
	return pos, jsonBody, true, ""
}

func slidingSyncRequestBody(req slidingSyncReq) map[string]interface{} {
	body := map[string]interface{}{}
	if req.ConnID != "" {
		body["conn_id"] = req.ConnID
	}
	if req.Pos != "" {
		body["pos"] = req.Pos
		body["timeout"] = 0
	}
	if req.Lists != nil {
		body["lists"] = req.Lists
	}
	if req.RoomSubscriptions != nil {
		body["room_subscriptions"] = req.RoomSubscriptions
	}

	return body
}

func legacySlidingSyncRequestBody(body map[string]interface{}) map[string]interface{} {
	legacyBody := map[string]interface{}{}
	if connID, ok := body["conn_id"]; ok {
		legacyBody["conn_id"] = connID
	}
	if lists, ok := body["lists"].(map[string]interface{}); ok {
		legacyLists := map[string]interface{}{}
		for listKey, listConfig := range lists {
			legacyLists[listKey] = legacySlidingSyncListConfig(listConfig, true)
		}
		legacyBody["lists"] = legacyLists
	}
	if roomSubscriptions, ok := body["room_subscriptions"].(map[string]interface{}); ok {
		legacyRoomSubscriptions := map[string]interface{}{}
		for roomID, roomConfig := range roomSubscriptions {
			legacyRoomSubscriptions[roomID] = legacySlidingSyncListConfig(roomConfig, false)
		}
		legacyBody["room_subscriptions"] = legacyRoomSubscriptions
	}
	if extensions, ok := body["extensions"]; ok {
		legacyBody["extensions"] = extensions
	}
	return legacyBody
}

func legacySlidingSyncListConfig(config interface{}, includeRanges bool) map[string]interface{} {
	configMap, _ := config.(map[string]interface{})
	legacyConfig := map[string]interface{}{}
	if timelineLimit, ok := configMap["timeline_limit"]; ok {
		legacyConfig["timeline_limit"] = timelineLimit
	}
	if requiredState, ok := configMap["required_state"].(map[string]interface{}); ok {
		legacyConfig["required_state"] = legacyRequiredState(requiredState)
	}
	if filters, ok := configMap["filters"]; ok {
		legacyConfig["filters"] = filters
	}
	if includeRanges {
		if rangeValue, ok := configMap["range"]; ok {
			legacyConfig["ranges"] = []interface{}{rangeValue}
		}
	}
	return legacyConfig
}

func legacyRequiredState(requiredState map[string]interface{}) [][]string {
	legacyState := [][]string{}
	if include, ok := requiredState["include"].([]map[string]interface{}); ok {
		for _, state := range include {
			legacyState = append(legacyState, legacyRequiredStateElement(state))
		}
	} else if include, ok := requiredState["include"].([]interface{}); ok {
		for _, rawState := range include {
			state, _ := rawState.(map[string]interface{})
			legacyState = append(legacyState, legacyRequiredStateElement(state))
		}
	}
	if lazyMembers, _ := requiredState["lazy_members"].(bool); lazyMembers {
		legacyState = append(legacyState, []string{"m.room.member", "$LAZY"})
	}
	return legacyState
}

func legacyRequiredStateElement(state map[string]interface{}) []string {
	eventType := "*"
	stateKey := "*"
	if value, ok := state["type"].(string); ok {
		eventType = value
	}
	if value, ok := state["state_key"].(string); ok {
		stateKey = value
	}
	return []string{eventType, stateKey}
}

func normalizeLegacySlidingSyncResponse(t *testing.T, res gjson.Result) gjson.Result {
	t.Helper()

	var normalized map[string]interface{}
	if err := json.Unmarshal([]byte(res.Raw), &normalized); err != nil {
		t.Fatalf("failed to parse legacy sliding sync response: %s", err)
	}

	roomLists := map[string]map[string]struct{}{}
	if lists, ok := normalized["lists"].(map[string]interface{}); ok {
		for listKey, rawList := range lists {
			list, _ := rawList.(map[string]interface{})
			ops, _ := list["ops"].([]interface{})
			for _, rawOp := range ops {
				op, _ := rawOp.(map[string]interface{})
				roomIDs, _ := op["room_ids"].([]interface{})
				for _, rawRoomID := range roomIDs {
					roomID, _ := rawRoomID.(string)
					if roomID == "" {
						continue
					}
					if _, ok := roomLists[roomID]; !ok {
						roomLists[roomID] = map[string]struct{}{}
					}
					roomLists[roomID][listKey] = struct{}{}
				}
			}
		}
	}

	if rooms, ok := normalized["rooms"].(map[string]interface{}); ok {
		for roomID, rawRoom := range rooms {
			room, _ := rawRoom.(map[string]interface{})
			if timeline, ok := room["timeline"]; ok {
				room["timeline_events"] = timeline
				delete(room, "timeline")
			}
			if expandedTimeline, ok := room["unstable_expanded_timeline"]; ok {
				room["expanded_timeline"] = expandedTimeline
				delete(room, "unstable_expanded_timeline")
			}
			if inviteState, ok := room["invite_state"]; ok {
				room["stripped_state"] = inviteState
				delete(room, "invite_state")
			}
			if lists, ok := roomLists[roomID]; ok {
				room["lists"] = sortedMapKeys(lists)
			} else {
				room["lists"] = []string{}
			}
		}
	}

	normalizedBytes, err := json.Marshal(normalized)
	if err != nil {
		t.Fatalf("failed to encode normalized legacy sliding sync response: %s", err)
	}
	return gjson.ParseBytes(normalizedBytes)
}

func sortedMapKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func slidingList(timelineLimit int, from int, to int) map[string]interface{} {
	return slidingListWithRequiredState(timelineLimit, from, to, map[string]interface{}{
		"include": []map[string]interface{}{},
	})
}

func slidingListWithRequiredState(timelineLimit int, from int, to int, requiredState map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"timeline_limit": timelineLimit,
		"required_state": requiredState,
		"range":          []int{from, to},
	}
}

func slidingSubscription(timelineLimit int) map[string]interface{} {
	return map[string]interface{}{
		"timeline_limit": timelineLimit,
		"required_state": map[string]interface{}{
			"include": []map[string]interface{}{},
		},
	}
}

func allRoomsList(timelineLimit int, from int, to int) map[string]interface{} {
	return map[string]interface{}{
		"all": slidingList(timelineLimit, from, to),
	}
}

func roomResult(res gjson.Result, roomID string) gjson.Result {
	return res.Get("rooms." + gjson.Escape(roomID))
}

func requireRoom(t *testing.T, res gjson.Result, roomID string) gjson.Result {
	t.Helper()
	room := roomResult(res, roomID)
	if !room.Exists() {
		t.Fatalf("expected room %s in sliding sync response: %s", roomID, res.Raw)
	}
	return room
}

func requireNoRoom(t *testing.T, res gjson.Result, roomID string) {
	t.Helper()
	if roomResult(res, roomID).Exists() {
		t.Fatalf("did not expect room %s in sliding sync response: %s", roomID, res.Raw)
	}
}

func sendMessage(t *testing.T, user *client.CSAPI, roomID string, body string) string {
	t.Helper()
	return user.SendEventSynced(t, roomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    body,
		},
	})
}

func unsafeSendMessage(t *testing.T, user *client.CSAPI, roomID string, body string) string {
	t.Helper()
	return user.Unsafe_SendEventUnsynced(t, roomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    body,
		},
	})
}

func TestMSC4186SlidingSyncLists(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	t.Run("Initial list returns count and room metadata", func(t *testing.T) {
		roomID := alice.MustCreateRoom(t, map[string]interface{}{})
		sendMessage(t, alice, roomID, "hello")

		_, res := mustDoSlidingSync(t, alice, slidingSyncReq{
			ConnID: "initial-list",
			Lists:  allRoomsList(1, 0, 0),
		})

		must.MatchGJSON(t, res,
			match.JSONKeyEqual("lists.all.count", float64(1)),
			match.JSONKeyPresent("pos"),
		)

		room := requireRoom(t, res, roomID)
		must.MatchGJSON(t, room,
			match.JSONKeyEqual("initial", true),
			match.JSONKeyEqual("membership", "join"),
			match.JSONKeyArrayOfSize("timeline_events", 1),
			match.JSONKeyEqual("lists.0", "all"),
		)
		requireBumpStamp(t, room)
	})

	t.Run("Incremental sync only returns rooms with updates", func(t *testing.T) {
		roomA := alice.MustCreateRoom(t, map[string]interface{}{})
		roomB := alice.MustCreateRoom(t, map[string]interface{}{})
		sendMessage(t, alice, roomA, "room A initial")
		sendMessage(t, alice, roomB, "room B initial")

		pos, res := mustDoSlidingSync(t, alice, slidingSyncReq{
			ConnID: "incremental-updates",
			Lists:  allRoomsList(1, 0, 9),
		})
		requireRoom(t, res, roomA)
		requireRoom(t, res, roomB)

		eventID := sendMessage(t, alice, roomB, "room B update")

		pos, res = mustDoSlidingSync(t, alice, slidingSyncReq{
			ConnID: "incremental-updates",
			Pos:    pos,
			Lists:  allRoomsList(1, 0, 9),
		})

		requireNoRoom(t, res, roomA)
		room := requireRoom(t, res, roomB)
		must.MatchGJSON(t, room,
			match.JSONKeyArrayOfSize("timeline_events", 1),
			match.JSONKeyEqual("timeline_events.0.event_id", eventID),
			match.JSONKeyEqual("num_live", float64(1)),
		)
		requireBumpStamp(t, room)

		_, res = mustDoSlidingSync(t, alice, slidingSyncReq{
			ConnID: "incremental-updates",
			Pos:    pos,
			Lists:  allRoomsList(1, 0, 9),
		})
		requireNoRoom(t, res, roomA)
		requireNoRoom(t, res, roomB)
	})
}

func TestMSC4186SlidingSyncSubscriptions(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	oldRoom := alice.MustCreateRoom(t, map[string]interface{}{})
	sendMessage(t, alice, oldRoom, "old room")
	newRoom := alice.MustCreateRoom(t, map[string]interface{}{})
	sendMessage(t, alice, newRoom, "new room")

	_, res := mustDoSlidingSync(t, alice, slidingSyncReq{
		ConnID: "subscription-outside-range",
		Lists:  allRoomsList(1, 0, 0),
		RoomSubscriptions: map[string]interface{}{
			oldRoom: slidingSubscription(1),
		},
	})

	must.MatchGJSON(t, res,
		match.JSONKeyEqual("lists.all.count", float64(2)),
	)
	requireRoom(t, res, oldRoom)
	requireRoom(t, res, newRoom)
}

func TestMSC4186SlidingSyncListDeltas(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	roomID := alice.MustCreateRoom(t, map[string]interface{}{})
	sendMessage(t, alice, roomID, "initial top room")

	pos, res := mustDoSlidingSync(t, alice, slidingSyncReq{
		ConnID: "list-deltas",
		Lists:  allRoomsList(1, 0, 0),
		RoomSubscriptions: map[string]interface{}{
			roomID: slidingSubscription(1),
		},
	})
	room := requireRoom(t, res, roomID)
	must.MatchGJSON(t, room,
		match.JSONKeyEqual("lists.0", "all"),
	)

	newTopRoom := alice.MustCreateRoom(t, map[string]interface{}{})
	sendMessage(t, alice, newTopRoom, "new top room")

	_, res = mustDoSlidingSync(t, alice, slidingSyncReq{
		ConnID: "list-deltas",
		Pos:    pos,
		Lists:  allRoomsList(1, 0, 0),
		RoomSubscriptions: map[string]interface{}{
			roomID: slidingSubscription(1),
		},
	})

	requireRoom(t, res, newTopRoom)
	room = requireRoom(t, res, roomID)
	must.MatchGJSON(t, room,
		match.JSONKeyArrayOfSize("lists", 0),
	)
}

func TestMSC4186SlidingSyncExpandedTimeline(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	roomID := alice.MustCreateRoom(t, map[string]interface{}{})
	for i := 0; i < 4; i++ {
		sendMessage(t, alice, roomID, fmt.Sprintf("message %d", i))
	}

	pos, res := mustDoSlidingSync(t, alice, slidingSyncReq{
		ConnID: "expanded-timeline",
		Lists:  allRoomsList(1, 0, 0),
	})
	room := requireRoom(t, res, roomID)
	must.MatchGJSON(t, room,
		match.JSONKeyArrayOfSize("timeline_events", 1),
	)

	_, res = mustDoSlidingSync(t, alice, slidingSyncReq{
		ConnID: "expanded-timeline",
		Pos:    pos,
		Lists:  allRoomsList(4, 0, 0),
	})
	room = requireRoom(t, res, roomID)
	must.MatchGJSON(t, room,
		match.JSONKeyEqual("expanded_timeline", true),
		match.JSONKeyArrayOfSize("timeline_events", 4),
	)
}

func TestMSC4186SlidingSyncBulkLoad(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	messageCounts := []int{15, 20, 25, 30, 35, 40, 45, 50, 60, 75}
	type loadedRoom struct {
		roomID   string
		eventIDs []string
	}
	rooms := make([]loadedRoom, 0, len(messageCounts))

	for roomIndex, messageCount := range messageCounts {
		roomID := alice.MustCreateRoom(t, map[string]interface{}{})
		eventIDs := make([]string, 0, messageCount)
		for messageIndex := 0; messageIndex < messageCount; messageIndex++ {
			eventIDs = append(eventIDs, unsafeSendMessage(
				t, alice, roomID, fmt.Sprintf("room %d message %d", roomIndex, messageIndex),
			))
		}
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, eventIDs[len(eventIDs)-1]))
		rooms = append(rooms, loadedRoom{
			roomID:   roomID,
			eventIDs: eventIDs,
		})
	}

	_, res := mustDoSlidingSync(t, alice, slidingSyncReq{
		ConnID: "bulk-load",
		Lists:  allRoomsList(7, 0, len(rooms)-1),
	})
	must.MatchGJSON(t, res,
		match.JSONKeyEqual("lists.all.count", float64(len(rooms))),
	)

	for _, loaded := range rooms {
		room := requireRoom(t, res, loaded.roomID)
		requireBumpStamp(t, room)

		timelineEvents := room.Get("timeline_events").Array()
		if len(timelineEvents) != 7 {
			t.Fatalf("room %s got %d timeline events, want 7: %s", loaded.roomID, len(timelineEvents), room.Raw)
		}

		wantEventIDs := loaded.eventIDs[len(loaded.eventIDs)-len(timelineEvents):]
		for i, wantEventID := range wantEventIDs {
			gotEventID := timelineEvents[i].Get("event_id").Str
			if gotEventID != wantEventID {
				t.Fatalf("room %s timeline event %d got %s, want %s: %s", loaded.roomID, i, gotEventID, wantEventID, room.Raw)
			}
		}

		if limited := room.Get("limited"); !limited.Exists() || !limited.Bool() {
			t.Fatalf("room %s must set limited=true after truncating %d messages to 7: %s", loaded.roomID, len(loaded.eventIDs), room.Raw)
		}
	}
}

func TestMSC4186SlidingSyncIncrementalRoomDeltas(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	t.Run("Unchanged room fields are omitted from incremental timeline updates", func(t *testing.T) {
		roomID := alice.MustCreateRoom(t, map[string]interface{}{
			"name": "Stable name",
		})

		pos, res := mustDoSlidingSync(t, alice, slidingSyncReq{
			ConnID: "incremental-field-deltas",
			Lists:  allRoomsList(1, 0, 0),
		})
		room := requireRoom(t, res, roomID)
		must.MatchGJSON(t, room,
			match.JSONKeyEqual("initial", true),
			match.JSONKeyEqual("name", "Stable name"),
		)

		eventID := sendMessage(t, alice, roomID, "this is the only changed data")

		_, res = mustDoSlidingSync(t, alice, slidingSyncReq{
			ConnID: "incremental-field-deltas",
			Pos:    pos,
			Lists:  allRoomsList(1, 0, 0),
		})
		room = requireRoom(t, res, roomID)
		must.MatchGJSON(t, room,
			match.JSONKeyMissing("initial"),
			match.JSONKeyMissing("name"),
			match.JSONKeyArrayOfSize("timeline_events", 1),
			match.JSONKeyEqual("timeline_events.0.event_id", eventID),
			match.JSONKeyEqual("num_live", float64(1)),
		)
	})

	t.Run("State changes are delivered as deltas without replaying unchanged state", func(t *testing.T) {
		roomID := alice.MustCreateRoom(t, map[string]interface{}{
			"name": "Initial name",
		})
		requiredNameState := map[string]interface{}{
			"include": []map[string]interface{}{
				{"type": "m.room.name", "state_key": ""},
			},
		}

		pos, res := mustDoSlidingSync(t, alice, slidingSyncReq{
			ConnID: "incremental-state-deltas",
			Lists: map[string]interface{}{
				"all": slidingListWithRequiredState(1, 0, 0, requiredNameState),
			},
		})
		room := requireRoom(t, res, roomID)
		must.MatchGJSON(t, room,
			match.JSONKeyEqual("initial", true),
			match.JSONKeyEqual("name", "Initial name"),
			match.JSONKeyArrayOfSize("required_state", 1),
			match.JSONKeyEqual("required_state.0.type", "m.room.name"),
			match.JSONKeyEqual("required_state.0.content.name", "Initial name"),
		)

		alice.SendEventSynced(t, roomID, b.Event{
			Type:     "m.room.name",
			StateKey: b.Ptr(""),
			Content:  map[string]interface{}{"name": "Renamed room"},
		})

		_, res = mustDoSlidingSync(t, alice, slidingSyncReq{
			ConnID: "incremental-state-deltas",
			Pos:    pos,
			Lists: map[string]interface{}{
				"all": slidingListWithRequiredState(1, 0, 0, requiredNameState),
			},
		})
		room = requireRoom(t, res, roomID)
		must.MatchGJSON(t, room,
			match.JSONKeyMissing("initial"),
			match.JSONKeyEqual("name", "Renamed room"),
			match.JSONKeyArrayOfSize("required_state", 1),
			match.JSONKeyEqual("required_state.0.type", "m.room.name"),
			match.JSONKeyEqual("required_state.0.content.name", "Renamed room"),
		)
	})

	t.Run("Required state expansion returns newly requested state immediately", func(t *testing.T) {
		roomID := alice.MustCreateRoom(t, map[string]interface{}{
			"name": "Expanded state room",
		})

		pos, res := mustDoSlidingSync(t, alice, slidingSyncReq{
			ConnID: "required-state-expansion",
			Lists:  allRoomsList(1, 0, 0),
		})
		requireRoom(t, res, roomID)

		requiredNameState := map[string]interface{}{
			"include": []map[string]interface{}{
				{"type": "m.room.name", "state_key": ""},
			},
		}
		_, res = mustDoSlidingSync(t, alice, slidingSyncReq{
			ConnID: "required-state-expansion",
			Pos:    pos,
			Lists: map[string]interface{}{
				"all": slidingListWithRequiredState(1, 0, 0, requiredNameState),
			},
		})
		room := requireRoom(t, res, roomID)
		must.MatchGJSON(t, room,
			match.JSONKeyMissing("initial"),
			match.JSONKeyArrayOfSize("required_state", 1),
			match.JSONKeyEqual("required_state.0.type", "m.room.name"),
			match.JSONKeyEqual("required_state.0.content.name", "Expanded state room"),
		)
	})
}

func TestMSC4186SlidingSyncMembershipListSemantics(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	bob := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	t.Run("Voluntary leave before room was sent on connection is omitted", func(t *testing.T) {
		roomID := alice.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
		bob.MustJoinRoom(t, roomID, nil)
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(bob.UserID, roomID))
		bob.MustLeaveRoom(t, roomID)

		_, res := mustDoSlidingSync(t, bob, slidingSyncReq{
			ConnID: "leave-before-seen",
			Lists:  allRoomsList(1, 0, 9),
		})
		requireNoRoom(t, res, roomID)
	})

	t.Run("Voluntary leave after room was sent on connection is included", func(t *testing.T) {
		roomID := alice.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
		bob.MustJoinRoom(t, roomID, nil)
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(bob.UserID, roomID))

		pos, res := mustDoSlidingSync(t, bob, slidingSyncReq{
			ConnID: "leave-after-seen",
			Lists:  allRoomsList(1, 0, 9),
		})
		requireRoom(t, res, roomID)

		bob.MustLeaveRoom(t, roomID)

		pos, res = mustDoSlidingSync(t, bob, slidingSyncReq{
			ConnID: "leave-after-seen",
			Pos:    pos,
			Lists:  allRoomsList(1, 0, 9),
		})
		room := requireRoom(t, res, roomID)
		must.MatchGJSON(t, room,
			match.JSONKeyMissing("initial"),
			match.JSONKeyEqual("membership", "leave"),
			match.JSONKeyArrayOfSize("timeline_events", 1),
			match.JSONKeyEqual("timeline_events.0.type", "m.room.member"),
			match.JSONKeyEqual("timeline_events.0.state_key", bob.UserID),
			match.JSONKeyEqual("timeline_events.0.content.membership", "leave"),
			match.JSONKeyEqual("num_live", float64(1)),
		)
		requireBumpStamp(t, room)

		_, res = mustDoSlidingSync(t, bob, slidingSyncReq{
			ConnID: "leave-after-seen",
			Pos:    pos,
			Lists:  allRoomsList(1, 0, 9),
		})
		requireNoRoom(t, res, roomID)
	})

	t.Run("Kick before room was sent on connection is included", func(t *testing.T) {
		roomID := alice.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
		bob.MustJoinRoom(t, roomID, nil)
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(bob.UserID, roomID))
		kick(t, alice, roomID, bob.UserID)

		_, res := mustDoSlidingSync(t, bob, slidingSyncReq{
			ConnID: "kick-before-seen",
			Lists:  allRoomsList(1, 0, 9),
		})
		room := requireRoom(t, res, roomID)
		must.MatchGJSON(t, room,
			match.JSONKeyEqual("membership", "leave"),
		)
		requireBumpStamp(t, room)
	})

	t.Run("Ban before room was sent on connection is included", func(t *testing.T) {
		roomID := alice.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
		bob.MustJoinRoom(t, roomID, nil)
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(bob.UserID, roomID))
		ban(t, alice, roomID, bob.UserID)

		_, res := mustDoSlidingSync(t, bob, slidingSyncReq{
			ConnID: "ban-before-seen",
			Lists:  allRoomsList(1, 0, 9),
		})
		room := requireRoom(t, res, roomID)
		must.MatchGJSON(t, room,
			match.JSONKeyEqual("membership", "ban"),
		)
		requireBumpStamp(t, room)
	})
}

func requireBumpStamp(t *testing.T, room gjson.Result) {
	t.Helper()
	if !room.Get("bump_stamp").Exists() {
		t.Fatalf("expected bump_stamp in room response: %s", room.Raw)
	}
	requireSafeBumpStamp(t, room)
}

func requireSafeBumpStamp(t *testing.T, room gjson.Result) {
	t.Helper()
	bumpStamp := room.Get("bump_stamp")
	if !bumpStamp.Exists() {
		return
	}
	if bumpStamp.Type != gjson.Number {
		t.Fatalf("bump_stamp must be a number, got %s in %s", bumpStamp.Type, room.Raw)
	}
	value := bumpStamp.Float()
	if math.Trunc(value) != value {
		t.Fatalf("bump_stamp must be an integer, got %v in %s", value, room.Raw)
	}
	if value > maxSafeJSONInteger {
		t.Fatalf("bump_stamp must not exceed 2^53-1, got %.0f in %s", value, room.Raw)
	}
}

func kick(t *testing.T, user *client.CSAPI, roomID string, targetUserID string) {
	t.Helper()
	res := user.Do(t, "POST", []string{"_matrix", "client", "v3", "rooms", roomID, "kick"},
		client.WithJSONBody(t, map[string]interface{}{
			"user_id": targetUserID,
			"reason":  "testing",
		}),
	)
	must.MatchResponse(t, res, match.HTTPResponse{StatusCode: http.StatusOK})
}

func ban(t *testing.T, user *client.CSAPI, roomID string, targetUserID string) {
	t.Helper()
	res := user.Do(t, "POST", []string{"_matrix", "client", "v3", "rooms", roomID, "ban"},
		client.WithJSONBody(t, map[string]interface{}{
			"user_id": targetUserID,
			"reason":  "testing",
		}),
	)
	must.MatchResponse(t, res, match.HTTPResponse{StatusCode: http.StatusOK})
}

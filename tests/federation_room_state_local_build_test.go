package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/matrix-org/complement"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/match"
	"github.com/matrix-org/complement/must"
)

// These tests cover state resolution at incoming federation events whose
// prev_events are stored but not yet resolved. A homeserver that already
// holds the entire ancestry of an incoming event, through gap filling or
// earlier deliveries, must derive the state at that event locally: it must
// not need /state_ids or /state, and an ancestor that is valid against the
// auth_events it cites but unauthorized at its position in the DAG must not
// leak into the room state while events built on top of it integrate.

// gapFillServer wires the Complement federation server shared by the tests in
// this file. It serves keys, joins, single events and transactions, answers
// /get_missing_events per room from a table the test fills in, tolerates
// /backfill, and fails the test on any /state_ids or /state request while
// still serving a valid answer, so a server that does fetch keeps running and
// the state assertions afterwards expose what the fetched claim did.
type gapFillServer struct {
	srv           *federation.Server
	rooms         map[string]*federation.ServerRoom
	missingEvents map[string]http.HandlerFunc
}

func newGapFillServer(t *testing.T, deployment complement.Deployment) (*gapFillServer, func()) {
	gs := &gapFillServer{
		rooms:         make(map[string]*federation.ServerRoom),
		missingEvents: make(map[string]http.HandlerFunc),
	}
	gs.srv = federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
		federation.HandleEventRequests(),
		federation.HandleEventAuthRequests(),
	)
	gs.srv.Mux().HandleFunc("/_matrix/federation/v1/get_missing_events/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		roomID := mux.Vars(req)["roomID"]
		if handler := gs.missingEvents[roomID]; handler != nil {
			handler(w, req)
			return
		}
		t.Errorf("received /get_missing_events for room %s without a prepared gap", roomID)
		w.WriteHeader(404)
		w.Write([]byte("complement: no missing events prepared for this room"))
	}).Methods("POST")
	gs.srv.Mux().HandleFunc("/_matrix/federation/v1/state_ids/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		roomID := mux.Vars(req)["roomID"]
		t.Errorf("received /state_ids for room %s at event %q: the ancestry is fully known to the homeserver", roomID, req.URL.Query().Get("event_id"))
		room := gs.rooms[roomID]
		if room == nil {
			w.WriteHeader(404)
			w.Write([]byte("complement: unknown room"))
			return
		}
		state := room.AllCurrentState()
		respondJSON(t, w, map[string]interface{}{
			"auth_chain_ids": eventIDsOf(room.AuthChainForEvents(state)),
			"pdu_ids":        eventIDsOf(state),
		})
	}).Methods("GET")
	gs.srv.Mux().HandleFunc("/_matrix/federation/v1/state/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		roomID := mux.Vars(req)["roomID"]
		t.Errorf("received /state for room %s at event %q: the ancestry is fully known to the homeserver", roomID, req.URL.Query().Get("event_id"))
		room := gs.rooms[roomID]
		if room == nil {
			w.WriteHeader(404)
			w.Write([]byte("complement: unknown room"))
			return
		}
		state := room.AllCurrentState()
		respondJSON(t, w, map[string]interface{}{
			"auth_chain": gomatrixserverlib.NewEventJSONsFromEvents(room.AuthChainForEvents(state)),
			"pdus":       gomatrixserverlib.NewEventJSONsFromEvents(state),
		})
	}).Methods("GET")
	// Backfill is not part of the assertion surface; answer emptily so a
	// /messages walk past the join boundary cannot trip the 404 guard.
	gs.srv.Mux().HandleFunc("/_matrix/federation/v1/backfill/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		respondJSON(t, w, map[string]interface{}{
			"origin":           gs.srv.ServerName(),
			"origin_server_ts": spec.AsTimestamp(time.Now()),
			"pdus":             []json.RawMessage{},
		})
	}).Methods("GET")
	cancel := gs.srv.Listen()
	return gs, cancel
}

// makeGapFillRoom creates a room on the Complement server with charlie as its
// creator and mallory joined, then joins the given homeserver user to it over
// federation, so later events by either Complement user authenticate against
// state the homeserver received in the join response.
func (gs *gapFillServer) makeGapFillRoom(t *testing.T, joiner *client.CSAPI) (room *federation.ServerRoom, charlie, mallory string) {
	charlie = gs.srv.UserID("charlie")
	mallory = gs.srv.UserID("mallory")
	ver := joiner.GetDefaultRoomVersion(t)
	room = gs.srv.MustMakeRoom(t, ver, federation.InitialRoomEvents(ver, charlie))
	gs.rooms[room.RoomID] = room
	malloryJoin := gs.srv.MustCreateEvent(t, room, federation.Event{
		Type:     spec.MRoomMember,
		StateKey: &mallory,
		Sender:   mallory,
		Content:  map[string]interface{}{"membership": "join"},
	})
	room.AddEvent(malloryJoin)
	joiner.MustJoinRoom(t, room.RoomID, []spec.ServerName{gs.srv.ServerName()})
	joiner.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(joiner.UserID, room.RoomID))
	return room, charlie, mallory
}

// missingEventsResponder answers /get_missing_events with exactly the given
// events. The tests control the gap shape themselves, so the requested window
// is deliberately ignored; anything withheld here is still available through
// the /event fallback.
func missingEventsResponder(t *testing.T, events ...gomatrixserverlib.PDU) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		raws := make([]json.RawMessage, 0, len(events))
		for _, ev := range events {
			raws = append(raws, ev.JSON())
		}
		t.Logf("/get_missing_events: serving %d events", len(raws))
		respondJSON(t, w, map[string]interface{}{"events": raws})
	}
}

func respondJSON(t *testing.T, w http.ResponseWriter, body interface{}) {
	raw, err := json.Marshal(body)
	must.NotError(t, "failed to marshal response", err)
	w.WriteHeader(200)
	w.Write(raw)
}

func eventIDsOf(events []gomatrixserverlib.PDU) []string {
	ids := make([]string, 0, len(events))
	for _, ev := range events {
		ids = append(ids, ev.EventID())
	}
	return ids
}

// TestGapFillingUnauthorizedStateEvent drives the ancestry shape behind
// federation state resets: a state event that is valid against the
// auth_events it cites but unauthorized at its position in the DAG. When such
// an event arrives through gap filling, the homeserver must accept the events
// built on top of it, must keep it out of the room state, and must not ask
// for /state_ids: it already holds the event's entire ancestry.
//
// DAG, in room order:
//
//	ban    charlie bans mallory
//	evil   mallory updates her own membership, citing the pre-ban room
//	       state in auth_events; served only via /get_missing_events
//	probe  message by charlie with prev_events [evil], delivered via /send
//
// In every arrival order the correct outcome is the same: probe integrates,
// mallory stays banned, and no state fetch happens.
func TestGapFillingUnauthorizedStateEvent(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	alice.SyncUntilTimeout = 30 * time.Second
	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")
	gs, cancel := newGapFillServer(t, deployment)
	defer cancel()

	buildDAG := func(t *testing.T) (room *federation.ServerRoom, mallory string, ban, evil, probe gomatrixserverlib.PDU) {
		room, charlie, mallory := gs.makeGapFillRoom(t, alice)
		ban = gs.srv.MustCreateEvent(t, room, federation.Event{
			Type:     spec.MRoomMember,
			StateKey: &mallory,
			Sender:   charlie,
			Content:  map[string]interface{}{"membership": "ban", "reason": "unauthorized fold test"},
		})
		// Built before the ban is applied to the tracked room state, so the
		// automatic auth_events selection cites mallory's join: valid against
		// its own auth_events, unauthorized after the ban it descends from.
		evil = gs.srv.MustCreateEvent(t, room, federation.Event{
			Type:       spec.MRoomMember,
			StateKey:   &mallory,
			Sender:     mallory,
			Content:    map[string]interface{}{"membership": "join", "displayname": "evil"},
			PrevEvents: []string{ban.EventID()},
		})
		room.AddEvent(ban)
		room.AddEvent(evil)
		probe = gs.srv.MustCreateEvent(t, room, federation.Event{
			Type:       "m.room.message",
			Sender:     charlie,
			Content:    map[string]interface{}{"msgtype": "m.text", "body": "built on the unauthorized event"},
			PrevEvents: []string{evil.EventID()},
		})
		room.AddEvent(probe)
		return room, mallory, ban, evil, probe
	}

	assertOutcome := func(t *testing.T, room *federation.ServerRoom, mallory string, probe gomatrixserverlib.PDU) {
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(room.RoomID, probe.EventID()))
		content := alice.MustGetStateEventContent(t, room.RoomID, spec.MRoomMember, mallory)
		must.MatchGJSON(t, content, match.JSONKeyEqual("membership", "ban"))
		must.Equal(t, content.Get("displayname").Str, "", "the unauthorized membership update reached the room state")
	}

	t.Run("ban delivered first", func(t *testing.T) {
		room, mallory, ban, evil, probe := buildDAG(t)
		gs.missingEvents[room.RoomID] = missingEventsResponder(t, evil)

		srv := gs.srv
		srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{ban.JSON()}, nil)
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(room.RoomID, ban.EventID()))

		srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{probe.JSON()}, nil)
		assertOutcome(t, room, mallory, probe)
	})

	t.Run("ban backfilled after probe", func(t *testing.T) {
		room, mallory, ban, evil, probe := buildDAG(t)
		// Only the direct gap is served; the ban is left for the per-event
		// fallback, so it arrives as an outlier below the unauthorized event.
		gs.missingEvents[room.RoomID] = missingEventsResponder(t, evil)

		srv := gs.srv
		srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{probe.JSON()}, nil)
		// Delivering the ban afterwards must be a no-op: it was already
		// integrated while filling the gap.
		srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{ban.JSON()}, nil)
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(room.RoomID, ban.EventID()))
		assertOutcome(t, room, mallory, probe)
	})
}

// TestGapFillingAuthorizedStateEvent is the control for
// TestGapFillingUnauthorizedStateEvent: the same DAG shape with an authorized
// membership update in the gap must integrate the update into both timeline
// and state, still without any state fetch. This distinguishes "unauthorized
// ancestors are kept out of state" from "gap-filled ancestors never make it
// into state".
func TestGapFillingAuthorizedStateEvent(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	alice.SyncUntilTimeout = 30 * time.Second
	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")
	gs, cancel := newGapFillServer(t, deployment)
	defer cancel()

	room, charlie, mallory := gs.makeGapFillRoom(t, alice)
	emptyKey := ""
	rename := gs.srv.MustCreateEvent(t, room, federation.Event{
		Type:     "m.room.name",
		StateKey: &emptyKey,
		Sender:   charlie,
		Content:  map[string]interface{}{"name": "authorized fold control"},
	})
	update := gs.srv.MustCreateEvent(t, room, federation.Event{
		Type:       spec.MRoomMember,
		StateKey:   &mallory,
		Sender:     mallory,
		Content:    map[string]interface{}{"membership": "join", "displayname": "friendly"},
		PrevEvents: []string{rename.EventID()},
	})
	room.AddEvent(rename)
	room.AddEvent(update)
	probe := gs.srv.MustCreateEvent(t, room, federation.Event{
		Type:       "m.room.message",
		Sender:     charlie,
		Content:    map[string]interface{}{"msgtype": "m.text", "body": "built on the authorized event"},
		PrevEvents: []string{update.EventID()},
	})
	room.AddEvent(probe)
	gs.missingEvents[room.RoomID] = missingEventsResponder(t, update)

	gs.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{rename.JSON()}, nil)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(room.RoomID, rename.EventID()))

	gs.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{probe.JSON()}, nil)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(room.RoomID, probe.EventID()))
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(room.RoomID, update.EventID()))

	content := alice.MustGetStateEventContent(t, room.RoomID, spec.MRoomMember, mallory)
	must.MatchGJSON(t, content,
		match.JSONKeyEqual("membership", "join"),
		match.JSONKeyEqual("displayname", "friendly"),
	)
}

// TestGapFillingDeepChain delivers a chain of thirty events through a single
// /send of its tip: /get_missing_events serves only the ten newest ancestors
// and the rest arrive as per-event fetches, so children land as stored
// outliers before their parents integrate. Mid-chain sits a run of events by
// a banned user, each valid against the pre-ban auth_events it cites but
// unauthorized at its position. The homeserver must integrate every
// authorized event, keep the unauthorized run out of timeline and state, and
// never fetch /state_ids.
func TestGapFillingDeepChain(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	alice.SyncUntilTimeout = 60 * time.Second
	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")
	gs, cancel := newGapFillServer(t, deployment)
	defer cancel()

	room, charlie, mallory := gs.makeGapFillRoom(t, alice)
	daniel := gs.srv.UserID("daniel")

	var dag []gomatrixserverlib.PDU          // every chain event in room order, tip last
	var unauthorized []gomatrixserverlib.PDU // mallory's post-ban run
	var prev string
	appendMessage := func(sender, body string) gomatrixserverlib.PDU {
		ev := gs.srv.MustCreateEvent(t, room, federation.Event{
			Type:       "m.room.message",
			Sender:     sender,
			Content:    map[string]interface{}{"msgtype": "m.text", "body": body},
			PrevEvents: []string{prev},
		})
		dag = append(dag, ev)
		prev = ev.EventID()
		return ev
	}

	// The head of the chain is built before any of it is applied to the
	// tracked room state, so the automatic auth_events selection for
	// mallory's run cites the pre-ban room state: each event is valid
	// against its own auth_events yet unauthorized where it sits.
	ban := gs.srv.MustCreateEvent(t, room, federation.Event{
		Type:     spec.MRoomMember,
		StateKey: &mallory,
		Sender:   charlie,
		Content:  map[string]interface{}{"membership": "ban", "reason": "deep chain test"},
	})
	dag = append(dag, ban)
	prev = ban.EventID()
	for i := 1; i <= 7; i++ {
		appendMessage(charlie, fmt.Sprintf("before the unauthorized run %d", i))
	}
	rejoin := gs.srv.MustCreateEvent(t, room, federation.Event{
		Type:       spec.MRoomMember,
		StateKey:   &mallory,
		Sender:     mallory,
		Content:    map[string]interface{}{"membership": "join", "displayname": "evil"},
		PrevEvents: []string{prev},
	})
	dag = append(dag, rejoin)
	unauthorized = append(unauthorized, rejoin)
	prev = rejoin.EventID()
	for i := 1; i <= 3; i++ {
		unauthorized = append(unauthorized, appendMessage(mallory, fmt.Sprintf("unauthorized message %d", i)))
	}
	for _, ev := range dag {
		room.AddEvent(ev)
	}

	// The tail is applied as it is built; ordinary auth selection applies.
	danielJoin := gs.srv.MustCreateEvent(t, room, federation.Event{
		Type:       spec.MRoomMember,
		StateKey:   &daniel,
		Sender:     daniel,
		Content:    map[string]interface{}{"membership": "join"},
		PrevEvents: []string{prev},
	})
	room.AddEvent(danielJoin)
	dag = append(dag, danielJoin)
	prev = danielJoin.EventID()
	for i := 1; i <= 17; i++ {
		room.AddEvent(appendMessage(charlie, fmt.Sprintf("after the unauthorized run %d", i)))
	}
	tip := dag[len(dag)-1]

	// Serve only the ten newest ancestors below the tip; the deeper chain is
	// withheld from the batch and arrives through per-event fetches instead.
	gs.missingEvents[room.RoomID] = missingEventsResponder(t, dag[len(dag)-11:len(dag)-1]...)

	gs.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{ban.JSON()}, nil)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(room.RoomID, ban.EventID()))

	gs.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{tip.JSON()}, nil)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(room.RoomID, tip.EventID()))

	// The timeline converged on every authorized event and nothing else.
	res := alice.MustDo(t, "GET",
		[]string{"_matrix", "client", "v3", "rooms", room.RoomID, "messages"},
		client.WithQueries(url.Values{"dir": {"b"}, "limit": {"100"}}),
	)
	body := must.ParseJSON(t, res.Body)
	seen := map[string]bool{}
	body.Get("chunk").ForEach(func(_, ev gjson.Result) bool {
		seen[ev.Get("event_id").Str] = true
		return true
	})
	isUnauthorized := map[string]bool{}
	for _, ev := range unauthorized {
		isUnauthorized[ev.EventID()] = true
	}
	for _, ev := range dag {
		switch {
		case isUnauthorized[ev.EventID()] && seen[ev.EventID()]:
			t.Errorf("unauthorized event %s reached the timeline", ev.EventID())
		case !isUnauthorized[ev.EventID()] && !seen[ev.EventID()]:
			t.Errorf("authorized event %s missing from the timeline", ev.EventID())
		}
	}

	content := alice.MustGetStateEventContent(t, room.RoomID, spec.MRoomMember, mallory)
	must.MatchGJSON(t, content, match.JSONKeyEqual("membership", "ban"))
	must.Equal(t, content.Get("displayname").Str, "", "the unauthorized membership update reached the room state")
	content = alice.MustGetStateEventContent(t, room.RoomID, spec.MRoomMember, daniel)
	must.MatchGJSON(t, content, match.JSONKeyEqual("membership", "join"))

	// The unauthorized run stays retrievable as stored events even though it
	// never integrated.
	for _, ev := range unauthorized {
		res := alice.MustDo(t, "GET",
			[]string{"_matrix", "client", "v3", "rooms", room.RoomID, "event", ev.EventID()},
		)
		body := must.ParseJSON(t, res.Body)
		must.Equal(t, body.Get("event_id").Str, ev.EventID(), "unexpected event returned")
	}
}

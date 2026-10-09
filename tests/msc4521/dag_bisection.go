package msc4521

import (
	"errors"
	"fmt"
)

// ViewMode describes whether a peer claims a complete DAG or only a bounded
// authenticated view of it.
type ViewMode string

const (
	ViewTotal   ViewMode = "total"
	ViewPartial ViewMode = "partial"
)

// DAGEvent is the minimum event identity needed by the bisection contract.
// Position is an authenticated position in the negotiated frame order.
type DAGEvent struct {
	Position uint64
	EventID  string
	Type     string
	StateKey *string
}

// ViewBoundary authenticates the range a partial peer is willing to compare.
// The proof is opaque to this deterministic API; the transport is responsible
// for verifying it before constructing a DAGView.
type ViewBoundary struct {
	FrameID string
	Start   uint64
	End     uint64
	Proof   []byte
}

// DAGView is a peer's ordered view of one negotiated frame.
type DAGView struct {
	Mode     ViewMode
	Boundary ViewBoundary
	Events   []DAGEvent
}

type DifferenceKind string

const (
	EventOmission DifferenceKind = "event-omission"
	StateOmission DifferenceKind = "state-omission"
	EventConflict DifferenceKind = "event-conflict"
	StateConflict DifferenceKind = "state-conflict"
)

// Difference identifies the earliest comparable discrepancy. A nil side
// means that the event is absent from that peer's claimed coverage.
type Difference struct {
	Position uint64
	Kind     DifferenceKind
	Local    *DAGEvent
	Remote   *DAGEvent
}

var (
	ErrInvalidView       = errors.New("invalid DAG view")
	ErrFrameMismatch     = errors.New("DAG views use different frames")
	ErrBoundaryUntrusted = errors.New("partial view has no authenticated boundary")
)

// Bisect returns the earliest discrepancy in the intersection of two claimed
// views. Events outside a partial peer's authenticated boundary are unknown,
// not omissions. The input event slices must be ordered by Position.
func Bisect(local, remote DAGView) (*Difference, error) {
	if err := validateView(local); err != nil {
		return nil, fmt.Errorf("local view: %w", err)
	}
	if err := validateView(remote); err != nil {
		return nil, fmt.Errorf("remote view: %w", err)
	}
	if local.Boundary.FrameID != remote.Boundary.FrameID {
		return nil, ErrFrameMismatch
	}

	left := max(local.Boundary.Start, remote.Boundary.Start)
	right := min(local.Boundary.End, remote.Boundary.End)
	if left > right {
		return nil, nil
	}

	localEvents := eventsByPosition(local.Events)
	remoteEvents := eventsByPosition(remote.Events)
	for position := left; position <= right; position++ {
		le, lok := localEvents[position]
		re, rok := remoteEvents[position]
		if !lok && !rok {
			continue
		}
		if !lok || !rok {
			kind := EventOmission
			present := le
			if !lok {
				present = re
			}
			if present.StateKey != nil {
				kind = StateOmission
			}
			return &Difference{Position: position, Kind: kind, Local: le, Remote: re}, nil
		}
		if le.EventID == re.EventID {
			continue
		}
		kind := EventConflict
		if le.StateKey != nil && re.StateKey != nil && *le.StateKey == *re.StateKey && le.Type == re.Type {
			kind = StateConflict
		}
		return &Difference{Position: position, Kind: kind, Local: le, Remote: re}, nil
	}
	return nil, nil
}

func validateView(view DAGView) error {
	if view.Mode != ViewTotal && view.Mode != ViewPartial {
		return fmt.Errorf("%w: unknown mode %q", ErrInvalidView, view.Mode)
	}
	if view.Boundary.FrameID == "" || view.Boundary.Start > view.Boundary.End {
		return ErrInvalidView
	}
	if view.Mode == ViewPartial && len(view.Boundary.Proof) == 0 {
		return ErrBoundaryUntrusted
	}
	var previous uint64
	for i, event := range view.Events {
		if event.EventID == "" || (i > 0 && event.Position <= previous) {
			return ErrInvalidView
		}
		if event.Position < view.Boundary.Start || event.Position > view.Boundary.End {
			return ErrInvalidView
		}
		previous = event.Position
	}
	return nil
}

func eventsByPosition(events []DAGEvent) map[uint64]*DAGEvent {
	result := make(map[uint64]*DAGEvent, len(events))
	for i := range events {
		result[events[i].Position] = &events[i]
	}
	return result
}

func max(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}

func min(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}

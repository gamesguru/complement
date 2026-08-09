//go:build conduit_blacklist
// +build conduit_blacklist

package runtime

func init() {
	Homeserver = Conduit
}

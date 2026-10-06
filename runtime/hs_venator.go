//go:build venator_blacklist

package runtime

// init selects Venator for runtime test filtering when venator_blacklist is enabled.
func init() {
	Homeserver = Venator
}

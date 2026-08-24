//go:build continuwuity_blacklist
// +build continuwuity_blacklist

package runtime

func init() {
	Homeserver = Continuwuity
}

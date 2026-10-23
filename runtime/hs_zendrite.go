//go:build zendrite_blacklist
// +build zendrite_blacklist

package runtime

func init() {
	Homeserver = Zendrite
}

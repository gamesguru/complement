//go:build tuwunel_blacklist
// +build tuwunel_blacklist

package runtime

func init() {
	Homeserver = Tuwunel
}

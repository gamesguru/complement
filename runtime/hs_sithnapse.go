//go:build sithnapse_blacklist
// +build sithnapse_blacklist

package runtime

func init() {
	Homeserver = Sithnapse
}

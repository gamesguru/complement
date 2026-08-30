//go:build synapse_blacklist
// +build synapse_blacklist

package runtime

func init() {
	Homeserver = Synapse
}

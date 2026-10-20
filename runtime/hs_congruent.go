//go:build congruent_blacklist
// +build congruent_blacklist

package runtime

func init() {
	Homeserver = Congruent
}

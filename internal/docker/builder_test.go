// Copyright 2020 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package docker

import (
	"testing"

	"github.com/moby/moby/api/types/network"
)

// TestFindPortBindingEmptyHostIP is a regression test ensuring that a port
// binding with an unset/invalid `HostIP` (observed with podman v4.3.1) is
// still treated as a localhost binding, rather than being skipped because
// `netip.Addr.String()` does not render a zero value as `""`.
func TestFindPortBindingEmptyHostIP(t *testing.T) {
	portMap := network.PortMap{
		network.MustParsePort("1234/tcp"): []network.PortBinding{
			{
				// unset/invalid HostIP (zero value)
				HostPort: "5678",
			},
		},
	}

	pb, err := findPortBinding(portMap, "127.0.0.1", 1234)
	if err != nil {
		t.Fatalf("findPortBinding returned an error: %v", err)
	}
	if pb.HostPort != "5678" {
		t.Errorf("expected HostPort '5678', got '%s'", pb.HostPort)
	}
	if pb.HostIP.String() != "127.0.0.1" {
		t.Errorf("expected HostIP '127.0.0.1', got '%s'", pb.HostIP.String())
	}
}

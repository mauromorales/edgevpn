/*
Copyright © 2021-2022 Ettore Di Giacinto <mudler@mocaccino.org>
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package node

import (
	"testing"
	"time"

	"github.com/mudler/edgevpn/pkg/blockchain"
	"github.com/mudler/edgevpn/pkg/protocol"
)

// An application bucket registered with WithBucketPolicies must reach the
// registry the ledger enforces, next to the built-in buckets. Before this
// option existed the node always used DefaultRegistry alone, so an
// application bucket stayed open whatever the caller wanted.
func TestWithBucketPoliciesReachesLedgerRegistry(t *testing.T) {
	e, err := New(
		WithOwnership(blockchain.OwnershipEnforce, 0),
		WithBucketPolicies(blockchain.Registry{"app": blockchain.OwnedBucket(blockchain.NoExpiry, 0)}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r, err := e.ownershipRegistry(time.Minute)
	if err != nil {
		t.Fatalf("ownershipRegistry: %v", err)
	}
	p := r.Policy("app")
	if !p.Owned || p.Expiry != blockchain.NoExpiry || p.OwnerOf != nil {
		t.Errorf("app bucket policy = %+v, want owned, first-claim, no expiry", p)
	}
	if !r.Policy(protocol.MachinesLedgerKey).Owned {
		t.Error("built-in machines bucket lost its policy after merging application buckets")
	}
	if r.Policy("not-registered").Owned {
		t.Error("an unregistered bucket became owned; it must stay open")
	}
}

func TestWithBucketPoliciesAccumulates(t *testing.T) {
	e, err := New(
		WithBucketPolicies(blockchain.Registry{"a": blockchain.OwnedBucket(blockchain.Liveness, 0)}),
		WithBucketPolicies(blockchain.Registry{"b": blockchain.OwnedBucket(blockchain.Absolute, time.Hour)}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(e.config.BucketPolicies) != 2 {
		t.Errorf("BucketPolicies = %v, want both a and b", e.config.BucketPolicies)
	}
}

// Re-registering a built-in bucket could weaken it (for example make machines
// unowned), and registering one bucket twice is ambiguous. Both must fail.
func TestWithBucketPoliciesRejectsConflicts(t *testing.T) {
	cases := map[string][]Option{
		"built-in bucket": {
			WithBucketPolicies(blockchain.Registry{protocol.MachinesLedgerKey: {}}),
		},
		"duplicate bucket": {
			WithBucketPolicies(blockchain.Registry{"app": blockchain.OwnedBucket(blockchain.NoExpiry, 0)}),
			WithBucketPolicies(blockchain.Registry{"app": blockchain.OwnedBucket(blockchain.Liveness, 0)}),
		},
		"empty name": {
			WithBucketPolicies(blockchain.Registry{"": blockchain.OwnedBucket(blockchain.NoExpiry, 0)}),
		},
	}
	for name, opts := range cases {
		if _, err := New(opts...); err == nil {
			t.Errorf("%s: New accepted the options, want an error", name)
		}
	}
}

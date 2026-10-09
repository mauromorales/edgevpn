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

package blockchain

import (
	"io"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/mudler/edgevpn/pkg/protocol"
)

var _ = Describe("Application owned buckets", func() {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const bucket, key = "app", "config"

	ledgerWith := func(app BucketPolicy, clock time.Time) *Ledger {
		r, err := DefaultRegistry(time.Minute).Merge(Registry{bucket: app})
		Expect(err).NotTo(HaveOccurred())
		return New(io.Discard, &MemoryStore{},
			WithEnforcedOwnership(r, time.Minute),
			WithClock(func() time.Time { return clock }),
		)
	}
	stored := func(l *Ledger) string {
		v, _ := l.GetKey(bucket, key)
		var s string
		v.Unmarshal(&s)
		return s
	}

	Describe("ParseOwnedBucket", func() {
		It("defaults a bare name to liveness expiry, like dns", func() {
			name, p, err := ParseOwnedBucket("app")
			Expect(err).NotTo(HaveOccurred())
			Expect(name).To(Equal("app"))
			Expect(p.Owned).To(BeTrue())
			Expect(p.OwnerOf).To(BeNil())
			Expect(p.Expiry).To(Equal(Liveness))
		})
		It("accepts an explicit liveness expiry", func() {
			_, p, err := ParseOwnedBucket("app:liveness")
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Expiry).To(Equal(Liveness))
		})
		It("accepts never for an entry that does not expire", func() {
			_, p, err := ParseOwnedBucket("app:never")
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Expiry).To(Equal(NoExpiry))
			Expect(p.Reclaimable).To(BeFalse())
		})
		It("accepts a duration as an absolute TTL", func() {
			_, p, err := ParseOwnedBucket("app:24h")
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Expiry).To(Equal(Absolute))
			Expect(p.TTL).To(Equal(24 * time.Hour))
		})
		It("rejects an empty name and a bad expiry", func() {
			for _, spec := range []string{"", ":never", "app:", "app:forever", "app:-1h", "app:0s"} {
				_, _, err := ParseOwnedBucket(spec)
				Expect(err).To(HaveOccurred(), "spec %q", spec)
			}
		})
	})

	Describe("Registry.Merge", func() {
		It("adds application buckets and keeps the built-in ones", func() {
			r, err := DefaultRegistry(time.Minute).Merge(Registry{bucket: OwnedBucket(NoExpiry, 0)})
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Policy(bucket).Owned).To(BeTrue())
			Expect(r.Policy(protocol.MachinesLedgerKey).Owned).To(BeTrue())
		})
		It("refuses to override an existing bucket", func() {
			_, err := DefaultRegistry(time.Minute).Merge(Registry{protocol.MachinesLedgerKey: {}})
			Expect(err).To(HaveOccurred())
		})
		It("does not modify the receiver", func() {
			base := DefaultRegistry(time.Minute)
			_, err := base.Merge(Registry{bucket: OwnedBucket(NoExpiry, 0)})
			Expect(err).NotTo(HaveOccurred())
			Expect(base.Policy(bucket).Owned).To(BeFalse())
		})
	})

	It("leaves an unregistered application bucket open to overwrite", func() {
		l := New(io.Discard, &MemoryStore{},
			WithEnforcedOwnership(DefaultRegistry(time.Minute), time.Minute),
			WithClock(func() time.Time { return now }))
		a, b := newTestSigner(), newTestSigner()

		feed(l, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(a, bucket, key, "from-a", 1, now)}})
		feed(l, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(b, bucket, key, "from-b", 2, now)}})

		Expect(stored(l)).To(Equal("from-b"))
	})

	It("rejects another peer's overwrite of a registered never-expiring bucket", func() {
		l := ledgerWith(OwnedBucket(NoExpiry, 0), now)
		a, b := newTestSigner(), newTestSigner()

		// No heartbeat for A: a never-expiring entry must not depend on one.
		feed(l, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(a, bucket, key, "from-a", 1, now)}})
		feed(l, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(b, bucket, key, "from-b", 2, now)}})

		Expect(stored(l)).To(Equal("from-a"))
	})

	It("lets the owner update its own entry", func() {
		l := ledgerWith(OwnedBucket(NoExpiry, 0), now)
		a := newTestSigner()

		feed(l, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(a, bucket, key, "v1", 1, now)}})
		feed(l, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(a, bucket, key, "v2", 2, now)}})

		Expect(stored(l)).To(Equal("v2"))
	})

	It("protects a liveness bucket while the owner is live and frees it after", func() {
		l := ledgerWith(OwnedBucket(Liveness, 0), now)
		a, b := newTestSigner(), newTestSigner()

		feed(l, heartbeat(a, now))
		feed(l, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(a, bucket, key, "from-a", 1, now)}})
		feed(l, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(b, bucket, key, "from-b", 2, now)}})
		Expect(stored(l)).To(Equal("from-a"))

		// Same entries, but A's heartbeat is older than the liveness window.
		stale := now.Add(-10 * time.Minute)
		l2 := ledgerWith(OwnedBucket(Liveness, 0), now)
		feed(l2, heartbeat(a, stale))
		feed(l2, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(a, bucket, key, "from-a", 1, stale)}})
		feed(l2, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(b, bucket, key, "from-b", 2, now)}})
		Expect(stored(l2)).To(Equal("from-b"))
	})

	It("frees an absolute-TTL entry only after its TTL", func() {
		a, b := newTestSigner(), newTestSigner()
		written := now.Add(-30 * time.Minute)

		fresh := ledgerWith(OwnedBucket(Absolute, time.Hour), now)
		feed(fresh, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(a, bucket, key, "from-a", 1, written)}})
		feed(fresh, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(b, bucket, key, "from-b", 2, now)}})
		Expect(stored(fresh)).To(Equal("from-a"))

		expired := ledgerWith(OwnedBucket(Absolute, 10*time.Minute), now)
		feed(expired, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(a, bucket, key, "from-a", 1, written)}})
		feed(expired, map[string]map[string]SignedData{bucket: {key: mkSignedEntry(b, bucket, key, "from-b", 2, now)}})
		Expect(stored(expired)).To(Equal("from-b"))
	})
})

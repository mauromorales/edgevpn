package blockchain

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("owned- prefix buckets", func() {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const bucket = OwnedBucketPrefix + "noj"

	It("keeps the first signer as owner and rejects other writers", func() {
		l := enforcedLedger(time.Minute, now)
		a, b := newTestSigner(), newTestSigner()

		feed(l, map[string]map[string]SignedData{bucket: {"seatA": mkSignedEntry(a, bucket, "seatA", "v1", 1, now)}})
		v, _ := l.GetKey(bucket, "seatA")
		Expect(string(v)).To(Equal(`"v1"`))

		// B overwrites with a higher version: rejected.
		feed(l, map[string]map[string]SignedData{bucket: {"seatA": mkSignedEntry(b, bucket, "seatA", "HIJACKED", 99, now)}})
		v, _ = l.GetKey(bucket, "seatA")
		Expect(string(v)).To(Equal(`"v1"`))

		// Still rejected long after: NoExpiry means no reclaim.
		later := now.Add(365 * 24 * time.Hour)
		l.clock = func() time.Time { return later }
		feed(l, map[string]map[string]SignedData{bucket: {"seatA": mkSignedEntry(b, bucket, "seatA", "HIJACKED", 100, later)}})
		v, _ = l.GetKey(bucket, "seatA")
		Expect(string(v)).To(Equal(`"v1"`))

		// A updates its own entry: accepted.
		feed(l, map[string]map[string]SignedData{bucket: {"seatA": mkSignedEntry(a, bucket, "seatA", "v2", 101, later)}})
		v, _ = l.GetKey(bucket, "seatA")
		Expect(string(v)).To(Equal(`"v2"`))
	})

	It("leaves other unregistered buckets open", func() {
		Expect(DefaultRegistry(time.Minute).Policy("noj").Owned).To(BeFalse())
		Expect(DefaultRegistry(time.Minute).Policy(bucket).Owned).To(BeTrue())
	})
})

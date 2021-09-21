package discovery

import (
	"context"

	"github.com/libp2p/go-libp2p"
	"go.uber.org/zap"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
)

type MDNS struct {
	DiscoveryServiceTag string
}

// discoveryNotifee gets notified when we find a new peer via mDNS discovery
type discoveryNotifee struct {
	h host.Host
	c *zap.Logger
}

// HandlePeerFound connects to peers discovered via mDNS. Once they're connected,
// the PubSub system will automatically start interacting with them if they also
// support PubSub.
func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	//n.c.Infof("mDNS: discovered new peer %s\n", pi.ID.Pretty())
	err := n.h.Connect(context.Background(), pi)
	if err != nil {
		n.c.Sugar().Warnf("mDNS: error connecting to peer %s: %s\n", pi.ID.Pretty(), err)
	}
}

func (d *MDNS) Option(ctx context.Context) func(c *libp2p.Config) error {
	return func(*libp2p.Config) error { return nil }
}

func (d *MDNS) Run(l *zap.Logger, ctx context.Context, host host.Host) error {

	// setup mDNS discovery to find local peers
	disc := mdns.NewMdnsService(host, d.DiscoveryServiceTag)

	n := discoveryNotifee{h: host, c: l}
	disc.RegisterNotifee(&n)
	return nil
}
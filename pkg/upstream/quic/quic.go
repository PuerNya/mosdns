package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"

	"github.com/IrineSistiana/mosdns/v4/pkg/dnsutils"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type Upstream struct {
	conn       *quic.Conn
	early      bool
	addr       string
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	sync.Mutex
}

func NewQUICUpstream(addr string, early bool, tlsConfig *tls.Config, quicConfig *quic.Config) *Upstream {
	return &Upstream{
		early:      early,
		addr:       addr,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
	}
}

func (h *Upstream) offer(ctx context.Context) (*quic.Conn, error) {
	h.Lock()
	if h.conn != nil {
		conn := h.conn
		h.Unlock()
		select {
		case <-conn.Context().Done():
		default:
		}
		return conn, nil
	}
	h.Unlock()
	h.Lock()
	if h.conn != nil {
		conn := h.conn
		h.Unlock()
		select {
		case <-conn.Context().Done():
		default:
		}
		return conn, nil
	}
	h.Unlock()
	return h.offerNew(ctx)
}

func (h *Upstream) offerNew(ctx context.Context) (*quic.Conn, error) {
	h.Lock()
	defer h.Unlock()
	var conn *quic.Conn
	var err error
	if h.early {
		conn, err = quic.DialAddrEarly(ctx, h.addr, h.tlsConfig, h.quicConfig)
	} else {
		conn, err = quic.DialAddr(ctx, h.addr, h.tlsConfig, h.quicConfig)
	}
	if err != nil {
		return nil, err
	}
	h.conn = conn
	return conn, nil
}

func (h *Upstream) Close() error {
	h.Lock()
	if h.conn == nil {
		h.Unlock()
		return nil
	}
	h.Unlock()
	h.Lock()
	conn := h.conn
	h.conn = nil
	h.Unlock()
	return conn.CloseWithError(0, quic.NoError.String())
}

func (h *Upstream) ExchangeContext(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	var err error
	for i := 0; i < 2; i++ {
		var conn *quic.Conn
		conn, err = h.offer(ctx)
		if err != nil {
			return nil, err
		}
		var stream *quic.Stream
		stream, err = conn.OpenStreamSync(ctx)
		if err != nil {
			if isQUICRetryError(err) {
				stream.Close()
				continue
			} else {
				stream.Close()
				return nil, err
			}
		}
		id := m.MsgHdr.Id
		m.MsgHdr.Id = 0
		_, err = dnsutils.WriteMsgToTCP(stream, m)
		if err != nil {
			stream.Close()
			return nil, err
		}
		stream.Close()
		var resp *dns.Msg
		resp, _, err = dnsutils.ReadMsgFromTCP(stream)
		if err != nil {
			return nil, err
		}
		resp.MsgHdr.Id = id
		return resp, nil
	}
	return nil, err
}

// https://github.com/AdguardTeam/dnsproxy/blob/fd1868577652c639cce3da00e12ca548f421baf1/upstream/upstream_quic.go#L394
func isQUICRetryError(err error) (ok bool) {
	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) && qAppErr.ErrorCode == 0 {
		return true
	}

	var qIdleErr *quic.IdleTimeoutError
	if errors.As(err, &qIdleErr) {
		return true
	}

	var resetErr *quic.StatelessResetError
	if errors.As(err, &resetErr) {
		return true
	}

	var qTransportError *quic.TransportError
	if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError {
		return true
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		return true
	}

	return false
}

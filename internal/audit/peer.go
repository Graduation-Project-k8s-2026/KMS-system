package audit

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"syscall"
)

type peerKey struct{}

func PeerContext(ctx context.Context, c net.Conn) context.Context {
	u, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, e := u.SyscallConn()
	if e != nil {
		return ctx
	}
	var cred *syscall.Ucred
	raw.Control(func(fd uintptr) { cred, e = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) })
	if e != nil || cred == nil {
		return ctx
	}
	return context.WithValue(ctx, peerKey{}, "uid:"+strconv.FormatUint(uint64(cred.Uid), 10))
}
func PeerSubject(r *http.Request) string {
	if value, ok := r.Context().Value(peerKey{}).(string); ok {
		return value
	}
	return "unknown-peer"
}

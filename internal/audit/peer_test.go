package audit

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestUnixPeerCannotBeOverriddenByIdentityHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ConnContext: PeerContext, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, PeerSubject(r)) })}
	go srv.Serve(listener)
	defer srv.Close()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest("GET", "http://local/", nil)
	req.Header.Set("Tailscale-User-Login", "forged@example.test")
	res, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "uid:"+strconv.Itoa(os.Getuid()) {
		t.Fatal("UDS subject did not use SO_PEERCRED")
	}
}

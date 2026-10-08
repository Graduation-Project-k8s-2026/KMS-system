package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"
)

// 값의 출처 표시.
const (
	SourceMetrics = "metrics"
	SourceSocket  = "socket"
)

// Sources는 Status의 각 값이 어디서 왔는지 알려준다. 값을 얻지 못했으면 null.
type Sources struct {
	Sealed      *string `json:"sealed"`
	Keys        *string `json:"keys"`
	KeyVersions *string `json:"key_versions"`
	LastUnseal  *string `json:"last_unseal"`
}

// Status는 GET /api/dashboard/status의 응답이다.
type Status struct {
	Sealed      *bool           `json:"sealed"`
	Keys        *int            `json:"keys"`
	KeyVersions *int            `json:"key_versions"`
	LastUnseal  *time.Time      `json:"last_unseal"`
	Sources     Sources         `json:"sources"`
	Metrics     CollectorStatus `json:"metrics"`
}

func strp(s string) *string { return &s }

// buildStatus는 수집기가 정상이면 최신 메트릭 샘플로, 꺼졌거나 실패 중이면
// admin.sock(seal-status, keys 목록)으로 상태를 채운다. 소켓으로는
// key_versions와 last_unseal을 알 수 없으므로 그 경우 null이다.
// 키 이름은 개수만 세고 응답에 담지 않는다.
func buildStatus(ctx context.Context, col *Collector, sock *socketClient) Status {
	st := Status{Metrics: col.Status()}

	if s, ok := col.Latest(); ok && s.Sealed != nil {
		sealed := *s.Sealed != 0
		st.Sealed = &sealed
		st.Sources.Sealed = strp(SourceMetrics)
		if s.Keys != nil {
			n := int(*s.Keys)
			st.Keys = &n
			st.Sources.Keys = strp(SourceMetrics)
		}
		if s.KeyVersions != nil {
			n := int(*s.KeyVersions)
			st.KeyVersions = &n
			st.Sources.KeyVersions = strp(SourceMetrics)
		}
		if s.LastUnseal != nil {
			st.Sources.LastUnseal = strp(SourceMetrics)
			if *s.LastUnseal > 0 { // 0 = 한 번도 unseal이 관측되지 않음
				t := time.Unix(int64(*s.LastUnseal), 0).UTC()
				st.LastUnseal = &t
			}
		}
		return st
	}

	if sock == nil {
		return st
	}
	if sealed, err := sock.sealed(ctx); err == nil {
		st.Sealed = &sealed
		st.Sources.Sealed = strp(SourceSocket)
		if !sealed { // sealed 상태에서는 /v1/keys가 503이다
			if n, err := sock.keyCount(ctx); err == nil {
				st.Keys = &n
				st.Sources.Keys = strp(SourceSocket)
			}
		}
	}
	return st
}

// socketClient는 admin.sock을 직접 호출하는 작은 HTTP 클라이언트다.
type socketClient struct {
	client *http.Client
}

func newSocketClient(path string) *socketClient {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}
	return &socketClient{client: &http.Client{
		Transport: &http.Transport{DialContext: dial},
		Timeout:   3 * time.Second,
	}}
}

func (c *socketClient) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://admin.sock"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return &statusError{code: resp.StatusCode}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

type statusError struct{ code int }

func (e *statusError) Error() string { return "admin socket returned HTTP " + http.StatusText(e.code) }

func (c *socketClient) sealed(ctx context.Context) (bool, error) {
	var r struct {
		Sealed bool `json:"sealed"`
	}
	if err := c.getJSON(ctx, "/v1/sys/seal-status", &r); err != nil {
		return false, err
	}
	return r.Sealed, nil
}

func (c *socketClient) keyCount(ctx context.Context) (int, error) {
	var r struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := c.getJSON(ctx, "/v1/keys", &r); err != nil {
		return 0, err
	}
	return len(r.Keys), nil
}

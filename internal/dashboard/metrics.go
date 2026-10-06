// Package dashboard는 관리 API의 운영·성능 대시보드를 구현한다.
//
//   - KMS의 /metrics를 주기적으로 긁어(Collector) 메모리 링 버퍼에 쌓고,
//     카운터 차이와 히스토그램 버킷 차이로 초당 값·백분위를 계산한다.
//   - cmd/bench가 만든 JSON 결과를 받아 디렉터리에 저장·조회·삭제한다
//     (BenchStore).
//   - 위 둘을 JSON API와 정적 화면(/dashboard)으로 노출한다(Service).
//
// Prometheus 서버에는 의존하지 않는다. KMS 서버 쪽은 아무것도 바꾸지
// 않으며, 이미 노출 중인 메트릭만 읽는다.
package dashboard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// 대시보드가 읽는 메트릭 이름. internal/metrics의 정의와 일치해야 한다.
const (
	mSealed       = "kms_seal_sealed"
	mLastUnseal   = "kms_seal_last_unsealed_timestamp_seconds"
	mKeys         = "kms_keys_total"
	mKeyVersions  = "kms_key_versions_total"
	mTransitReq   = "kms_transit_requests_total"
	mTransitDur   = "kms_transit_request_duration_seconds"
	mCacheReq     = "kms_authz_cache_requests_total"
	mSARDur       = "kms_authz_sar_duration_seconds"
	mAPIServerRTT = "kms_authz_apiserver_roundtrip_seconds"
)

// maxMetricsBody: /metrics 응답 크기 상한. 정상 응답은 수십 KB 수준이다.
const maxMetricsBody = 8 << 20

// bucket은 누적 히스토그램 버킷 하나다. +Inf 버킷은 따로 두지 않고
// histSample.Count가 대신한다.
type bucket struct {
	Upper float64
	Cum   float64
}

// histSample은 히스토그램 하나의 한 시점 값이다.
type histSample struct {
	Buckets []bucket
	Count   float64
	Sum     float64
}

// opSample은 Transit 작업(encrypt/decrypt/rewrap) 하나의 한 시점 값이다.
type opSample struct {
	Success float64
	Error   float64
	Dur     histSample
}

// authzSample은 인가 관련 메트릭의 한 시점 값이다. 인가를 쓰지 않는
// 서버에서는 Sample.Authz가 nil이다.
type authzSample struct {
	CacheHit  float64
	CacheMiss float64
	SAR       histSample
	RTT       histSample
}

// Sample은 한 번 수집한 /metrics에서 대시보드가 쓰는 값만 추려 둔 것이다.
// 포인터 필드는 "그 메트릭이 응답에 없었음"을 nil로 나타낸다.
type Sample struct {
	At          time.Time
	Sealed      *float64
	Keys        *float64
	KeyVersions *float64
	LastUnseal  *float64
	Ops         map[string]*opSample
	Authz       *authzSample
}

// parseSample은 Prometheus 텍스트 포맷을 expfmt로 파싱해 Sample로 만든다.
func parseSample(r io.Reader, at time.Time) (Sample, error) {
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(r)
	if err != nil {
		return Sample{}, fmt.Errorf("parse metrics: %w", err)
	}
	s := Sample{At: at, Ops: map[string]*opSample{}}

	s.Sealed = gaugeValue(families[mSealed])
	s.Keys = gaugeValue(families[mKeys])
	s.KeyVersions = gaugeValue(families[mKeyVersions])
	s.LastUnseal = gaugeValue(families[mLastUnseal])

	if fam := families[mTransitReq]; fam != nil {
		for _, m := range fam.Metric {
			op := labelValue(m, "operation")
			if op == "" || m.Counter == nil {
				continue
			}
			o := opFor(s.Ops, op)
			switch labelValue(m, "result") {
			case "success":
				o.Success += m.Counter.GetValue()
			case "error":
				o.Error += m.Counter.GetValue()
			}
		}
	}
	if fam := families[mTransitDur]; fam != nil {
		for _, m := range fam.Metric {
			op := labelValue(m, "operation")
			if op == "" || m.Histogram == nil {
				continue
			}
			opFor(s.Ops, op).Dur = toHist(m.Histogram)
		}
	}

	// 인가 메트릭: 히스토그램은 인가를 꺼도 0으로 노출되므로 "존재"만으로는
	// 인가 사용 여부를 알 수 없다. 한 번이라도 관측된 경우에만 Authz를 채운다.
	az := &authzSample{}
	if fam := families[mCacheReq]; fam != nil {
		for _, m := range fam.Metric {
			if m.Counter == nil {
				continue
			}
			switch labelValue(m, "result") {
			case "hit":
				az.CacheHit += m.Counter.GetValue()
			case "miss":
				az.CacheMiss += m.Counter.GetValue()
			}
		}
	}
	if h := firstHistogram(families[mSARDur]); h != nil {
		az.SAR = toHist(h)
	}
	if h := firstHistogram(families[mAPIServerRTT]); h != nil {
		az.RTT = toHist(h)
	}
	if az.CacheHit+az.CacheMiss > 0 || az.SAR.Count > 0 {
		s.Authz = az
	}
	return s, nil
}

func opFor(ops map[string]*opSample, op string) *opSample {
	o := ops[op]
	if o == nil {
		o = &opSample{}
		ops[op] = o
	}
	return o
}

func gaugeValue(f *dto.MetricFamily) *float64 {
	if f == nil || len(f.Metric) == 0 || f.Metric[0].Gauge == nil {
		return nil
	}
	v := f.Metric[0].Gauge.GetValue()
	return &v
}

func firstHistogram(f *dto.MetricFamily) *dto.Histogram {
	if f == nil || len(f.Metric) == 0 {
		return nil
	}
	return f.Metric[0].Histogram
}

func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.Label {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

func toHist(h *dto.Histogram) histSample {
	out := histSample{Count: float64(h.GetSampleCount()), Sum: h.GetSampleSum()}
	for _, b := range h.Bucket {
		if math.IsInf(b.GetUpperBound(), 1) {
			continue // +Inf 버킷은 Count가 대신한다
		}
		out.Buckets = append(out.Buckets, bucket{Upper: b.GetUpperBound(), Cum: float64(b.GetCumulativeCount())})
	}
	sort.Slice(out.Buckets, func(i, j int) bool { return out.Buckets[i].Upper < out.Buckets[j].Upper })
	return out
}

// CollectorStatus는 수집기의 현재 상태 스냅샷이다(JSON 응답용).
type CollectorStatus struct {
	Enabled         bool       `json:"enabled"`
	OK              bool       `json:"ok"`
	LastSuccess     *time.Time `json:"last_success"`
	LastError       *string    `json:"last_error"`
	IntervalSeconds int        `json:"interval_seconds"`
	Samples         int        `json:"samples"`
}

// Collector는 KMS /metrics를 주기적으로 수집해 링 버퍼에 보관한다.
// 수집이 실패해도 멈추지 않고 다음 주기에 다시 시도한다.
type Collector struct {
	url      string
	interval time.Duration
	capacity int
	client   *http.Client

	mu          sync.RWMutex
	samples     []Sample
	ok          bool
	lastSuccess time.Time
	lastErr     string
}

// NewCollector는 url이 빈 문자열이면 수집을 끈 수집기를 만든다.
// window는 보관할 시간 길이다.
func NewCollector(url string, interval, window time.Duration, client *http.Client) *Collector {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if window < interval {
		window = interval
	}
	if client == nil {
		timeout := interval
		if timeout > 10*time.Second {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	return &Collector{
		url:      url,
		interval: interval,
		capacity: int(window/interval) + 1,
		client:   client,
	}
}

// Enabled는 수집이 켜져 있는지 알려준다.
func (c *Collector) Enabled() bool { return c.url != "" }

// Window는 링 버퍼가 보관하는 최대 시간 길이다.
func (c *Collector) Window() time.Duration {
	return time.Duration(c.capacity-1) * c.interval
}

// Run은 ctx가 끝날 때까지 interval마다 수집한다. 첫 수집은 즉시 한다.
func (c *Collector) Run(ctx context.Context) {
	if !c.Enabled() {
		return
	}
	wasOK := true
	tick := func() {
		err := c.ScrapeOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		// 상태가 바뀔 때만 로그를 남긴다 — 실패가 계속돼도 5초마다 쏟아지지 않게.
		switch {
		case err != nil && wasOK:
			log.Printf("dashboard: metrics scrape failed (will keep retrying): %v", err)
		case err == nil && !wasOK:
			log.Print("dashboard: metrics scrape recovered")
		}
		wasOK = err == nil
	}
	tick()
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// ScrapeOnce는 /metrics를 한 번 가져와 파싱하고 링 버퍼에 추가한다.
// 실패하면 상태에 사유를 기록하고 오류를 반환한다 — 버퍼는 그대로 둔다.
func (c *Collector) ScrapeOnce(ctx context.Context) error {
	s, err := c.fetch(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.ok = false
		c.lastErr = err.Error()
		return err
	}
	c.ok = true
	c.lastErr = ""
	c.lastSuccess = s.At
	c.samples = append(c.samples, s)
	if len(c.samples) > c.capacity {
		c.samples = append([]Sample(nil), c.samples[len(c.samples)-c.capacity:]...)
	}
	return nil
}

func (c *Collector) fetch(ctx context.Context) (Sample, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return Sample{}, err
	}
	req.Header.Set("Accept", "text/plain;version=0.0.4")
	resp, err := c.client.Do(req)
	if err != nil {
		return Sample{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Sample{}, fmt.Errorf("metrics endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetricsBody+1))
	if err != nil {
		return Sample{}, err
	}
	if len(body) > maxMetricsBody {
		return Sample{}, errors.New("metrics response too large")
	}
	return parseSample(bytes.NewReader(body), time.Now())
}

// Status는 현재 수집 상태를 반환한다.
func (c *Collector) Status() CollectorStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	st := CollectorStatus{
		Enabled:         c.Enabled(),
		OK:              c.ok,
		IntervalSeconds: int(c.interval / time.Second),
		Samples:         len(c.samples),
	}
	if !c.lastSuccess.IsZero() {
		t := c.lastSuccess
		st.LastSuccess = &t
	}
	if c.lastErr != "" {
		e := c.lastErr
		st.LastError = &e
	}
	return st
}

// Latest는 가장 최근 샘플을 반환한다. 마지막 수집이 성공 상태일 때만
// 유효하다(실패 중이면 ok=false).
func (c *Collector) Latest() (Sample, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.ok || len(c.samples) == 0 {
		return Sample{}, false
	}
	return c.samples[len(c.samples)-1], true
}

// Window 안의 샘플을 시간순으로 복사해 반환한다. now 기준 window 이내만.
func (c *Collector) samplesSince(cutoff time.Time) []Sample {
	c.mu.RLock()
	defer c.mu.RUnlock()
	i := sort.Search(len(c.samples), func(i int) bool { return !c.samples[i].At.Before(cutoff) })
	return append([]Sample(nil), c.samples[i:]...)
}

package dashboard

import (
	"math"
	"time"
)

// Ops: 대시보드가 보여주는 Transit 작업. 응답 키 순서·집합을 고정한다.
var transitOps = []string{"encrypt", "decrypt", "rewrap"}

// OpSeries는 작업 하나의 시계열이다. 모든 배열은 Traffic.T와 길이가 같고,
// 계산할 수 없는 지점(요청 없음, 카운터 리셋 등)은 null이다.
type OpSeries struct {
	RPS       []*float64 `json:"rps"`
	ErrorRate []*float64 `json:"error_rate"`
	P50ms     []*float64 `json:"p50_ms"`
	P99ms     []*float64 `json:"p99_ms"`
}

// AuthzSeries는 인가 관련 시계열이다.
type AuthzSeries struct {
	CacheHitRatio     []*float64 `json:"cache_hit_ratio"`
	SARRPS            []*float64 `json:"sar_rps"`
	SARAvgMs          []*float64 `json:"sar_avg_ms"`
	APIServerRTTAvgMs []*float64 `json:"apiserver_rtt_avg_ms"`
	// ClientWaitAvgMs = SAR 평균 - apiserver 왕복 평균 (rate limiter 등 클라이언트 대기).
	ClientWaitAvgMs []*float64 `json:"client_wait_avg_ms"`
}

// Traffic은 GET /api/dashboard/traffic의 응답이다.
type Traffic struct {
	WindowSeconds int                  `json:"window_seconds"`
	StepSeconds   int                  `json:"step_seconds"`
	T             []int64              `json:"t"`
	Ops           map[string]*OpSeries `json:"ops"`
	Authz         *AuthzSeries         `json:"authz"`
}

// computeTraffic은 시간순 샘플에서 인접한 두 샘플의 차이로 시계열을 만든다.
// 시계열의 각 점은 (이전 샘플, 이 샘플) 구간을 뜻하고 시각은 이 샘플의 것이다.
func computeTraffic(samples []Sample, window, step time.Duration) Traffic {
	tr := Traffic{
		WindowSeconds: int(window / time.Second),
		StepSeconds:   int(step / time.Second),
		T:             []int64{},
		Ops:           map[string]*OpSeries{},
	}

	n := 0
	if len(samples) > 1 {
		n = len(samples) - 1
	}
	for i := 1; i <= n; i++ {
		tr.T = append(tr.T, samples[i].At.Unix())
	}

	for _, op := range transitOps {
		seen := false
		for _, s := range samples {
			if s.Ops[op] != nil {
				seen = true
				break
			}
		}
		if !seen {
			tr.Ops[op] = nil
			continue
		}
		ser := &OpSeries{RPS: []*float64{}, ErrorRate: []*float64{}, P50ms: []*float64{}, P99ms: []*float64{}}
		for i := 1; i <= n; i++ {
			prev, cur := samples[i-1].Ops[op], samples[i].Ops[op]
			dt := samples[i].At.Sub(samples[i-1].At).Seconds()
			if prev == nil || cur == nil || dt <= 0 {
				ser.RPS = append(ser.RPS, nil)
				ser.ErrorRate = append(ser.ErrorRate, nil)
				ser.P50ms = append(ser.P50ms, nil)
				ser.P99ms = append(ser.P99ms, nil)
				continue
			}
			dOK, dErr := cur.Success-prev.Success, cur.Error-prev.Error
			if dOK < 0 || dErr < 0 { // 카운터 리셋(서버 재시작)
				ser.RPS = append(ser.RPS, nil)
				ser.ErrorRate = append(ser.ErrorRate, nil)
			} else {
				ser.RPS = append(ser.RPS, fp((dOK+dErr)/dt))
				if dOK+dErr > 0 {
					ser.ErrorRate = append(ser.ErrorRate, fp(dErr/(dOK+dErr)))
				} else {
					ser.ErrorRate = append(ser.ErrorRate, nil)
				}
			}
			ser.P50ms = append(ser.P50ms, quantileMs(0.50, prev.Dur, cur.Dur))
			ser.P99ms = append(ser.P99ms, quantileMs(0.99, prev.Dur, cur.Dur))
		}
		tr.Ops[op] = ser
	}

	if n > 0 && samples[len(samples)-1].Authz != nil {
		az := &AuthzSeries{
			CacheHitRatio: []*float64{}, SARRPS: []*float64{}, SARAvgMs: []*float64{},
			APIServerRTTAvgMs: []*float64{}, ClientWaitAvgMs: []*float64{},
		}
		for i := 1; i <= n; i++ {
			prev, cur := samples[i-1].Authz, samples[i].Authz
			dt := samples[i].At.Sub(samples[i-1].At).Seconds()
			if prev == nil || cur == nil || dt <= 0 {
				az.CacheHitRatio = append(az.CacheHitRatio, nil)
				az.SARRPS = append(az.SARRPS, nil)
				az.SARAvgMs = append(az.SARAvgMs, nil)
				az.APIServerRTTAvgMs = append(az.APIServerRTTAvgMs, nil)
				az.ClientWaitAvgMs = append(az.ClientWaitAvgMs, nil)
				continue
			}
			dHit, dMiss := cur.CacheHit-prev.CacheHit, cur.CacheMiss-prev.CacheMiss
			if dHit >= 0 && dMiss >= 0 && dHit+dMiss > 0 {
				az.CacheHitRatio = append(az.CacheHitRatio, fp(dHit/(dHit+dMiss)))
			} else {
				az.CacheHitRatio = append(az.CacheHitRatio, nil)
			}
			if dSAR := cur.SAR.Count - prev.SAR.Count; dSAR >= 0 {
				az.SARRPS = append(az.SARRPS, fp(dSAR/dt))
			} else {
				az.SARRPS = append(az.SARRPS, nil)
			}
			sar := avgMs(prev.SAR, cur.SAR)
			rtt := avgMs(prev.RTT, cur.RTT)
			az.SARAvgMs = append(az.SARAvgMs, sar)
			az.APIServerRTTAvgMs = append(az.APIServerRTTAvgMs, rtt)
			if sar != nil && rtt != nil {
				az.ClientWaitAvgMs = append(az.ClientWaitAvgMs, fp(*sar-*rtt))
			} else {
				az.ClientWaitAvgMs = append(az.ClientWaitAvgMs, nil)
			}
		}
		tr.Authz = az
	}
	return tr
}

// avgMs는 두 시점 사이 관측값의 평균(ms)이다. 관측이 없으면 nil.
func avgMs(prev, cur histSample) *float64 {
	dc, ds := cur.Count-prev.Count, cur.Sum-prev.Sum
	if dc <= 0 || ds < 0 {
		return nil
	}
	return fp(ds / dc * 1e3)
}

// quantileMs는 두 시점 사이에 새로 관측된 값들의 q 분위수(ms)를 버킷
// 증가분으로 추정한다(버킷 안에서는 선형 보간, Prometheus의
// histogram_quantile과 같은 방식). 관측이 없거나 버킷이 달라졌으면 nil.
func quantileMs(q float64, prev, cur histSample) *float64 {
	if len(prev.Buckets) == 0 || len(prev.Buckets) != len(cur.Buckets) {
		return nil
	}
	total := cur.Count - prev.Count
	if total <= 0 {
		return nil
	}
	d := make([]float64, len(cur.Buckets))
	for i := range cur.Buckets {
		if cur.Buckets[i].Upper != prev.Buckets[i].Upper {
			return nil
		}
		d[i] = cur.Buckets[i].Cum - prev.Buckets[i].Cum
		if d[i] < 0 {
			return nil // 리셋
		}
	}
	rank := q * total
	for i, b := range cur.Buckets {
		if d[i] < rank {
			continue
		}
		lower, lowerCum := 0.0, 0.0
		if i > 0 {
			lower, lowerCum = cur.Buckets[i-1].Upper, d[i-1]
		}
		if d[i] == lowerCum {
			return fp(b.Upper * 1e3)
		}
		return fp((lower + (b.Upper-lower)*(rank-lowerCum)/(d[i]-lowerCum)) * 1e3)
	}
	// 마지막 유한 버킷보다 큰 값(+Inf 버킷)은 상한을 알 수 없어 마지막 경계로 대신한다.
	return fp(cur.Buckets[len(cur.Buckets)-1].Upper * 1e3)
}

func fp(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	return &v
}

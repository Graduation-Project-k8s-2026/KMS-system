// Package bench은 cmd/bench가 쓰는 측정 로직(HTTP 클라이언트, worker pool
// 실행기, 백분위 집계, 결과 포맷)을 담는다. 이 패키지는 KMS를 **외부에서
// HTTP로 호출하는 클라이언트**일 뿐이다 — KMS 코어/API/인증·인가/메트릭
// 패키지를 임포트하지 않는다. 서버가 실제로 받는 요청/응답 JSON 형식과
// 일치하는 최소한의 구조체를 이 패키지 안에 독립적으로 정의해 쓴다.
package bench

import (
	"math"
	"sort"
	"time"
)

// LatencyStats는 지연 시간 샘플 하나의 집계 결과다. 전량을 보관했다가
// 정렬해 백분위를 정확히 계산한다 — 이 도구가 실제로 다루는 샘플 수(한
// 실행당 많아야 수백만 개)에서는 time.Duration 슬라이스를 통째로 들고
// 있어도 메모리 비용이 무시할 만한 수준이고(샘플 100만 개 = 8MB),
// HDR 히스토그램 같은 근사 알고리즘을 들여올 이유가 없다.
type LatencyStats struct {
	Count              int
	Min, Max, Mean     time.Duration
	P50, P90, P95, P99 time.Duration
}

// ComputeLatencyStats는 samples(성공한 요청의 지연 시간만)를 정렬해
// 최소/최대/평균/p50/p90/p95/p99를 계산한다. 백분위는 최근접 순위
// (nearest-rank) 방식을 쓴다: 정렬된 n개 샘플에서 p번째 백분위의 인덱스는
// ceil(p/100*n)-1이다. samples가 비어있으면(모든 요청이 실패한 경우)
// 전부 0인 LatencyStats를 반환한다 — 호출부가 Count==0으로 "유효한
// 지연 데이터 없음"을 판별할 수 있다.
func ComputeLatencyStats(samples []time.Duration) LatencyStats {
	n := len(samples)
	if n == 0 {
		return LatencyStats{}
	}

	sorted := make([]time.Duration, n)
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var sum time.Duration
	for _, s := range sorted {
		sum += s
	}

	percentile := func(p float64) time.Duration {
		idx := int(math.Ceil(p/100*float64(n))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= n {
			idx = n - 1
		}
		return sorted[idx]
	}

	return LatencyStats{
		Count: n,
		Min:   sorted[0],
		Max:   sorted[n-1],
		Mean:  sum / time.Duration(n),
		P50:   percentile(50),
		P90:   percentile(90),
		P95:   percentile(95),
		P99:   percentile(99),
	}
}

// OpsPerSec는 성공한 요청 수를 wall(측정에 걸린 실제 시간)로 나눈
// 처리량이다. wall이 0 이하이면(비정상 상황) 0을 반환한다.
func OpsPerSec(successCount int, wall time.Duration) float64 {
	if wall <= 0 {
		return 0
	}
	return float64(successCount) / wall.Seconds()
}

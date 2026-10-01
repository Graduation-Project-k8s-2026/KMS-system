# 성능 측정 도구 (cmd/bench)

`internal/metrics`(Prometheus)가 "운영 중 무슨 일이 일어났는가"를 수동적으로
기록한다면, `cmd/bench`는 **인위적으로 부하를 걸어 조건을 통제한 상태에서
측정**하는 도구다. 논문 성능 평가에 쓸 데이터를 만드는 것이 목적이다.

이 도구는 Transit API(`:8200`)만 HTTP로 호출하는 **외부 클라이언트**다.
Admin 평면(유닉스 소켓)에는 접근하지 않고, 서버 설정을 바꾸거나 키를 만들지
않는다 — 측정 대상 상태를 건드리지 않는 것이 이 도구의 기본 원칙이다.

현재는 로컬 실행 CLI까지만 만들었다. 쿠버네티스 Job으로 포장해 관리
대시보드에서 실행·조회하는 것은 이후 과제다("향후 계획" 절 참고).

---

## 빠른 시작

KMS 서버가 떠 있고(unseal 완료) 측정할 키가 이미 만들어져 있어야 한다 —
`bench`는 키를 만들지 않는다:

```bash
# (별도 터미널에서 서버 기동 후) 키 준비
curl --unix-socket /var/run/kms/admin.sock -XPOST http://localhost/v1/keys \
  -H 'content-type: application/json' -d '{"name":"bench-demo"}'

# 기본 처리량·지연 측정
go run ./cmd/bench --key bench-demo
```

```
OPERATION  PAYLOAD  CONC  OPS/SEC   P50     P90     P95     P99     MAX     ERRORS
encrypt    1KB      1     7020.8    0.12ms  0.15ms  0.16ms  0.30ms  0.30ms  0
decrypt    1KB      1     6564.5    0.13ms  0.16ms  0.21ms  0.40ms  0.40ms  0
rewrap     1KB      1     6149.6    0.14ms  0.17ms  0.25ms  0.44ms  0.44ms  0
```

---

## 측정 시나리오

`--scenario`로 고른다.

| 시나리오 | 훑는 축 | 고정값 |
|---|---|---|
| `basic`(기본값) | operation (`--op`) | payload=`--payload`, concurrency=`--concurrency` |
| `payload` | payload 크기 (`--payload-sizes`) | concurrency=`--concurrency` |
| `concurrency` | 동시성 수준 (`--concurrency-levels`) | payload=`--payload` |
| `all` | 위 세 가지를 basic → payload → concurrency 순서로 전부 | — |

각 시나리오는 선택된 `--op`(encrypt/decrypt/rewrap/all) 전부에 대해 반복된다.

---

## 플래그

| 플래그 | 기본값 | 설명 |
|---|---|---|
| `--addr` | `http://localhost:8200` | Transit API 주소 |
| `--key` | (필수) | 측정할 키 이름. 없으면 명확한 에러로 중단 — 만들어주지 않는다 |
| `--scenario` | `basic` | `basic`\|`payload`\|`concurrency`\|`all` |
| `--op` | `all` | `encrypt`\|`decrypt`\|`rewrap`\|`all` |
| `--count` | `1000` | 측정 한 칸(run)당 요청 수. `--duration`이 0보다 크면 무시됨 |
| `--duration` | `0`(비활성) | 설정하면 `--count` 대신 이 시간만큼 측정(예: `10s`) |
| `--concurrency` | `1` | `basic`/`payload` 시나리오가 쓰는 고정 동시성 |
| `--concurrency-levels` | `1,10,50,100` | `concurrency` 시나리오가 훑는 동시성 집합 |
| `--payload` | `1KB` | `basic`/`concurrency` 시나리오가 쓰는 고정 페이로드 크기 |
| `--payload-sizes` | `1KB,10KB,100KB,1MB` | `payload` 시나리오가 훑는 페이로드 크기 집합 |
| `--warmup` | `20` | 측정 전 버리는 요청 수. decrypt/rewrap은 이 중 암호화 결과를 암호문 풀로 재사용하므로 **1 이상이어야 함**(0이면 에러) |
| `--token` | (없음) | Bearer 토큰 직접 지정 (`--token-file`과 동시 사용 불가) |
| `--token-file` | (없음) | 토큰이 든 파일 경로 (내용 앞뒤 공백 제거) |
| `--label` | (없음) | 결과에 붙일 조건 라벨 (예: `authz-cached`) — 접근 제어 비교 실험에 필수 |
| `--format` | `table` | `table`\|`json` |
| `--output` | (stdout) | 결과를 쓸 파일 경로 |
| `--keepalive` | `true` | HTTP 커넥션 재사용 여부. `false`로 끄면 매 요청 새 커넥션 비용을 포함해 측정(비교용) |
| `--timeout` | `30s` | 요청 하나의 HTTP 타임아웃 (안전장치) |

크기 표현(`--payload`, `--payload-sizes`)은 `512B`/`1KB`/`10MB`처럼 쓰거나
단위 없이 바이트 수만 써도 된다. 1KB=1024바이트(이진 단위) 기준이다.

---

## 접근 제어 오버헤드 비교 실험 (논문 핵심 실험)

**이 도구는 서버를 재기동하지 않는다.** 서버 설정(`KMS_AUTHN`/`KMS_AUTHZ`)이
다른 네 조건을 비교하려면, 각 조건으로 서버를 따로 띄워가며 `bench`를 네 번
실행하고 `--label`로 조건을 표시한 뒤 결과를 나중에 합쳐서 비교한다.

| 조건 | 서버 환경변수 | `--label` |
|---|---|---|
| baseline | `KMS_AUTHN=off KMS_AUTHZ=off` | `baseline` |
| authn only | `KMS_AUTHN=on KMS_AUTHZ=off` | `authn-only` |
| authz cached | `KMS_AUTHN=on KMS_AUTHZ=on KMS_AUTHZ_CACHE_TTL=10` | `authz-cached` |
| authz uncached | `KMS_AUTHN=on KMS_AUTHZ=on KMS_AUTHZ_CACHE_TTL=-1` | `authz-uncached` |

> `KMS_AUTHZ_CACHE_TTL`은 초 단위 정수만 받는다(`10s`처럼 단위를 붙이면
> 기동이 실패한다). **음수를 주면 캐시가 완전히 비활성화**되어 매 요청마다
> apiserver에 SAR을 묻는다 — "uncached" 조건은 짧은 TTL로 흉내 내지 말고
> 이 값을 쓴다. `0`은 "설정 안 함"과 같은 뜻으로 기본값(10초)이 적용되므로
> uncached 조건에 실수로 `0`을 쓰지 않도록 주의한다.

절차:

```bash
# 조건마다: 서버를 그 설정으로 띄우고(터미널 1), 키를 만든 뒤(admin.sock),
# bench를 그 라벨로 실행한다(터미널 2).

# 1) baseline
KMS_AUTHN=off KMS_AUTHZ=off KMS_SEAL_TYPE=dev KMS_MASTER_KEY=x KMS_STORAGE=memory \
  go run ./cmd/server
# (다른 터미널) 키 생성 후:
go run ./cmd/bench --key bench-demo --label baseline --format json --output baseline.json

# 2) authn only — KMS_SA_PUBLIC_KEY 등 인증 설정 추가, bench에도 --token(-file) 필요
KMS_AUTHN=on KMS_AUTHZ=off ... go run ./cmd/server
go run ./cmd/bench --key bench-demo --token-file /path/to/token \
  --label authn-only --format json --output authn-only.json

# 3) authz cached
KMS_AUTHN=on KMS_AUTHZ=on KMS_AUTHZ_CACHE_TTL=10 ... go run ./cmd/server
go run ./cmd/bench --key bench-demo --token-file /path/to/token \
  --label authz-cached --format json --output authz-cached.json

# 4) authz uncached
KMS_AUTHN=on KMS_AUTHZ=on KMS_AUTHZ_CACHE_TTL=-1 ... go run ./cmd/server
go run ./cmd/bench --key bench-demo --token-file /path/to/token \
  --label authz-uncached --format json --output authz-uncached.json
```

네 JSON 파일의 같은 `operation`/`payload_bytes`/`concurrency` 조합끼리
`latency.p50_seconds` 등을 비교하면 각 단계(인증만 추가/인가 캐시 히트/인가
캐시 미스)가 더한 오버헤드를 분리해 볼 수 있다. authz uncached 쪽의 지연
상승분은 거의 그대로 `kms_authz_sar_duration_seconds`(Prometheus)가 보여주는
SAR 왕복 시간과 맞아떨어져야 한다 — 두 도구의 결과가 서로 교차 검증이 된다.

---

## 결과 해석

- **ops/sec**: 성공한 요청 수 ÷ 측정에 실제로 걸린 시간. 동시성을 올렸을 때
  거의 선형으로 늘지 않고 일찍 꺾이면, 그 지점이 서버(또는 같은 머신에서
  도구 자신)의 포화점이다.
- **p50 vs p99**: p50은 전형적인 경우, p99는 꼬리 지연(tail latency)이다.
  p99가 p50보다 훨씬 크면 GC, 캐시 미스, 커넥션 재수립 같은 산발적 비용이
  섞여 있다는 신호다.
- **payload 시나리오**: 봉투 암호화 구조상 지연이 페이로드 크기에 어느 정도
  비례할 것으로 예상된다 — 이 도구로 실측해 그 가정이 맞는지, 어느 크기부터
  네트워크/직렬화 비용이 AES-GCM 자체보다 커지는지 확인한다.
- **errors**: 0이 아니면 먼저 원인을 확인한다. JSON 출력의 `errors` 배열에
  샘플 메시지가(최대 5개) 들어있다. 동시성이 너무 높아 서버가 포화된 상태에서
  타임아웃이 늘어나는 것인지, 다른 문제인지 구분해야 지연 수치를 신뢰할 수
  있다.

---

## 측정 시 주의사항

- **워밍업이 필요한 이유**: 첫 요청들은 TCP 핸드셰이크, TLS(쓴다면), Go
  런타임 워밍업(GC, 스케줄러) 비용을 포함해 비정상적으로 느리다. `--warmup`
  (기본 20)만큼 버리고 측정해야 정상 상태(steady state)의 지연을 본다.
- **커넥션 재사용(`--keepalive`)**: 기본은 켜짐이다. 매 요청 새 커넥션을
  맺으면(`--keepalive=false`) 지연이 거의 전부 TCP 핸드셰이크 비용에
  지배되어 서버 처리 시간 자체를 가늠하기 어렵다. 반대로 이 비용 자체를
  보고 싶다면(예: 커넥션 풀링이 없는 호출자를 흉내) 꺼서 비교한다.
- **decrypt/rewrap의 암호문 풀**: 이 도구는 상태를 바꾸지 않으므로 측정용
  암호문을 매번 새로 만들지 않고 `--warmup`개만큼 미리 만들어 둔 풀을
  순환하며 재사용한다. AES-GCM 복호화 비용은 내용과 무관하므로 측정값에
  영향이 없다 — 다만 `--warmup`이 너무 작으면(예: 1) 모든 동시성 worker가
  같은 암호문 하나를 반복해서 두드리게 된다. 보통은 문제가 안 되지만, 서버
  쪽에 내용 기반 캐시가 추가되는 미래 변경이 있다면 재검토할 부분이다.
- **같은 머신에서 서버·클라이언트를 함께 돌릴 때의 한계**: 로컬에서
  `cmd/server`와 `cmd/bench`를 같은 머신(같은 CPU 코어 풀)에서 돌리면 둘이
  CPU를 다툰다 — 특히 동시성을 높이거나 페이로드가 클 때(클라이언트 쪽의
  난수 생성·JSON 직렬화·base64 인코딩도 공짜가 아니다) 측정값이 "서버가 얼마나
  빠른가"가 아니라 "이 머신이 둘을 합쳐 얼마나 처리할 수 있는가"에 가까워진다.
  신뢰할 수 있는 절대 수치가 필요하면 서버와 bench를 별도 머신(또는 별도
  파드)에서 돌려야 한다. 로컬 측정은 상대 비교(조건 A vs 조건 B, 이 저장소
  안에서의 회귀 확인)에는 여전히 유효하다.
- **플레인텍스트는 run마다 한 번만 생성**: AES-GCM 비용은 평문 내용과
  무관하므로, 요청마다 새로 난수를 만들지 않고 run 하나에 한 번만 만들어
  재사용한다 — 특히 큰 페이로드에서 난수 생성 자체가 클라이언트 CPU를
  잡아먹어 처리량을 왜곡하는 것을 막기 위함이다.

---

## 안전장치

- 측정 시작 전 1바이트짜리 `encrypt`를 한 번 호출해 서버 상태를 확인한다
  (seal-status는 Admin 평면이라 이 도구가 접근할 수 없다): `503`이면
  sealed로 판단해 중단, `404`면 키 없음으로 판단해 중단한다. 이 호출은
  서버에 아무 상태도 남기지 않는다.
- Ctrl+C(SIGINT)로 중단하면 그 즉시 요청을 그만 보내고, 아직 시작하지 않은
  나머지 run은 건너뛴 채 그때까지 모은 결과를 평소와 같은 형식으로
  출력한다 — 에러로 취급하지 않는다.

---

## 향후 계획

- 이 CLI를 쿠버네티스 Job으로 포장해, 관리 대시보드에서 실행하고 결과를
  조회할 수 있게 한다.
- 접근 제어 비교 실험(네 조건)을 대시보드에서 버튼 한 번으로 돌리고
  결과를 나란히 보여주는 것이 목표다.
- 이번 범위에는 포함하지 않는다: Job 매니페스트 작성, 대시보드 연동, 서버
  측 코드 수정.

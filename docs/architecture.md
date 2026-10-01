# 아키텍처

## 개요

이 KMS는 **Transit형**이다. 사용자 데이터를 저장하지 않고 암복호화 연산만 제공한다
(AWS KMS, GCP Cloud KMS, HashiCorp Vault transit engine과 동일한 모델).

서버는 하나의 코어 위에 여러 개의 입구를 둔다. 입구마다 노출 범위와 검문 수준이 다르다.

```
관리자 → :8201 (관리 API) → admin.sock ──┐
                                          ├→ [KMS 코어]
앱    → :8200 (Transit) → 인증 → 인가 ────┘       │
                           ↓      ↓               ↓
                        sa.pub   SAR          키 저장소
                                  ↓
                            kube-apiserver

Prometheus → :9100 /metrics
(추후) kube-apiserver → kms-v2.sock (gRPC)
```

---

## 키 계층

3단 구조로 봉투 암호화를 구성한다.

| 계층 | 역할 | 수명 | 저장 |
|---|---|---|---|
| Root Key | KEK를 암호화 | 프로세스 메모리에만 존재 | 저장 안 함 (seal이 보호) |
| KEK | 각 transit 키의 버전별 자료. DEK를 감쌈 | 회전 단위 | Root Key로 암호화되어 저장 |
| DEK | 실제 데이터 암호화 | 요청 1회용 | 저장 안 함 (암호문에 감싸져 전달) |

**회전과 버전 정책은 KEK 단위로 동작한다.** 키를 회전하면 새 KEK 버전이 추가되고,
기존 버전은 삭제되지 않아 옛 암호문을 계속 복호화할 수 있다.

### 암호문 포맷

```
kms:v1:<base64>
 │   │    └ 암호화된 데이터 + 감싸진 DEK + 부가정보
 │   └ 암호화에 사용된 KEK 버전
 └ 포맷 식별자
```

버전이 암호문에 내장되어 있어, 복호화 시 별도 메타데이터 없이 올바른 KEK 버전을 찾을 수 있다.

---

## 평면 분리

### Transit 평면 (TCP `:8200`)

네트워크로 열린다. 사용자 애플리케이션이 데이터 암복호화를 요청하는 경로.

| 엔드포인트 | 인증 | 인가 |
|---|---|---|
| `POST /v1/encrypt/{name}` | 필요 | 필요 |
| `POST /v1/decrypt/{name}` | 필요 | 필요 |
| `POST /v1/rewrap/{name}` | 필요 | 필요 |
| `GET /v1/sys/seal-profile` | 필요 | 불필요 |
| `GET /v1/sys/seal-benchmark` | 필요 | 불필요 |

`seal-profile`/`seal-benchmark`이 인가 대상에서 제외된 이유: 벤치마크 실행기가
특정 키 권한 없이 성능을 측정할 수 있어야 한다. 이들은 특정 키를 대상으로 하지 않는다.

### Admin 평면 (유닉스 소켓)

네트워크로 열지 않는다. 같은 노드의 관리 API만 접근한다.

| 엔드포인트 | 설명 |
|---|---|
| `POST /v1/sys/init` | 초기화 (seal 방식에 따라 조각 발급) |
| `POST /v1/sys/unseal` | 봉인 해제 |
| `GET /v1/sys/seal-status` | 봉인 상태 조회 |
| `POST /v1/keys` | 키 생성 |
| `GET /v1/keys` | 키 목록 |
| `GET /v1/keys/{name}` | 키 메타데이터 조회 (키 자료는 반환하지 않음) |
| `POST /v1/keys/{name}/rotate` | 키 회전 |
| `POST /v1/keys/{name}/config` | 정책 설정 (min_decryption_version, 자동 회전) |

**보호 수단**: 유닉스 도메인 소켓 + 파일 권한 `0600`.
인증 미들웨어를 적용하지 않는다. 네트워크로 닿을 수 없다는 것 자체가 경계다.

### Metrics 평면 (TCP `:9100`)

Prometheus 수집 전용. 인증 없음. 민감 정보(키 이름, 토큰, 주체)를 라벨에 포함하지 않는다.
네트워크 정책으로 접근을 제한해야 한다.

| 엔드포인트 | 인증 | 인가 |
|---|---|---|
| `GET /metrics` | 불필요 | 불필요 |

계측 위치는 코어 패키지를 건드리지 않는 쪽을 택했다: 암복호화 요청 수/지연/
payload 크기는 `internal/api/transit`의 미들웨어·핸들러에서, 인가(SAR/캐시)
지표는 `internal/authz`에서 직접 기록한다. seal 상태와 키/버전 현황은
상시 갱신하지 않고 `/metrics` 요청이 올 때마다 `internal/metrics.
SealKeyCollector`가 `barrier.IsSealed()`/`keys.ListKeys()`/`GetKeyMeta()`를
그대로 호출해 조회한다. 노출 지표 전체 목록과 버킷 설계 근거는
`README.md`의 "7. 메트릭(Prometheus)" 절 참고.

---

## 요청 경로

### 1. 앱이 자기 데이터를 암호화

```
앱 파드 → Service → :8200 → 인증 → 인가 → 코어 → 암호문 반환
```

앱은 키 자료를 전혀 모른다. 키 이름과 평문만 보내고 암호문을 받는다.

### 2. 관리자가 키를 관리

```
관리자 → :8201 (관리 API) → admin.sock → 코어
```

관리 API는 별도 프로세스다. 요청을 해석하지 않고 그대로 중계한다(투명 프록시).

### 3. 쿠버네티스가 Secret을 암호화 (구현 예정)

```
kube-apiserver → kms-v2.sock (gRPC) → 코어 → 암호문 → etcd
```

KMS는 etcd를 직접 건드리지 않는다. 암호문을 apiserver에 돌려주면 저장은 apiserver가 한다.

---

## 접근 제어

### 인증 — 로컬 JWT 서명 검증

ServiceAccount 토큰은 kube-apiserver가 서명한 JWT다.
컨트롤 플레인 노드의 서명 공개키(`/etc/kubernetes/pki/sa.pub`)로 서명을 로컬 검증한다.

apiserver의 TokenReview를 쓰지 않는 이유는 `docs/decisions.md` ADR-003 참고.

검증 항목: 서명, 만료(`exp`), 발급 시각(`iat`/`nbf`), issuer·audience(설정 시).
`alg: none`과 HMAC 알고리즘은 거부한다.

레거시 토큰(`sub: system:serviceaccount:<ns>:<name>`)과 projected 토큰
(`kubernetes.io` 클레임) 양쪽을 지원한다.

### 인가 — SubjectAccessReview

자체 정책 저장소를 두지 않는다. kube-apiserver에 SAR을 질의해 권한을 판단한다.

| KMS 개념 | RBAC 표현 |
|---|---|
| API 그룹 | `kms.local` |
| 리소스 | `keys` |
| 키 이름 | `resourceNames` |
| 동작 | verb: `encrypt`, `decrypt`, `rewrap` |
| 스코프 | 네임스페이스 (요청자 기준) |

`kms.local/keys`는 실제로 존재하는 쿠버네티스 리소스가 아니다.
SAR은 가상 리소스에 대한 질의도 허용하므로 이 방식이 성립한다.

**네임스페이스 스코프 주의**: 키 저장소에는 네임스페이스 개념이 없다.
키는 클러스터 전역 목록이며, 네임스페이스는 **권한 판단에만** 사용한다.
"team-a의 demo 키"가 따로 존재하는 것이 아니라,
"demo 키에 대한 team-a 소속 요청자의 권한"을 묻는 것이다.

**캐싱**: (주체, 네임스페이스, 키, verb) 단위로 짧은 TTL(기본 10초) 캐싱.
허용·거부 모두 캐싱한다. TTL이 짧아야 권한 회수 반영 지연이 제한된다.

**apiserver 장애 시**: fail-closed(거부)가 기본.
유효한 캐시 항목이 있으면 사용한다. 장애 시 내린 폴백 판단은 캐싱하지 않는다.

---

## 확장 지점

인터페이스로 분리되어 구현체 교체가 가능한 부분.

| 인터페이스 | 구현체 |
|---|---|
| `Seal` | dev, shamir, tpm, k8s |
| `StorageBackend` | memory, file |

---

## 배포 구조 (예정)

KMS 서버는 **static pod**로 컨트롤 플레인 노드에 배치한다.

이유:
- gRPC KMS Provider는 유닉스 소켓 통신이므로 apiserver와 같은 노드여야 한다
- static pod는 kubelet이 직접 띄우므로 apiserver보다 먼저 살아 있을 수 있다
  (KMS가 죽으면 apiserver가 Secret을 못 읽는 순환 문제 완화)

static pod의 제약:
- ServiceAccount 토큰이 자동 마운트되지 않는다 → kubeconfig를 hostPath로 제공
- ConfigMap/Secret/PVC를 참조할 수 없다 → 설정은 매니페스트에 직접, 저장소는 hostPath

필요한 마운트:

| 마운트 | 용도 |
|---|---|
| `/etc/kubernetes/pki/sa.pub` (ro) | 토큰 서명 검증 |
| kubeconfig 또는 전용 SA 토큰 | SAR 호출 자격 증명 |
| 키 저장소 디렉터리 | KEK·메타데이터 |
| `admin.sock` 디렉터리 | 관리 API와 공유 |
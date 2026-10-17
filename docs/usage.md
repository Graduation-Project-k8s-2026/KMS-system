# 사용법

README가 빠른 시작을 다룬다면, 이 문서는 **기능별 상세 사용법**을 다룬다.

---

## 실행 구성

서버는 두 프로세스로 나뉜다.

| 프로세스 | 역할 | 리스너 |
|---|---|---|
| `cmd/server` | KMS 본체 | Transit `:8200`, admin.sock, metrics `:9100` |
| `cmd/admin-api` | 관리 중계 + 웹 UI | HTTP `:8201` |

### 로컬 최소 실행

**터미널 1 — KMS 서버**
```bash
KMS_SEAL_TYPE=dev KMS_MASTER_KEY=change-me KMS_STORAGE=memory \
KMS_ADMIN_SOCKET=$HOME/kms-admin.sock \
go run ./cmd/server
```

**터미널 2 — 관리 API**
```bash
KMS_ADMIN_SOCKET=$HOME/kms-admin.sock \
go run ./cmd/admin-api
```

브라우저에서 `http://localhost:8201/console` 접속.

---

## 환경변수

### KMS 서버

| 변수 | 기본값 | 설명 |
|---|---|---|
| `KMS_SEAL_TYPE` | `dev` | 루트 키 보호 방식: `dev`\|`shamir`\|`tpm`\|`k8s` |
| `KMS_MASTER_KEY` | — | dev seal의 패스프레이즈 |
| `KMS_SHAMIR_PARTS` | 5 | shamir 조각 수 |
| `KMS_SHAMIR_THRESHOLD` | 3 | 복원에 필요한 조각 수 |
| `KMS_TPM_SIMULATOR` | false | TPM 시뮬레이터 사용 |
| `KMS_TPM_DEVICE` | `/dev/tpmrm0` | 실제 TPM 장치 경로 |
| `KMS_SEAL_ALLOWED` | `shamir,tpm` | 운영 서버의 허용 봉인 방식(실제 방식은 init 기록이 정함, ADR-010). **운영 배포 템플릿은 `shamir`** — 이때 `seal-migrate target=tpm`은 403 |
| `KMS_TRANSIT_AUDIT_DIR` | (비움=끔) | Transit 요청 비동기 감사 파일 디렉터리 (키 이름·주체·결과·지연; 본문 미기록) |
| `KMS_TRANSIT_AUDIT_BUFFER` | 8192 | 감사 버퍼 크기. 가득 차면 요청을 막지 않고 버리며 `kms_audit_dropped_total`이 오른다 |
| `KMS_TRANSIT_AUDIT_FSYNC_MS` | 1000 | 감사 fsync 주기(ms) |
| `KMS_EXTERNAL_ADDR` | (비움=끔) | 외부(인터넷 공개) 리스너 주소. 템플릿 기본 `0.0.0.0:9443` |
| `KMS_EXTERNAL_SUBJECT_NAMESPACES` | `kms-external` | 외부 리스너가 받는 요청자 SA의 네임스페이스(쉼표 목록) |
| `KMS_EXTERNAL_KEY_NAMESPACES` | `kms-external` | 외부 리스너가 받는 키 `<ns>.<name>`의 ns(쉼표 목록) |
| `KMS_EXTERNAL_RPS` / `KMS_EXTERNAL_BURST` | 20 / 40 | 클라이언트 IP별 초당 요청 수 / 버스트. 넘으면 429 `rate_limited` |
| `KMS_EXTERNAL_AUTHFAIL_MAX` | 10 | IP당 1분 내 인증 실패(401) 허용 횟수. 넘으면 5분 차단(429) |
| `KMS_PROTECTED_KEYS` | (비움) | 비활성화·삭제 예약을 거부할 키 목록(쉼표). KMS v2 키(`KMS_V2_KEY_NAME`)는 자동 보호 |
| `KMS_KEY_REAPER_INTERVAL_SEC` | 600 | 삭제 유예가 끝난 키를 점검하는 주기(초) |
| `KMS_STORAGE` | `file` | 저장 백엔드: `memory`\|`file` |
| `KMS_DATA_DIR` | `./data` | file 저장소 경로 |
| `KMS_TRANSIT_ADDR` | `:8200` | Transit 리스너 주소 (`PORT`도 하위호환 인식) |
| `KMS_ADMIN_SOCKET` | `/var/run/kms/admin.sock` | Admin 유닉스 소켓 경로 |
| `KMS_METRICS_ADDR` | `:9100` | 메트릭 리스너. 빈 값이면 비활성 |

**인증**

| 변수 | 기본값 | 설명 |
|---|---|---|
| `KMS_AUTHN` | `off` | `on`이면 Transit 요청에 토큰 요구 |
| `KMS_SA_PUBLIC_KEY` | `/etc/kubernetes/pki/sa.pub` | 서명 공개키 (쉼표로 여러 개) |
| `KMS_SA_ISSUER` | — | 설정 시 `iss` 검증 |
| `KMS_SA_AUDIENCE` | — | 설정 시 `aud` 검증 |

**인가**

| 변수 | 기본값 | 설명 |
|---|---|---|
| `KMS_AUTHZ` | `off` | `on`이면 SAR로 권한 판단 |
| `KMS_KUBECONFIG` | — | apiserver 접근용. 비면 in-cluster 설정 시도 |
| `KMS_AUTHZ_CACHE_TTL` | `10`(초) | 판단 결과 캐시 수명. **초 단위 정수**만 받는다(`10s`처럼 단위를 붙이면 기동에 실패한다). `0`은 기본값(10초) 사용, **음수를 주면 캐시를 완전히 비활성화**한다(매 요청마다 apiserver에 SAR을 묻는다) |
| `KMS_AUTHZ_TIMEOUT` | `3`(초) | SAR 호출 타임아웃. 역시 초 단위 정수만 받는다 |
| `KMS_AUTHZ_FAIL_OPEN` | `false` | apiserver 장애 시 허용 여부 |
| `KMS_AUTHZ_QPS` | `50` | 인가 클라이언트가 apiserver에 SAR을 보내는 초당 요청 수 상한. `0`은 기본값, **음수면(QPS/BURST 둘 중 하나라도) 클라이언트 측 속도 제한을 완전히 비활성화**한다. 근거는 ADR-008 참고 |
| `KMS_AUTHZ_BURST` | `100` | 위 QPS의 버스트 용량(토큰이 한꺼번에 쌓일 수 있는 최대치). 해석 규칙은 `KMS_AUTHZ_QPS`와 같다 |

> `KMS_AUTHZ=on`인데 `KMS_AUTHN=off`이면 기동에 실패한다.
> 신원 없이는 권한을 판단할 수 없다.
>
> `KMS_AUTHZ_CACHE_TTL`을 음수로 주고 기동하면 로그에
> `authorization cache is disabled (KMS_AUTHZ_CACHE_TTL < 0) — every request queries the apiserver`가
> 남는다 — 성능에 큰 영향을 주는 설정이라 눈에 띄게 남긴다.
>
> `KMS_AUTHZ_QPS`/`KMS_AUTHZ_BURST`를 명시적으로 설정하지 않으면
> client-go 기본값(QPS 5, Burst 10 — 컨트롤러용)이 아니라 이 값들(50/100)이
> 적용된다. client-go 기본값이 그대로 쓰이면 캐시 미스가 몰릴 때 요청마다
> 최대 수백 ms씩 대기하다 `KMS_AUTHZ_TIMEOUT`을 넘겨 정상 요청이 403을
> 받을 수 있다(ADR-008) — 둘 중 하나라도 음수로 끄면 그 보호가 전부
> apiserver의 API Priority and Fairness에만 맡겨지므로, 끌 때는 기동
> 로그의 경고를 확인해야 한다.

### 관리 API

| 변수 | 기본값 | 설명 |
|---|---|---|
| `ADMIN_API_ADDR` | `:8201` | 수신 주소 |
| `KMS_ADMIN_SOCKET` | `/var/run/kms/admin.sock` | 연결할 소켓 |
| `ADMIN_API_METRICS_URL` | `http://127.0.0.1:9100/metrics` | 대시보드가 수집할 KMS 메트릭 주소. 설정했지만 빈 값이면 수집을 끈다 |
| `ADMIN_API_METRICS_INTERVAL` | `5` | 메트릭 수집 주기(초, 1 이상 정수) |
| `ADMIN_API_METRICS_WINDOW` | `15` | 메모리에 보관할 메트릭 길이(분, 1 이상 정수) |
| `ADMIN_API_BENCH_DIR` | `./admin-data/bench` | 벤치 결과 저장 디렉터리 (`KMS_DATA_DIR` 기본값 `./data`과 겹치지 않게 분리) |

**클러스터 배포 시 `ADMIN_API_METRICS_URL`을 KMS 메트릭 주소로 설정할 것** (기본값 `127.0.0.1`은 관리 API 파드 자신을 가리킴).
설정하지 않으면 대시보드는 "메트릭 수집 불가"를 표시하고, sealed와 키 개수만 admin.sock에서 대신 가져온다.

---

## 기능별 사용법

아래 예시에서 `SOCK`는 admin.sock 경로다.
관리 API(`:8201`)를 쓰면 `curl --unix-socket $SOCK http://localhost` 대신
`curl localhost:8201`로 바꿔 쓸 수 있다.

```bash
SOCK=$HOME/kms-admin.sock
```

### 초기화와 봉인 해제

```bash
curl --unix-socket $SOCK http://localhost/v1/sys/seal-status
curl --unix-socket $SOCK -XPOST http://localhost/v1/sys/init
curl --unix-socket $SOCK -XPOST http://localhost/v1/sys/unseal
```

seal 방식별 동작:

| seal | init | unseal |
|---|---|---|
| dev | 별도 단계 없음 (패스프레이즈에서 결정적 유도) | 즉시 |
| shamir | 조각 N개 발급 — **이 순간 한 번만 표시됨** | threshold개 조각 제출 |
| tpm | 바로 완료 | 자동 (코드·시뮬레이터 검증만; 운영 배포 보류) |
| k8s | 바로 완료 | 자동 |

> `init`은 서버 수명 동안 **한 번만** 실행된다. 재실행하면 오류.
> `unseal`은 **프로세스 재시작마다** 필요하다.

### 키 관리

```bash
# 생성
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys \
  -H 'content-type: application/json' -d '{"name":"demo"}'

# 목록
curl --unix-socket $SOCK http://localhost/v1/keys

# 상세 — 메타데이터만 반환. 키 자료는 절대 노출되지 않음
curl --unix-socket $SOCK http://localhost/v1/keys/demo
```

응답 예:
```json
{
  "Name": "demo",
  "Type": "aes256-gcm",
  "LatestVersion": 1,
  "MinDecryptionVersion": 1,
  "AutoRotatePeriodSec": 0,
  "Versions": [{"Version": 1, "CreatedAt": "..."}]
}
```

### 키 수명 주기 — 사용 중지 → 삭제 예약 → 삭제

키를 곧바로 지우면 그 키로 암호화한 데이터를 영구히 못 푼다. 그래서 단계를 둔다 (관리 소켓 전용).
조회 응답에 `state`(`active`\|`disabled`\|`pending_deletion`)와 `deletion_date`가 들어간다.

```bash
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/disable          # 사용 중지
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/enable           # 다시 사용
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/schedule-deletion \
  -H 'content-type: application/json' -d '{"pending_days": 14}'                # 7~30일(기본 30), deletion_date 반환
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/cancel-deletion  # 취소 → disabled (다시 쓰려면 enable)
```

`disabled`/`pending_deletion` 키의 encrypt/decrypt/rewrap은 `409 key_not_active`이고 자동 회전도 건너뛴다.
유예가 지나면 백그라운드 작업이 키 자료를 삭제한다(되돌릴 수 없음, 관리 감사에 기록, 봉인 해제 상태에서만).
KMS v2 키와 `KMS_PROTECTED_KEYS`의 키는 `409 key_protected`로 거부된다.

### data key — 봉투 암호화를 클라이언트에서

큰 데이터는 KMS로 보내지 않고, KMS에서 1회용 데이터 키를 받아 로컬에서 암호화한다(권한: verb `datakey`).

```bash
# 키 받기 (기본 256비트, 평문 키 포함)
curl -s -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{}' https://<주소>/v1/datakey/<키>
# → {"ciphertext":"kms:v1:...","plaintext":"<base64 키>","key_version":1}
#   {"bits":128} 로 128비트, {"plaintext":false} 로 암호문만 받을 수도 있다
```

클라이언트는 `plaintext` 키로 데이터를 AES-GCM 등으로 암호화하고 키를 버린 뒤 `ciphertext`(키의 암호문)를 데이터와 함께 저장한다.
복호화할 때는 저장해 둔 `ciphertext`를 `POST /v1/decrypt/<키>`에 보내 평문 키를 되찾는다. 키를 회전해도 이전 data key 암호문은
`min_decryption_version`이 허용하는 동안 복호화된다.

### 외부에서 사용하기 (인터넷 공개 경로)

운영자가 외부 사용자 한 명을 만든다 (서버에서):

```bash
scripts/kms-external-user.sh add alice orders      # SA kms-external/alice, 키 kms-external.orders (권한: encrypt/decrypt/rewrap/datakey)
scripts/kms-external-user.sh token alice 1         # 1시간(최대 24시간)짜리 토큰이 표준 출력으로 나온다
```

**내부 CA 인증서(공개값)를 사용자에게 전달**한다(`sudo cat <내부 CA 인증서 경로>`, PEM 텍스트). CA *키*는 절대 보내지 않는다.
사용자는 이를 `ca.crt`로 저장한다.

```bash
B=https://<공인 주소>:9443
curl --cacert ca.crt $B/healthz
curl --cacert ca.crt -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"plaintext":"aGVsbG8="}' $B/v1/encrypt/kms-external.orders
curl --cacert ca.crt -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{}' $B/v1/datakey/kms-external.orders
```

외부에서는 `encrypt|decrypt|rewrap|datakey`만 되고 키 이름은 `kms-external.<이름>`이어야 한다(그 외는 모두 같은 403). 요청이 너무 많으면
`429 rate_limited`(`Retry-After` 헤더), 잘못된 토큰을 반복하면 5분간 차단된다. 내부 ServiceAccount 토큰은 외부에서 403이다.

### CLI (`kms`) — 외부 사용자용

외부 사용자는 `curl` 대신 CLI로 쓸 수 있다. 큰 파일은 자동으로 data key 방식(KMSF 파일 형식)으로 암호화한다.

1. **CA 인증서 받기**: 관리자에게 내부 CA의 *공개* 인증서(PEM 파일)를 받아 `ca.crt`로 저장한다. (CA 키는 받지 않는다.)
2. **설치**: 관리자가 알려 준 배포 주소로 `KMS_CLI_URL=<배포 URL> ./install.sh` (체크섬 검증 후 `~/.local/bin/kms`에 설치, [y/N] 확인).
   직접 빌드하려면 `scripts/build-cli.sh` → `dist/`.
3. **login**: 서버 주소와 CA를 기억시킨다 (`~/.config/kms/config.json`, 권한 0600). 토큰은 **기본적으로 저장하지 않는다.**

```bash
kms login --addr https://<공인 주소>:9443 --ca ca.crt --token-file ~/kms.token   # 토큰 파일 '경로'만 기억 (또는 환경변수 KMS_TOKEN)
export KMS_TOKEN=$(cat ~/kms.token)                                              # 파일 대신 환경변수를 써도 된다
kms login ... --token-stdin --save-token                                          # 설정 파일(0600)에 토큰까지 저장하려면 명시해야 한다
```

4. **암호화·복호화**

```bash
echo -n 'hello' | kms encrypt kms-external.orders                    # → kms:v1:... (1MiB 이하는 Transit encrypt)
kms decrypt kms-external.orders -i secret.txt.kms -o secret.txt      # kms:v.. 문자열은 키 이름이 필요하다
kms encrypt kms-external.orders -i backup.tar -o backup.tar.kmsf     # 1MiB 초과는 자동으로 datakey + KMSF 파일
kms decrypt -i backup.tar.kmsf -o backup.tar                         # KMSF 파일은 키 이름이 헤더에 있다 (형식은 앞 4바이트로 판별)
kms encrypt k --mode file ...                                        # --mode transit|file 로 강제
kms datakey kms-external.orders [--no-plaintext]                     # data key를 직접 받기
kms version
```

복호화에 실패한 결과(변조·잘림)는 출력 파일을 남기지 않는다. 오류는 서버의 `{error,message,hint}`를 한국어 안내로 보여 주고,
429이면 `Retry-After`를 보고 재시도 시간을 알려 준다. 토큰·평문은 오류 메시지에 나오지 않는다.

**KMSF 파일 형식**(`pkg/kmsfile`): 헤더(`KMSF`, 버전, 키 이름, data key 암호문, 청크 크기, 기본 nonce) + 64KiB 청크별 AES-256-GCM.
nonce는 청크마다 다르고 AAD에 헤더 해시·청크 번호·마지막 청크 여부가 들어가 순서 바꾸기·잘라내기·덧붙이기를 탐지한다.
웹 포털의 "파일 암호화" 탭이 만든 파일도 같은 형식이라 CLI로 풀 수 있다.

### 오류 응답 형식

모든 오류는 `{"error":"<기계용 코드>","message":"<사람용 설명>","hint":"<선택>"}` JSON이다(상태 코드는 그대로).
키 이름·버전 숫자는 응답에 넣지 않는다(예: 최소 복호화 버전 거부는 `version_not_allowed`, 상세는 감사 로그에만).
본문이 2 MiB를 넘으면 `413 {"error":"payload_too_large","limit_bytes":...}`.

### 암복호화

```bash
# 암호화 (평문은 base64)
curl -XPOST localhost:8200/v1/encrypt/demo \
  -H 'content-type: application/json' \
  -d "{\"plaintext\":\"$(echo -n 'hello' | base64)\"}"
# → {"ciphertext":"kms:v1:AAAAP..."}

# 복호화
curl -XPOST localhost:8200/v1/decrypt/demo \
  -H 'content-type: application/json' \
  -d '{"ciphertext":"kms:v1:AAAAP..."}'
```

> 같은 평문을 두 번 암호화하면 서로 다른 암호문이 나온다.
> 요청마다 DEK가 새로 생성되기 때문이다.

### 키 회전

```bash
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/rotate
```

회전 후:
- `LatestVersion`이 증가하고 새 버전이 `Versions`에 추가된다
- 새 암호화는 최신 버전을 사용한다 (`kms:v2:...`)
- **기존 버전은 삭제되지 않는다.** 옛 암호문은 계속 복호화된다

### rewrap — 평문 노출 없는 재암호화

```bash
curl -XPOST localhost:8200/v1/rewrap/demo \
  -H 'content-type: application/json' \
  -d '{"ciphertext":"kms:v1:..."}'
# → {"ciphertext":"kms:v2:..."}
```

옛 버전으로 암호화된 데이터를 최신 버전으로 갈아끼운다.
**원본 암호문은 그대로 남는다** — rewrap은 삭제가 아니라 사본 생성이다.
실제 교체는 애플리케이션이 저장소의 값을 바꿔 넣어야 완료된다.

### 정책 설정

```bash
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/config \
  -H 'content-type: application/json' \
  -d '{"min_decryption_version":2}'
```

- `min_decryption_version`: 이 값보다 낮은 버전으로 암호화된 데이터의 복호화를 거부한다.
  키 유출 대응 수단
- 자동 회전 주기 설정도 이 엔드포인트로 한다

### seal 비교

```bash
curl localhost:8200/v1/sys/seal-profile
curl localhost:8200/v1/sys/seal-benchmark
```

Transit 평면에 있다. 특정 키를 대상으로 하지 않으므로 인가 대상에서 제외된다.

---

## 접근 제어 사용

### 인증 활성화

```bash
KMS_AUTHN=on KMS_SA_PUBLIC_KEY=/etc/kubernetes/pki/sa.pub ... go run ./cmd/server
```

Transit 요청에 토큰을 실어 보낸다.

```bash
TOKEN=$(kubectl -n team-a create token app-a)

curl -XPOST localhost:8200/v1/encrypt/demo \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"plaintext\":\"$(echo -n 'hello' | base64)\"}"
```

토큰이 없거나 유효하지 않으면 `401`.
Admin 평면(소켓)은 인증 대상이 아니므로 영향받지 않는다.

### 인가 활성화

```bash
KMS_AUTHN=on KMS_SA_PUBLIC_KEY=... \
KMS_AUTHZ=on KMS_KUBECONFIG=/path/to/kubeconfig \
... go run ./cmd/server
```

관리자가 `kubectl`로 권한을 정의한다. 키 소유 규칙(C+B, ADR-009): `<ns>.<name>` 키는 `<ns>`
네임스페이스의 Role/RoleBinding, 점 없는 전역 키는 ClusterRole/ClusterRoleBinding으로만 허용된다.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kms-demo-encrypt
  namespace: team-a
rules:
- apiGroups: ["kms.local"]
  resources: ["keys"]
  resourceNames: ["team-a.demo"]    # team-a 소유 키
  verbs: ["encrypt"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kms-demo-encrypt
  namespace: team-a
subjects:
- kind: ServiceAccount
  name: app-a
  namespace: team-a
roleRef:
  kind: Role
  name: kms-demo-encrypt
  apiGroup: rbac.authorization.k8s.io
```

권한이 없으면 `403`.

### KMS용 자격 증명의 최소 권한

SAR 생성 권한만 있으면 된다. `admin.conf`(클러스터 전체 관리자)는 과도하다.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kms-sar-reviewer
rules:
- apiGroups: ["authorization.k8s.io"]
  resources: ["subjectaccessreviews"]
  verbs: ["create"]
```

---

### 운영·성능 대시보드

`http://localhost:8201/dashboard` (관리 API 필요). 세 부분으로 되어 있다.

1. **상태 카드** — sealed/unsealed, 키 수, 키 버전 합계, 마지막 unseal, 메트릭 수집 상태.
   값마다 출처(`metrics`/`socket`)를 함께 보여준다.
2. **실시간 트래픽**(5초마다 갱신, 구간 1/5/15분) — 처리량, 에러율, p50/p99 지연,
   인가 캐시 적중률, SAR 호출/초, SAR 평균 vs apiserver 왕복. 차트마다 "표 보기"가 있다.
3. **벤치 결과** — 제출된 실행을 목록에서 골라(최대 8개) 같은 동시성 기준으로 처리량·p50·p99를
   막대와 표로 비교한다. 삭제 버튼이 있다.

**메트릭 수집이 안 될 때**: 화면에 "메트릭 수집 불가"가 뜨고 계속 재시도한다. 이때 sealed와 키
개수는 admin.sock에서 대신 가져오며(출처 `socket`), 키 버전 합계와 마지막 unseal은 `—`로 표시된다.

**벤치 결과 제출**

```bash
# 측정 직후 제출 (실패해도 결과 출력·--output 저장은 그대로, 경고만 출력)
kms-bench --key demo --scenario concurrency --label authz-cached \
  --submit http://localhost:8201

# 접근 제어 비교 실험 스크립트: 조건별로 자동 제출
SUBMIT=http://localhost:8201 scripts/bench-access-control.sh

# 직접 제출/조회/삭제
curl -XPOST localhost:8201/api/bench/results --data-binary @result.json
curl localhost:8201/api/bench/results
curl -XDELETE localhost:8201/api/bench/results/<id>
```

제한: 요청 본문 1MB, `runs` 최대 200개, 저장 500개(넘으면 오래된 것부터 삭제).
파일명은 서버가 만든다(`<UTC 타임스탬프>-<정리된 라벨>`). 인증이 없으므로 업로드·삭제도
신뢰된 네트워크 안에서만 열어둘 것.

---

## 웹 UI

| 경로 | 상태 |
|---|---|
| `/console` | 사용 가능 — 키 관리, init/unseal |
| `/` | `/console`로 리다이렉트 |
| `/dashboard` | 사용 가능 — 운영·성능 대시보드(상태, 실시간 트래픽, 벤치 결과 비교). 아래 "운영·성능 대시보드" 참고 |
| `/portal` | 비활성 — Transit API를 호출하는 별도 데모 앱으로 분리 예정 |

console의 "Seal 특성" 카드는 Transit API가 필요하다는 안내를 표시한다.

---

## 주의사항

**관리 API에는 인증과 TLS가 없다.** 신뢰할 수 없는 네트워크에 노출하지 말 것.

**메트릭 포트에도 인증이 없다.** 네트워크 정책으로 Prometheus만 접근하도록 제한할 것.

**memory 저장소는 재시작 시 모든 키가 소실된다.** 개발·테스트용으로만 사용할 것.
file 저장소를 쓰더라도 디렉터리가 날아가면 KEK가 전멸해 기존 암호문을 영구히 복호화할 수 없다.
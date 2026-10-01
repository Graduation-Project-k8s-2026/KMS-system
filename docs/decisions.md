# 설계 결정 기록

각 결정의 배경과 근거를 남긴다. 나중에 "왜 이렇게 했지?"를 되짚기 위한 문서다.

---

## ADR-001. Transit형 KMS로 간다

**상태**: 확정

**배경**
KMS를 두 가지 형태로 만들 수 있다.
- kv형: 값을 받아 암호화해 저장하고, 나중에 복호화해 돌려준다
- transit형: 저장하지 않고 암복호화 연산만 제공한다

**결정**
Transit형.

**근거**
- AWS KMS, GCP Cloud KMS가 transit형이다. "실제 클라우드 KMS 재현"이라는 목표에 부합한다
- 쿠버네티스 KMS Provider 규격 자체가 `Encrypt`/`Decrypt`만 요구하고 저장을 요구하지 않는다.
  저장 기능을 만들어도 쿠버네티스는 쓰지 않는다
- 저장 부담(영속성, 백업, 용량)이 작아 졸업 프로젝트 규모에 현실적이다

**대가**
데모 임팩트가 약하다 — "문자열 넣으면 암호문 나온다"가 전부로 보일 수 있다.
이를 쓰는 얇은 데모 앱을 부록으로 둬서 보완한다.

---

## ADR-002. API를 Transit/Admin 두 평면으로 분리한다

**상태**: 확정

**배경**
단일 HTTP 서버(`:8200`)에 암복호화와 키 관리, init/unseal이 모두 섞여 있었다.
클러스터 안의 어떤 파드든 8200에 접속하면 키를 만들고 지울 수 있었다.

**결정**
- Transit 평면: TCP `:8200` — 암복호화, rewrap
- Admin 평면: 유닉스 도메인 소켓 — 키 관리, init/unseal

**근거**
"키를 사용하는 권한"과 "키를 관리하는 권한"은 다르다
(AWS KMS의 키 관리자/키 사용자 분리, Azure의 Crypto Officer/Crypto User와 동일한 원칙).
관리 기능을 네트워크에서 아예 제거하면, 권한 체계를 만들기 전에도 구조적으로 보호된다.

**대가**
브라우저는 유닉스 소켓에 접속할 수 없다. 웹 UI가 동작하지 않게 되어,
별도 프로세스인 관리 API가 필요해졌다(ADR-005).

---

## ADR-003. 인증은 apiserver TokenReview가 아닌 로컬 JWT 서명 검증

**상태**: 확정

**배경**
Transit API 요청자를 식별해야 한다. ServiceAccount 토큰 검증 방법은 두 가지다.
- kube-apiserver의 TokenReview API 호출
- 서명 공개키로 로컬에서 JWT 검증

**실험**
kind 클러스터에서 static pod를 띄워 확인했다.

```bash
# /etc/kubernetes/manifests/ 에 매니페스트 배치 (serviceAccountName: default 명시)
crictl exec <container> ls /var/run/secrets/kubernetes.io/serviceaccount/
→ No such file or directory
```

**static pod에는 ServiceAccount 토큰이 자동 마운트되지 않는다.**
토큰 주입은 kube-apiserver의 admission controller가 수행하는데,
static pod는 kubelet이 매니페스트를 직접 읽어 생성하므로 이 과정을 건너뛴다.
`kubectl get pods`에 보이는 것은 사후 등록되는 mirror pod일 뿐이다.

**결정**
로컬 JWT 서명 검증. `/etc/kubernetes/pki/sa.pub`를 읽어 서명을 확인한다.

**근거**
- TokenReview를 쓰려면 KMS가 apiserver 접근 자격을 따로 마련해야 한다
- 암복호화는 요청마다 일어나는 핫패스다. 매 요청 apiserver 왕복은 지연이 크다
- KMS가 컨트롤 플레인 노드의 static pod라는 점을 활용할 수 있다
- apiserver가 죽어도 암복호화가 계속 동작한다

**한계**
토큰 폐기(revocation) 여부를 확인할 수 없다.
쿠버네티스의 projected token은 주기적으로 갱신되므로 실질적 노출 창은 제한적이지만,
명시적 한계로 문서화한다.

---

## ADR-004. 인가는 자체 정책이 아닌 SubjectAccessReview

**상태**: 확정

**배경**
"이 요청자가 이 키에 이 동작을 해도 되는가"를 판단해야 한다.
- 자체 정책 저장소를 두고 KMS가 직접 판단 (HashiCorp Vault 방식)
- kube-apiserver의 SAR에 위임 (쿠버네티스 RBAC 활용)

**결정**
SubjectAccessReview.

RBAC 어휘 매핑:
```yaml
apiGroups: ["kms.local"]
resources: ["keys"]
resourceNames: ["demo"]
verbs: ["encrypt", "decrypt", "rewrap"]
```

**근거**
- 정책 저장소, 편집 API, 관리 UI, 백업을 따로 만들지 않아도 된다
- 관리자가 `kubectl`로 Role/RoleBinding을 다루면 된다. 권한 관리가 표준 도구로 통일된다
- 검증된 시스템에 위임하는 것이 자체 구현보다 안전하다

**검증**
kind 클러스터에서 실제 apiserver를 상대로 확인했다.
team-a의 ServiceAccount에 `demo` 키 `encrypt`만 허용한 뒤:
- encrypt → 200
- decrypt → 403 (같은 토큰·같은 키인데 동작에 따라 갈림)
- team-b 토큰으로 encrypt → 403 (네임스페이스 격리)

가상 리소스와 커스텀 verb로 SAR이 성립함을 실증했다.

**대가**
ADR-003에서 피하려던 apiserver 자격 증명 문제가 돌아온다.
kubeconfig 또는 전용 SA 토큰을 hostPath로 제공해야 한다.
요청마다 apiserver를 부르는 지연은 짧은 TTL 캐싱으로 완화한다.

**부수 결정**
- 캐시 TTL 기본 10초. 허용·거부 모두 캐싱
- apiserver 장애 시 fail-closed(거부)가 기본. 보안 도구이므로 판단 불가 시 거부가 안전하다
- 장애 시 내린 폴백 판단은 캐싱하지 않는다 — TTL 동안 굳어지면 곤란하다

---

## ADR-005. 관리 API는 별도 프로세스

**상태**: 확정

**배경**
ADR-002로 관리 기능이 유닉스 소켓으로 이동해 웹 UI가 동작하지 않게 되었다.
브라우저가 소켓에 접속할 방법이 없다.

**결정**
HTTP를 받아 admin.sock으로 투명 중계하는 별도 프로세스(`cmd/admin-api`)를 만든다.
웹 UI도 이 프로세스가 서빙한다.

**근거**
- KMS 서버는 static pod로 배포되어 제약이 많다(ConfigMap 불가, SA 토큰 없음).
  관리 API는 일반 파드로 자유롭게 배포할 수 있다
- 웹 UI와 TLS 종단 같은 부가 기능을 KMS 본체에 섞지 않아 공격 표면을 줄인다

**중계 방식**
투명 프록시를 택했다. 요청을 해석하지 않고 경로/메서드/헤더/바디를 그대로 넘긴다.
구현이 짧고 KMS API가 바뀌어도 관리 API를 고치지 않아도 된다.

감사 로그나 관리자 인증을 넣으려면 명시적 라우팅으로 전환해야 한다. 추후 과제.

**미해결**
관리 API는 기동 시 admin.sock 존재를 확인하고 없으면 종료한다.
쿠버네티스에서 KMS보다 먼저 뜨면 CrashLoopBackOff가 된다.
재시작 정책으로 넘길지, initContainer로 대기시킬지 매니페스트 작업 시 결정한다.

---

## ADR-006. 배포 seal은 shamir

**상태**: 잠정 확정 (TPM 확보 시 재검토)

**배경**
서버 부팅 시 루트 키를 메모리에 올려야 KMS를 쓸 수 있다. 누가 풀어줄 것인가.

구현된 seal 4종의 적합성:

| seal | 가능 여부 | 사유 |
|---|---|---|
| k8s | ❌ | 루트 키를 K8s Secret에 두는데, 그 Secret을 암호화하는 것이 이 KMS. 순환 |
| dev | ❌ | 패스프레이즈가 매니페스트에 평문. 키 저장소와 같은 디스크에 있게 되어 디스크 탈취 시 무방비 |
| tpm | ❌ (현재) | 인스턴스에 `/dev/tpm*` 없음. OCI Shielded Instance로 재생성하면 가능할 수 있으나 A1 셰이프 지원 여부 미확인 |
| shamir | ✅ | 사용 가능 |

**결정**
shamir. 기본 5조각, threshold 3.

**대가 — 부팅 공백**
노드 재부팅 시 KMS가 sealed 상태로 뜬다.
관리자가 조각을 입력할 때까지 apiserver는 암호화된 Secret을 읽을 수 없다.

이를 약점이 아니라 설계 선택으로 다룬다:
"자동 복구보다 정족수 기반 통제를 우선했다.
재부팅 시 관리자 개입이 필요한 대신, 단일 관리자나 디스크 탈취로는 루트 키를 얻을 수 없다."

**TPM에 대한 입장**
구현과 기능 검증은 완료했으나, 실험 환경에 하드웨어 TPM이 없어 시뮬레이터로만 검증했다.
실제 보안 보장은 하드웨어 TPM이 있는 환경에서 성립한다. 이 제약을 명시한다.

---

## ADR-007. 메트릭은 별도 포트

**상태**: 확정

**배경**
Prometheus가 `/metrics`를 수집해야 한다. 어느 평면에 둘 것인가.

**결정**
전용 포트 `:9100`. 인증을 붙이지 않는다.

**근거**
- Transit에 두면 인증이 켜진 상태에서 Prometheus도 토큰이 필요해진다
- 메트릭이 애플리케이션 트래픽과 같은 경로로 노출되지 않게 분리한다
- 네트워크 정책으로 Prometheus만 접근하도록 제한하기 쉽다

**제약**
민감 정보를 메트릭에 포함하지 않는다.
키 이름을 라벨로 쓰지 않는다 — cardinality 폭발과 정보 노출 양쪽 문제다.
주체·네임스페이스도 같은 이유로 라벨에서 제외한다.
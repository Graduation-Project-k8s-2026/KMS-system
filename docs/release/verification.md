# §12–16 실제 검증 결과

실행일 2026-10-12 KST (기계 증거는 UTC). 기준 HEAD `a41b11ad11ae41df4400b622e9e1a0c5a5ac097f`, 실제 linux/arm64 단일 노드, Kubernetes 1.35.9·etcd 3.6.6·Go 1.26.9. 현재 소스 수정은 미커밋이며 새 릴리스 SHA로 주장하지 않는다. 최초 로컬 구현의 기록은 [이력](verification-local-history.md)에 보존했다.

`PASS`는 해당 증거 범위만 뜻한다. `PARTIAL`은 일부 실제 시나리오가 미검증이고, `DEFERRED`는 사용자 보류 범위다. 전체 제출 gate를 일괄 PASS로 채우지 않는다.

| ID | 결과 | 이번 실행의 범위·증거 |
|---|---|---|
| T01 이미지 분리 | PASS | 실제 세 제품 이미지의 바이너리 하나씩·ARM64·UID10001 검사: [image-contents](evidence/steps12-16/image-contents.json), [release-lock](release-lock.json) |
| T02 초기화 보호 | PASS (자동 시험) | 전체 race suite의 initialization/reinit/wrong-share. 운영에서는 기존 share만 사용, Init 없음 |
| T03 내구성 | PASS (fault injection) | crash/ENOSPC/EROFS 자동 시험. 실제 운영 디스크를 채우거나 read-only로 바꾸지는 않음 |
| T04 동시성 | PASS | [race.log](evidence/steps12-16/race.log), 실제 운영 v2 동시 decrypt 및 20회 keyID 단조성 시험 |
| T05 Transit | PASS (실제 정상+자동 부정 시험) | TLS/JWT/SAR 비교 Job 6회 오류0, [재부팅 후 Transit 10왕복·결과 제출 오류0](evidence/steps12-16/post-reboot-transit.json), CA/SAN/401/403 단위 시험 |
| T06 GUI 인가 | PASS (운영 경계+자동 시험) | [live-access](evidence/steps12-16/live-access.json): 실제 viewer 읽기200/쓰기403/회수403, 익명401·Host/CSRF403·미등록404. 가상 시험 viewer만 잠시 추가 후 원래 역할 파일 복원. 사람 tailnet 로그인과 구분 |
| T07 네트워크 | PARTIAL | [재부팅 후 사설 HTTPS의 CA/SAN 검증·익명401](evidence/steps12-16/post-reboot-https.json). 승인/비승인 외부 기기의 IPv4/IPv6 검사는 미실행 |
| T08 Prometheus | PASS | [cluster-health](evidence/steps12-16/cluster-health.json): KMS/API target up, 백업 정지 및 실제 호스트 재부팅 후 과거 시계열 조회 |
| T09 Job 제어 | PASS (정상 실운영+부정 자동 시험) | 실제 18개 Job 생성·추적·완료. 취소/timeout/reconcile/임의 template 거부는 자동 시험 |
| T10 결과 제출 | PASS | 실제 Job/SA/Pod 귀속·TLS ingest·PVC 결과 18개. [재부팅 후 기존 결과 23개 보존](evidence/steps12-16/reboot.json) 및 새 Transit 결과 제출 확인 |
| T11 KMS v2 | PASS | 실제 공식 RPC/오류/재시작과 [rotation](evidence/steps12-16/rotation.json), [복원 RPC](evidence/steps12-16/restored-kms-rpc.json) |
| T12 Secret 저장 | PASS | [identity 제거](evidence/steps12-16/identity-removed.json), [재쓰기 후 envelope](evidence/steps12-16/envelope-after-rewrite.json). 현재 2개 모두 keyID2, 전체 API 읽기 성공 |
| T13 호스트 재부팅 | PASS | [실제 boot ID 변경·기존 share·과거 ciphertext·Secret 2개·벤치 결과 23개·감사 파일 4개 보존](evidence/steps12-16/reboot.json). 관리/Prometheus와 호스트 서비스 회복. 측정 상한 418.13초, 이 중 share 입력 17.69초 |
| T14 백업·복원 | PASS (별도 경로 복원·PC 반출) | [정지 백업/hash](evidence/steps12-16/backup-summary.json), [복원한 etcd·API·KMS에서 이전 Secret 읽기](evidence/steps12-16/final-restored-control-plane.json). [암호 입력 없는 암호화 export·실제 복호화/hash](evidence/steps12-16/local-backup-export.json) 확인. [PC 다운로드·복구 암호 별도 보관은 사용자 확인](evidence/steps12-16/external-backup.json), 목적지 SHA256 일치도 사용자 확인 |
| T15 데모 앱 | PASS (2026-10-15 공개 경로 범위) | Campus Store 공개 HTTPS·접속 암호·실제 KMS 암복호화·SAR 403·Portal 재시작 후 주문 보존 검증. 데모 사용자는 Tailscale 불필요. [현재 구조·검증 범위](../demo/verification.md). 기존 관리 경로의 외부 기기 검증은 T07에 남김 |
| T16 관측 정직성 | PASS (자동 시험+실제 sealed) | sealed/401/403/5xx와 N/A 처리 tests, 실제 Job 오류·성공 구분. [실제 재부팅 후 sealed=1, API readyz 실패, 과거 시계열 보존 확인](evidence/steps12-16/reboot-sealed-observability.json) |
| T17 회수 | PARTIAL | 역할/토큰/인증서 만료·교체 자동 시험. 실제 tailnet 기기 회수·모든 운영 자격증명 교체는 미검증. [Transit/ingest 인증서](evidence/steps12-16/certificate-expiry.json)와 [Kubernetes 인증서](evidence/steps12-16/kubernetes-certificate-expiry.json) 만료 점검 완료 |
| T18 성능 | PASS (명시 조건) | [18개 trial·요약](benchmark/README.md), [차트](benchmark/throughput.svg), 동일 Spec/image, 오류0. fake K8sSeal/TPM simulator 한계 별도 표기 |

## 실제 변경·실패 복구

- 기존 apiserver command/인증서/etcd 설정을 보존하고 encryption config와 소켓 mount만 병합했다. 원본은 감시 디렉터리 밖의 최초 backup에 보관했다.
- 최초 재쓰기 대상은 0개였다. 새 공개 proof Secret 생성 후 raw 암호화를 검증했고, 회전 시험으로 2개가 된 현재 Secret 전체를 다시 썼다. 과거 revision의 평문 소거를 주장하지 않는다.
- 실제 rewrite에서 SecretList item의 `apiVersion/kind` 생략을 발견했다. TypeMeta를 보완하고 실제 2개 재쓰기와 회귀 시험을 통과했다.
- 격리 복원 KMS의 최초 시작은 TLS 파일 경로/소유권 복원 차이로 실패했다. 원래 mount 경로와 numeric UID/GID를 복원하도록 수정한 뒤 실제 기동·기존 share·과거 ciphertext 복호화를 통과했다.
- apiserver 설정 변경은 kubelet의 정지/재기동 대기 시간이 필요했다. API가 준비되기 전 rewrite 시도는 실패했고, readyz 정상 후 재시도했다. 실패한 상태에서 provider를 제거하거나 Secret을 삭제하지 않았다.
- 격리 apiserver의 최소 capability를 실제 동작에 맞춰 NET_BIND_SERVICE(공식 실행 파일 capability)·DAC_OVERRIDE(UID10001/0600 KMS UDS에 대한 원래 root 접근)로 보완했다. 복원 경로만 mount하며 운영 socket/데이터는 mount하지 않았다. 최종 복원 API에서 이전 Secret 2개 읽기를 통과했다.
- 자동 승인 검토가 환경변수 값 출력 명령을 개인키 노출 우려로 차단했다. 값 출력 대신 설정 이름·파일 존재 여부만 확인했다. 키/share/JWT/Secret 원문은 증거에 포함하지 않았다.

## 자동 회귀

- `go test -race ./... -count=1`: [로그](evidence/steps12-16/race.log)
- `go vet ./...`: [로그](evidence/steps12-16/vet.log)
- `python3 -m unittest discover -s scripts -p 'test_*.py'`: [로그](evidence/steps12-16/python.log)
- `CGO_ENABLED=1 go run -tags=tpm_lab ./cmd/seal-lab --repeats 5`: [JSONL](benchmark/seal-lab.jsonl)
- 공식 프로토콜 근거: [Kubernetes 1.35 KMS](https://v1-35.docs.kubernetes.io/docs/tasks/administer-cluster/kms-provider/), [EncryptedObject v0.35.9](https://github.com/kubernetes/apiserver/blob/v0.35.9/pkg/storage/value/encrypt/envelope/kmsv2/v2/api.proto), [etcd 3.6 recovery](https://etcd.io/docs/v3.6/op-guide/recovery/).

## 최종 재부팅·외부 백업 확인

실제 재부팅 뒤 KMS는 sealed 상태로 정상 기동했고 API readiness는 실패했다. 기존 share 입력 후 KMS provider가 먼저 정상화됐으며 informer 동기화 대기 후 전체 readyz가 회복됐다. 초기 준비부터 최종 검증까지 418.13초이며 share 입력 17.69초를 차감하면 400.44초다. 예약 대기·운영자 재접속·검증 지연을 포함한 상한값으로, 순수 서버 시작 시간이나 전체 사람 대기를 제외한 값으로 해석하지 않는다.

최종 암호화 백업은 생성 후 실제 복호화로 15개 파일을 대조했고, 운영자가 PC 다운로드·복구 암호 별도 보관·목적지 SHA256 일치를 확인했다. 공유용 제출 묶음에는 이 운영 백업과 복구 암호를 포함하지 않는다. T07/T17의 실제 외부 기기·운영 자격증명 교체 시연은 여전히 PARTIAL이다. T15는 2026-10-14 사설 경로 배포 후, 2026-10-15 사용자 요청에 따라 공개 HTTPS 사용자 경로로 전환해 실제 연동을 검증했다. 기존 관리 경로의 외부 기기 검증은 T07의 별도 범위다. [시나리오와 구성도](../demo/campus-store.md), [검증 기록](../demo/verification.md).

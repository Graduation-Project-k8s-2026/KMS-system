# 실제 백업·복원·업데이트 절차

2026-10-12 KST. 최초 설계 단계 문서는 [이력](recovery-local-history.md)에 보존했다. 실행 결과의 최종 상태는 [verification.md](verification.md), 백업 hash는 `evidence/steps12-16/backup-summary.json`을 기준으로 한다.

## 생성한 백업

| ID | 의미 | 보호 범위 |
|---|---|---|
| `pre-kms-v2-20261011T1610Z` | apiserver 연결 전 일관된 정지 백업 | KEK v1, 당시 etcd·운영 데이터·TSDB·설정·이미지 |
| `identity-removal-20261011T1610Z` | identity 제거/회전 직전 추가 snapshot | 보조 etcd snapshot 및 원래 encryption config·회전 상태. 단독 전체 복원 묶음이 아님 |
| `final-kms-v2-20261011T1616Z` | identity 제거·KEK 회전·Secret 재쓰기 후 정지 백업 | KEK v1/v2, KMS-only Secret 2개, 운영 결과·감사·TSDB·설정·이미지·release-lock |

전체 묶음은 `/var/backups/custom-kms/<ID>`의 root 전용 디렉터리에 있다. share는 포함하지 않았다. 파일별 SHA256은 `checksums.json`이며 `state.json`의 complete가 true인 묶음만 복원한다. state는 재개 후 갱신되므로 checksum 대상에서 제외한다. 설정/이미지 tar와 운영 snapshot은 비공개 자료이며 Git에 넣지 않는다.

정지 백업은 관리 API·앱·Prometheus scale0 → 활성 Job 재검사 → apiserver 종료 확인 → KMS seal로 scheduler/쓰기 중지 → etcd snapshot → KMS 종료 확인 → 데이터/설정/이미지 복사 순서다. 원본 데이터를 삭제하지 않는다. 종료는 `crictl ps`의 실제 컨테이너 상태로 판단한다. manifest는 감시 폴더 밖에 보관하고 복원할 때만 atomic replace한다.

### 중단된 백업 재개

```bash
sudo python3 scripts/backup-kms.py status --directory /var/backups/custom-kms/<ID>
sudo python3 scripts/host-unseal.py
sudo python3 scripts/backup-kms.py resume --directory /var/backups/custom-kms/<ID>
```

`prepare` 도중 실패했어도 같은 ID로 prepare를 다시 덮어쓰지 않는다. `held/`와 state를 확인하고 resume로 운영을 먼저 회복한다. complete=false인 결과를 사용 가능한 백업으로 표시하지 않는다. live/held 양쪽 manifest가 다르면 도구는 덮어쓰지 않고 중단한다.

## 별도 경로 복원

```bash
sudo python3 scripts/restore-kms.py \
  --backup /var/backups/custom-kms/final-kms-v2-20261011T1616Z \
  --directory /var/backups/custom-kms-restores/<새-ID> --start-kms
sudo python3 scripts/host-unseal.py \
  --socket /var/backups/custom-kms-restores/<새-ID>/run/admin.sock
sudo python3 scripts/restore-control-plane.py \
  --backup /var/backups/custom-kms/final-kms-v2-20261011T1616Z \
  --directory /var/backups/custom-kms-restores/<새-ID> \
  --evidence /tmp/restored-control-plane.json
```

- archive의 path traversal·symlink·device를 거부하고, 검증된 파일의 UID/GID를 복원한다. 기존 운영 경로를 덮지 않는다.
- KMS 시험 컨테이너는 network=none, 새 UDS, 복원한 키만 사용한다. 실제 기존 share로 unseal하고 KEK v1의 공개 ciphertext를 읽는다.
- etcdutl은 실제 배포와 같은 3.6.6 공식 바이너리다. 공식 배포 SHA256을 검증했다. 원래 etcd name·peer URL·initial cluster를 보존하고 새 data-dir에 `--bump-revision=1000000000 --mark-compacted`로 복원한다.
- 통합 시험은 복원 etcd의 loopback12379, 별도 apiserver의 loopback16443과 복원 KMS를 연결한다. 인증서·관리 kubeconfig도 복원본만 사용하고 TLS 검증을 끄지 않는다.
- API로 과거 공개 Secret을 읽고 raw envelope까지 확인한다. 시험 후 etcd/apiserver 컨테이너는 중지한다. 복원 KMS는 `docker stop kms-restore-<새-ID>`로 중지한다.
- 이 시험에는 복원된 kubelet/controller-manager/scheduler나 다른 VM의 워크로드 재스케줄링은 포함되지 않는다. 운영 볼륨을 교체하는 DR 전환으로 확대해 주장하지 않는다.

## 실제 재부팅

재부팅 직전 `verify-reboot.py prepare --state <private-state>`로 boot ID와 결과·감사 기록 hash를 기록한다. 감사 로그는 재부팅 후 추가 기록을 허용하되 기존 바이트의 변경·유실을 거부한다. SSH/OCI 콘솔 접근 및 기존 share 보유 상태에서 재부팅한다. 재접속 후 GUI를 기다리지 말고 `sudo python3 scripts/host-unseal.py`를 먼저 실행한다. 시간 측정이 필요하면 unseal 명령에 `--timing-file <private-timing.json>`을 추가한다. 그 뒤 `verify-reboot.py check --state <same-state> --unseal-timing <private-timing.json> --evidence <report>`는 실제 boot ID 변경·과거 ciphertext·Secret·bench 결과·감사 기록·관리/Prometheus Deployment·호스트 서비스를 대조한다.

RTO는 기록 시점부터 실제 검증 완료까지의 상한값과 share 입력 대기를 포함한다. 사람의 응답 대기·증거 수집 시간까지 포함하므로 순수 서비스 시작 지연으로 해석하지 않는다. 별도 timing 파일이 있으면 실제 share 입력에 소요된 시간과 이를 차감한 상한값도 기록한다. 재접속 등 측정 밖의 사람 대기는 여전히 포함된다. snapshot 시점 이후 새 쓰기는 해당 백업의 RPO 범위 밖이다. 정지 구간의 KMS/etcd 데이터는 같은 쓰기 중단 지점으로 맞췄다.

### 이번 실제 재부팅 결과

2026-10-12 09:53 KST 실제 부팅 후 기존 share로 unseal했다. [검증 증거](evidence/steps12-16/reboot.json)에 이전/이후 boot ID, 과거 Secret 2개·벤치 결과 23개·감사 파일 4개 보존 및 서비스 정상화를 기록했다. 측정 상한 418.13초 중 share 입력은 17.69초다. share 입력 직후 KMS는 정상화됐고, API informer 동기화 완료를 기다린 뒤 readyz가 통과했다. [재부팅 후 Transit Job](evidence/steps12-16/post-reboot-transit.json)도 10왕복·결과 제출 오류0을 확인했다.

## 암호화·외부 반출

현재 간단한 반출 방식은 `sudo python3 scripts/export-backup-auto.py`다. 입력 창 없이 무작위 384-bit 복구 암호로 GPG AES256 암호화를 수행하며, 완성본을 실제 복호화해 모든 파일 hash를 원본과 대조한다. 기존 출력/암호 파일이 있으면 덮어쓰지 않는다. 평문 백업을 저장소에 생성하지 않는다.

- 암호화 파일: 저장소의 `.backup-download/kms-final-v2-auto.tar.gpg` (Git 제외, 폴더0700·파일0600).
- SHA256: 같은 이름에 `.sha256`을 붙인 파일. 검증 결과는 [local-backup-export.json](evidence/steps12-16/local-backup-export.json).
- 복구 암호: **저장소 밖** `/home/ubuntu/.kms-backup-keys/kms-final-v2-auto.password` (폴더0700·파일0600). 백업 archive에는 들어 있지 않다.

VS Code 원격 탐색기에서 `.gpg` 파일을 우클릭해 본인 PC로 다운로드한다. 복구 암호 파일도 별도로 다운로드하거나 비밀번호 관리자에 보관한다. 호스트 터미널에서 `cat /home/ubuntu/.kms-backup-keys/kms-final-v2-auto.password`로 직접 확인할 수 있으며 채팅/Git에는 붙여넣지 않는다. 파일을 잃으면 암호화 백업을 열 수 없다. `.gpg`와 복구 암호를 Git에 커밋하지 않는다.

PC에서 `Get-FileHash .\kms-final-v2-auto.tar.gpg -Algorithm SHA256`을 실행해 위 검증 결과의 SHA256과 비교한다. 이번 최종 묶음은 운영자가 PC 다운로드·복구 암호 별도 보관·SHA256 일치를 확인했다([증거](evidence/steps12-16/external-backup.json)). 이후 새 묶음도 목적지 hash 확인 전에는 완료로 표시하지 않는다. 같은 인스턴스에만 있으면 로컬 백업이다.

복구 암호를 별도 파일로 보유한 장치에서는 다음처럼 복호화할 수 있다. 이 명령의 출력은 민감한 평문이므로 개인 보관 디렉터리에서만 실행한다.

```bash
gpg --batch --pinentry-mode loopback \
  --passphrase-file /별도보관경로/kms-final-v2-auto.password \
  --output kms-final-v2.tar --decrypt kms-final-v2-auto.tar.gpg
```

이전 `export-backup.sh --final`은 사람이 직접 정한 암호를 쓰는 선택 사항이다. SSH 별칭/키 오류나 반복 암호 입력이 있으면 위 자동 생성 방식을 사용한다. 실패한 PowerShell 명령 이후 단독으로 출력된 “완료” 문구는 성공 증거가 아니다.

## 구성요소별 갱신·롤백

- admin-api: 새 이미지 import, 해당 Deployment만 변경, rollout 후 role/CSRF/Job/결과 회귀. KMS는 유지한다.
- bench: 이미지와 admin의 고정 bench image 설정을 함께 변경한다. 기존 run의 기록된 runtime/image는 바꾸지 않는다.
- server: 현재 형식/모든 KEK를 읽는지 별도 복원 경로에서 검증한 후 계획된 Static Pod 변경·기존 share unseal·과거 데이터 회귀를 수행한다.
- 공통 코드: 영향받는 제품 전체 테스트를 실행한다. 새/직전 호환 이미지 tar·digest와 키를 보존한다.
- TLS/SAR/SA 공개키: 실제 만료 전 파일을 안전하게 교체하고 해당 프로세스를 재시작한다. 원래 파일로 복귀 가능한 복사본·기존 share를 유지하고 신규/기존 연결을 검사한다.
- 역할 회수: roles는 요청마다 로드하므로 변경 직후 허용 여부를 검증한다. 필요 시 admin 재시작으로 CSRF 세션을 무효화하고 tailnet 기기/계정 회수를 별도로 수행한다.

이미 암호화된 Secret이 있을 때 원본 apiserver manifest로 단순 복귀하거나 KMS provider/과거 KEK를 지우지 않는다. 암호화 해제는 정상 복호화 상태에서 별도 명시적 migration으로 수행할 작업이며 자동 장애 복구에 포함하지 않았다.

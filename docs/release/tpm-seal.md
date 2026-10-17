# TPM 봉인 적용·이전·되돌리기 절차서

> **경고 — 먼저 읽으세요.** 이 절차는 KMS를 **여러 번 재시작**합니다. KMS가 재시작되면 **봉인(sealed) 상태**로 뜨고,
> 해제되기 전까지(Shamir 조각 3개를 입력하거나 TPM이 자동으로 풀 때까지) **클러스터 Secret 읽기가 중단**됩니다.
> apiserver는 암호화된 Secret을 복호화하지 못해 Secret을 쓰는 Pod의 시작·갱신이 실패할 수 있습니다.
> 조각 3명이 **지금 같은 자리에 있을 때** 시작하세요. (4단계의 첫 재시작은 반드시 조각 3개가 필요합니다.)
>
> **KMS 본체 묶음(C+B·감사·오류 형식·키 삭제)과 함께 적용하는 경우 [kms-core-apply.md](kms-core-apply.md)를 따르세요** (재시작 횟수를 줄인 통합 절차).
> 이 문서만 단독으로 적용하더라도 새 static pod 템플릿이 Transit 감사 디렉터리를 마운트하므로 먼저
> `sudo install -d -o 10001 -g 10001 -m 0700 /var/lib/custom-kms/transit-audit` 가 필요합니다(없으면 Pod가 시작하지 못합니다).

대상: 단일 노드(OCI) 운영 클러스터, 현재 봉인 방식 = Shamir(5/3, init 기록 v1).
코드 변경: `feat/tpm-seal-migration` 브랜치 (ADR-010). 이 문서의 명령은 **서버에서 사람이 그대로 실행**하도록 썼고,
작성 시점에는 어떤 운영 서버에서도 실행하지 않았습니다. 각 단계의 "확인"을 통과한 뒤에만 다음 단계로 가세요.

## 이 절차가 하는 일과 하지 않는 일

- **루트 키는 바뀌지 않습니다.** 메모리에 올라와 있는 *같은* 루트 키를 TPM에 다시 봉인하고, 같은 키로 새 조각 5개를 만들 뿐입니다.
  그래서 기존 Secret·암호문이 그대로 읽힙니다. 루트 키를 새로 만드는 경로는 이 기능에 없습니다.
- 이전 후에도 Shamir 조각은 **복구용**으로 남습니다 (TPM이 고장 나거나 blob이 손상되면 조각 3개로 해제).
- **하지 않는 것**: swtpm은 소프트웨어 TPM이라 하드웨어 보호가 아닙니다 (7. 보안 한계).

## 0. 준비물과 전제

| 항목 | 내용 |
|---|---|
| 사람 | 기존 Shamir 조각 보유자 3명 이상 (4단계), 새 조각을 나눠 받을 5명 (5단계) |
| 노드 | 호스트에 `/dev/tpm*`가 **없어야** 합니다 (있으면 vTPM 장치 번호가 `tpm1`이 되어 템플릿 경로와 어긋남). 확인: `ls /dev/tpm* 2>&1` → "No such file" |
| 코드 | 이 브랜치가 main에 merge되고, 서버 이미지(`SERVER_IMAGE` digest)가 새로 빌드·배포 가능한 상태 |
| 렌더 입력 | 기존 릴리스 값 + 새 항목 `TPM_GROUP_GID` (2단계에서 확인) |

## 1. swtpm 설치와 vTPM 장치 만들기

swtpm은 TPM 2.0을 소프트웨어로 흉내 내고, 커널의 `tpm_vtpm_proxy`가 그것을 `/dev/tpmrm0`으로 노출합니다.
KMS는 장치가 swtpm인지 실제 칩인지 모르고 같은 코드로 엽니다.

```bash
sudo apt-get update
sudo apt-get install -y swtpm swtpm-tools

# 커널 모듈 로드 + 부팅 시 자동 로드
sudo modprobe tpm_vtpm_proxy
echo tpm_vtpm_proxy | sudo tee /etc/modules-load.d/tpm_vtpm_proxy.conf
lsmod | grep tpm_vtpm_proxy          # 확인: 한 줄 출력

# swtpm이 권한을 낮춰 실행할 tss 계정/그룹 (이미 있으면 건너뜀)
getent group tss >/dev/null || sudo groupadd --system tss
getent passwd tss >/dev/null || sudo useradd --system --gid tss --no-create-home --shell /usr/sbin/nologin tss

# TPM 상태 디렉터리. 반드시 영속 경로(/run, /tmp 금지): 재부팅 후에도 같은 TPM이어야
# 저장된 blob이 열립니다. 이 상태가 사라지면 blob은 영구히 못 엽니다(복구 조각으로만 해제).
sudo install -d -m 0700 -o tss -g tss /var/lib/custom-kms/swtpm
```

systemd 서비스 (`--runas tss`: 가상 장치를 만든 직후 root 권한을 버립니다):

```bash
sudo tee /etc/systemd/system/swtpm-kms.service >/dev/null <<'UNIT'
[Unit]
Description=swtpm virtual TPM 2.0 for custom KMS
After=systemd-modules-load.service
Wants=systemd-modules-load.service
Before=kubelet.service

[Service]
Type=simple
ExecStart=/usr/bin/swtpm chardev --vtpm-proxy --tpm2 --tpmstate dir=/var/lib/custom-kms/swtpm,mode=0600 --runas tss
# 장치 노드가 생길 때까지 기다린 뒤에야 "시작됨"으로 취급 (kubelet이 그 뒤에 뜨도록)
ExecStartPost=/bin/sh -c 'for i in $(seq 1 50); do [ -c /dev/tpmrm0 ] && exit 0; sleep 0.2; done; echo "tpmrm0 did not appear" >&2; exit 1'
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

# kubelet(= KMS Pod)이 swtpm 뒤에 뜨도록 순서 고정. 순서가 어긋나 장치가 없을 때 Pod가
# 시작하면 일부 런타임이 /dev/tpmrm0를 빈 디렉터리로 만들어 장치 생성을 막을 수 있습니다.
sudo install -d /etc/systemd/system/kubelet.service.d
sudo tee /etc/systemd/system/kubelet.service.d/10-after-swtpm.conf >/dev/null <<'UNIT'
[Unit]
After=swtpm-kms.service
Wants=swtpm-kms.service
UNIT

sudo systemctl daemon-reload
```

**아직 서비스를 켜지 마세요.** 2단계의 udev 규칙을 먼저 넣어야 장치 권한이 맞게 생성됩니다.

## 2. 장치 권한 (udev) 과 KMS Pod 접근

`/dev/tpmrm0`을 `root:tss 0660`으로 만들고, KMS 컨테이너(uid/gid 10001)에는 `supplementalGroups`로 tss gid를 줍니다.

```bash
sudo tee /etc/udev/rules.d/60-kms-tpm.rules >/dev/null <<'RULE'
KERNEL=="tpmrm[0-9]*", SUBSYSTEM=="tpmrm", GROUP="tss", MODE="0660"
RULE
sudo udevadm control --reload

sudo systemctl enable --now swtpm-kms.service
sudo systemctl status swtpm-kms.service --no-pager        # 확인: active (running)
ls -l /dev/tpmrm0                                         # 확인: crw-rw---- 1 root tss ...
```

확인 결과가 `crw-rw---- root tss`가 아니면: `sudo udevadm trigger --subsystem-match=tpmrm` 후 다시 `ls -l`.
그래도 아니면 `sudo systemctl restart swtpm-kms` 한 번 (재시작 후 `ls -l`).

렌더 입력에 쓸 gid:

```bash
getent group tss | cut -d: -f3        # 예: 995  → release 값 JSON의 "TPM_GROUP_GID"에 문자열로 입력
```

## 3. 적용 전 정지 백업

기존 절차(`docs/release/recovery.md`)와 같습니다. **이 백업이 4단계 문제 시 되돌리는 기준점**입니다.
`<ID>`는 예: `pre-tpm-$(date -u +%Y%m%dT%H%MZ)`.

```bash
ID=pre-tpm-$(date -u +%Y%m%dT%H%MZ); echo $ID
sudo python3 scripts/backup-kms.py prepare --directory /var/backups/custom-kms/$ID
# KMS가 봉인 상태로 다시 뜹니다 → 조각 3개를 입력합니다 (TTY, 화면에 보이지 않음)
sudo python3 scripts/host-unseal.py
sudo python3 scripts/backup-kms.py resume --directory /var/backups/custom-kms/$ID
sudo python3 scripts/backup-kms.py status --directory /var/backups/custom-kms/$ID | grep -E '"stage"|"complete"'
# 확인: stage resumed, complete true
```

백업의 `kms-data.tar.gz`에는 `keys/`(= KMS 데이터, 이전 후에는 TPM blob 포함)가 들어갑니다.
swtpm 상태(`/var/lib/custom-kms/swtpm`)는 포함되지 않습니다 — 이 상태 없이 복원하면 blob은 못 열고 복구 조각으로 해제해야 합니다.

## 4. KMS Static Pod 교체 → 재시작 → 조각 3개로 해제

릴리스 값에 `TPM_GROUP_GID`를 넣고 **새 디렉터리**로 렌더합니다 (렌더 결과는 커밋하지 않습니다).

```bash
python3 scripts/render-release.py --values <비밀 없는 릴리스 값.json> --output /root/release-tpm-$ID   # 새 디렉터리여야 함
# 변경 확인: 기존 매니페스트와의 차이는 KMS_SEAL_*/KMS_TPM_DEVICE/supplementalGroups/tpm 볼륨(과 새 이미지)뿐이어야 합니다
sudo diff /etc/kubernetes/manifests/kms-static-pod.yaml /root/release-tpm-$ID/kms-static-pod.yaml
```

교체. kubelet은 `.`으로 시작하는 파일을 무시하므로 임시 파일로 만든 뒤 `mv`(원자적)로 바꿉니다.

```bash
sudo install -m 0600 /root/release-tpm-$ID/kms-static-pod.yaml /etc/kubernetes/manifests/.kms-static-pod.yaml.new
sudo mv /etc/kubernetes/manifests/.kms-static-pod.yaml.new /etc/kubernetes/manifests/kms-static-pod.yaml
# kubelet이 Pod를 다시 만듭니다. 이 순간부터 봉인 상태.
```

**지금 바로** 조각 3개로 해제:

```bash
until sudo test -S /run/custom-kms/admin/admin.sock; do sleep 2; done
sudo python3 scripts/host-unseal.py
```

점검:

```bash
sudo curl -sS --unix-socket /run/custom-kms/admin/admin.sock http://localhost/v1/sys/seal-status
# 확인: "sealed":false, "seal_type":"shamir", "recovery_available":false
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf get --raw '/readyz?verbose' | grep kms
# 확인: [+]kms-provider-0 ok  (이름은 구성에 따라 다를 수 있으나 kms 항목이 ok)
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf get secrets -A --no-headers | wc -l
# 확인: 오류 없이 개수 출력 (목록 조회는 모든 Secret을 KMS로 복호화합니다)
```

문제가 있으면 되돌리기: `sudo cp /var/backups/custom-kms/$ID/manifests/kms-static-pod.yaml` 를 위와 같은 방식(임시 파일 → `mv`)으로 복원하고 조각 3개로 해제.

## 5. TPM 으로 이전 (seal-migrate)

**봉인 해제 상태**에서만 가능합니다 (봉인 상태면 409). 이 요청이 실패하면 아무것도 바뀌지 않습니다
(TPM 봉인 → 같은 장치로 다시 풀어 같은 키인지 확인 → 기록 저장 순서이고, 기록 저장 실패 시 방금 만든 blob을 지웁니다).

응답에 **새 조각 5개가 한 번만** 나옵니다. 화면·셸 기록·로그에 남기지 않도록 root 전용 메모리 파일로 받습니다.

```bash
sudo sh -c 'umask 077; curl -sS -o /dev/shm/seal-migrate.json -w "%{http_code}\n" \
  --unix-socket /run/custom-kms/admin/admin.sock -X POST -H "Content-Type: application/json" \
  -d "{\"target\":\"tpm\"}" http://localhost/v1/sys/seal-migrate'
# 확인: 200
```

200이 아니면 오류 내용을 보고(조각 없음) 파일을 지운 뒤 멈추세요:

```bash
sudo python3 -c 'import json;print(json.load(open("/dev/shm/seal-migrate.json")).get("error"))'
sudo shred -u /dev/shm/seal-migrate.json
```

| 오류 | 의미 | 조치 |
|---|---|---|
| 409 `kms is sealed` | 봉인 상태 | 해제 후 재시도 |
| 409 `TPM seal already initialized` | 이전 시도의 blob이 남아 있음 | **덮어쓰지 않습니다.** blob의 출처를 확인한 뒤 사람이 판단 (확실히 불필요할 때만 `/var/lib/custom-kms/keys/seal/tpm/rootkey` 삭제) |
| 503 `TPM unavailable ... permission denied` | gid/udev/컨테이너 장치 접근 문제 | 아래 "알려진 위험" 참고 |
| 503 `TPM unavailable ... not found` | 장치 없음 | `ls -l /dev/tpmrm0`, `systemctl status swtpm-kms` |
| 500 `record and server state disagree` | init 기록과 서버 상태 불일치 | 중단하고 보고 (자동 수정 안 함) |

200이면 조각 5개를 **서로 다른 보관자에게** 전달합니다 (이 TTY에서만 출력):

```bash
sudo python3 - <<'PY'
import json
d = json.load(open('/dev/shm/seal-migrate.json'))
print(d['message'])
for i, s in enumerate(d['shares'], 1):
    print(f'--- share {i}/{len(d["shares"])} ---'); print(s)
PY
# 전달이 끝나면 즉시 파기하고 터미널 화면도 지웁니다
sudo shred -u /dev/shm/seal-migrate.json; clear
```

- 이 조각은 **TPM 해제가 실패할 때 쓰는 복구 조각**입니다 (`POST /v1/sys/unseal`에 3개). 기존 조각과 **같은 루트 키**의 조각이라
  이전 조각 묶음도 계속 유효합니다. **이전 조각과 새 조각을 섞어 3개를 넣으면 실패**하니 한 묶음에서만 3개를 쓰세요.
- 이전 조각을 무효로 만들 수는 없습니다 (그러려면 루트 키 교체가 필요하고 미구현). 이전 조각 보관자에게 폐기를 요청하는 것은 운영상 약속일 뿐입니다.

### 재시작 → 사람 개입 없이 해제되는지 확인

```bash
# 전체 봉인 상태 확인
sudo curl -sS --unix-socket /run/custom-kms/admin/admin.sock http://localhost/v1/sys/seal-status
# 확인: "seal_type":"tpm", "recovery_available":true

# KMS Static Pod 재시작 (매니페스트를 잠깐 치웠다 되돌림)
sudo mv /etc/kubernetes/manifests/kms-static-pod.yaml /var/lib/custom-kms/kms-static-pod.yaml.held
sleep 20     # Pod가 내려갈 시간 (확인: sudo crictl ps --name kms 에 아무것도 없음)
start=$(date +%s)
sudo mv /var/lib/custom-kms/kms-static-pod.yaml.held /etc/kubernetes/manifests/kms-static-pod.yaml

# 조각 입력 없이 sealed:false가 되는지 기다림 (최대 5분)
for i in $(seq 1 150); do
  r=$(sudo curl -sS --unix-socket /run/custom-kms/admin/admin.sock http://localhost/v1/sys/seal-status 2>/dev/null)
  case "$r" in *'"sealed":false'*) echo "auto-unseal OK after $(( $(date +%s) - start ))s"; break;; esac
  sleep 2
done
echo "$r"
# 확인: "sealed":false, "seal_type":"tpm"  — host-unseal.py 를 실행하지 않았음
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf get --raw '/readyz?verbose' | grep kms
```

sealed로 남으면 서버 로그에서 원인을 확인합니다 (`sudo crictl logs $(sudo crictl ps -a --name kms -q | head -1) 2>&1 | grep -i tpm`).
"봉인 상태로 기동"은 설계된 동작입니다 — 복구 조각 3개로 해제하세요 (`host-unseal.py`). 해제 후에도 기록은 tpm으로 유지됩니다.
장치 문제를 고쳤다면 조각 없이 `{}` 로 `POST /v1/sys/unseal`을 호출하면 TPM 해제를 다시 시도합니다:

```bash
sudo curl -sS --unix-socket /run/custom-kms/admin/admin.sock -X POST -H "Content-Type: application/json" -d '{}' http://localhost/v1/sys/unseal
```

### (선택) 호스트 재부팅 후 자동 복구 시간 기록

```bash
sudo reboot
# 재접속 직후:
echo "boot: $(uptime -s)"; date
for i in $(seq 1 180); do
  r=$(sudo curl -sS --unix-socket /run/custom-kms/admin/admin.sock http://localhost/v1/sys/seal-status 2>/dev/null)
  case "$r" in *'"sealed":false'*) echo "unsealed at $(date) (boot $(uptime -s))"; break;; esac
  sleep 5
done
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf get --raw '/readyz?verbose' | grep kms
```

`uptime -s`(부팅 시각)과 `unsealed at`의 차이가 "재부팅 → 사람 개입 없는 복구" 시간입니다. Shamir 모드의 같은 측정은
`docs/release/recovery.md`(조각 입력 시간 포함 418초)와 비교하세요. 결과를 `docs/release/verification.md`에 기록하세요.

## 6. 되돌리기 (TPM → Shamir)

> 5단계(`seal-migrate`)를 한 번이라도 실행하면 init 기록이 `format_version 2`가 되어 **이전 서버 이미지는 이 저장소를 읽지 못합니다**(기동 거부).
> 이 되돌리기는 봉인 *방식*만 Shamir로 바꿉니다. 이전 이미지로 복귀하려면 3단계의 정지 백업 복원이 필요합니다.

```bash
sudo sh -c 'umask 077; curl -sS -o /dev/shm/seal-migrate.json -w "%{http_code}\n" \
  --unix-socket /run/custom-kms/admin/admin.sock -X POST -H "Content-Type: application/json" \
  -d "{\"target\":\"shamir\"}" http://localhost/v1/sys/seal-migrate'
# 확인: 200 → 5단계와 같은 방법으로 새 조각 5개를 전달·파기
```

순서는 "새 조각 → 기록을 shamir로 저장 → TPM blob 삭제"입니다. blob 삭제가 실패하면 기록을 tpm으로 되돌리고 오류를 냅니다.
성공한 뒤 swtpm을 정리합니다:

```bash
sudo systemctl disable --now swtpm-kms.service
sudo rm /etc/systemd/system/kubelet.service.d/10-after-swtpm.conf && sudo systemctl daemon-reload
```

이후 KMS를 재시작하면 봉인 상태로 뜨고 **조각 3개가 필요**합니다 (Shamir 모드). `/var/lib/custom-kms/swtpm` 상태는 보존하세요 (삭제는 별도 판단).
Shamir로 되돌린 뒤에는 새 조각 묶음과 이전 조각 묶음이 둘 다 유효합니다 (같은 루트 키).

**조각 재발급**(Shamir → Shamir, 보관자 교체 등)은 `"target":"shamir"`를 Shamir 모드에서 호출하면 됩니다. 응답의 `warning`처럼
**이전 조각도 계속 유효**하므로 조각 유출 대응이 되지 못합니다.

## 알려진 위험 (적용 전에 읽으세요)

1. **컨테이너의 장치 접근 (가장 먼저 확인할 것).** 일반(비특권) 컨테이너는 런타임의 장치 cgroup 허용 목록에 없는 장치를 hostPath로
   마운트해도 `open`이 `operation not permitted`로 거부될 수 있습니다. 파일 권한(gid)과 별개의 제한입니다. 이 문서의 구성
   (hostPath + supplementalGroups)이 이 클러스터의 런타임에서 실제로 열리는지는 **작성 시점에 실행해 확인하지 못했습니다.**
   5단계 `seal-migrate`가 503(`permission denied` 또는 `operation not permitted`)이면 **아무것도 바뀐 것이 없습니다.** 대안:
   (a) 컨테이너에 `privileged: true`(강한 권한 확대 — 보안 검토 후 결정), (b) containerd CDI로 장치를 허용 목록에 추가.
   어느 쪽도 임의로 선택하지 않았으니 결과를 알려 주세요.
2. **swtpm 재시작 = KMS 재시작 필요.** swtpm이 재시작되면 장치가 새로 생성되어, KMS가 들고 있는 이전 장치 핸들이 끊어집니다.
   swtpm을 재시작했다면 5단계의 "Static Pod 재시작"을 같이 하세요.
3. **빈 디렉터리 함정.** swtpm보다 먼저 Pod가 떠서 런타임이 `/dev/tpmrm0`을 디렉터리로 만들었다면: `sudo systemctl stop swtpm-kms;
   sudo rmdir /dev/tpmrm0; sudo systemctl start swtpm-kms` 후 KMS 재시작.
4. **PCR은 기본 꺼짐** (`KMS_TPM_PCRS` 미설정). 켜려면 템플릿에 `KMS_TPM_PCRS=7` 같은 값을 추가하고 *다시 이전*(되돌리기 → 이전)해야
   합니다. 켜면 커널/펌웨어 업데이트로 PCR이 바뀔 때 자동 해제가 실패해 복구 조각이 필요합니다 (ADR-010).

## 7. 보안 한계 (정직하게)

- swtpm의 상태(`/var/lib/custom-kms/swtpm`)는 **디스크의 파일**입니다. TPM blob(`/var/lib/custom-kms/keys/seal/tpm/rootkey`)과 같은 디스크를 가진 공격자는
  swtpm 상태를 같이 가져가 blob을 열 수 있습니다. 따라서 이 배포는 *디스크 탈취로부터의 보호가 아닙니다.*
- 이 배포의 가치는 **"실제 TPM 장치 경로로 동작하는 구조의 검증"** 입니다: 장치 열기, 봉인/해제, 자동 해제, 복구 조각, 이전·되돌리기가
  운영 클러스터에서 동작함을 확인합니다.
- 실물 TPM 또는 클라우드 vTPM 인스턴스로 옮기면 **코드 수정 없이 장치(`KMS_TPM_DEVICE`)만 바꿔** 하드웨어 보호를 얻습니다.
  그 경우 이전 절차(5단계)를 새 환경에서 다시 수행하세요.
- 호스트 root는 신뢰 경계 안입니다 (`limitations.md`). 루트 키는 해제된 KMS 프로세스의 RAM에 있습니다.

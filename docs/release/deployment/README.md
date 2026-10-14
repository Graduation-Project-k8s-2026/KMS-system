# §12–16 적용·복구 도구

비밀 없는 원본 템플릿은 `deploy/oci-single-node/templates/`, renderer는 `scripts/render-release.py`다. 실제 운영 YAML·역할 파일·인증서는 이 디렉터리에 복사하지 않는다. renderer 예시는 `deploy/oci-single-node/release-values.example.json`을 사용한다.

현재 제품 배포는 이미 존재하므로 §2–11을 재실행하지 않는다. 이 단계는 새 제품 이미지를 배포하지 않고 기존 이미지에 호스트 운영 도구를 추가했다. 현재 manifest digest/ARM64/non-root는 상위 `release-lock.json`에 기록했다.

## 실행 순서

1. `go build -o /home/ubuntu/kms-tools/kms-verify ./cmd/kms-verify`, `scripts/test-kmsv2.sh`, 운영 소켓 probe.
2. `sudo python3 scripts/backup-kms.py prepare --directory /var/backups/custom-kms/<ID>` → 사람이 `host-unseal.py` → `backup-kms.py resume`.
3. root 전용 `/etc/kubernetes/encryption-config.yaml`을 KMS-first/identity-last로 생성. 이미 다른 provider가 있으면 자동 덮어쓰기 금지.
4. `patch-apiserver-kms.py --output <watched-directory-outside-candidate> --backup-dir <ID>`로 후보를 검토하고 같은 명령에 `--apply`로 적용. 해당 도구는 실제 UID/GID의 소켓 접속·운영 RPC·백업 checksum을 다시 검사한다.
5. readyz의 `kms-providers` 정상 후 `sudo env KUBECONFIG=/etc/kubernetes/admin.conf python3 scripts/rewrite-secrets.py --execute --backup-id <ID> --resume <private-checkpoint>`.
6. `migrate-secrets.py verify --evidence <report>` → `finalize --backup-dir <new-private-dir> --evidence <report>`. 전체 API 읽기와 raw etcd 객체 집합을 비교하고 새 snapshot 후 identity 제거·apiserver 정지 확인·재시작을 수행한다.
7. `rotate-kms-v2.py --backup <complete-ID> --state <private-state> --fixture <public-fixture> --evidence <report>`로 과거 ciphertext/Secret, 이전 KEK 보존, 새 envelope keyID를 확인한다. 전체 Secret 재쓰기에는 새 checkpoint를 쓴다.
8. `benchmark-release.py --host-admin --provider identity|kms-v2 --output <new-dir>`는 실제 설정과 provider 라벨을 대조한다. identity baseline은 KMS 연결 전에 실행해야 한다.
9. 회전 이후 다시 정지 백업. `restore-kms.py`와 `restore-control-plane.py`로 새 경로·별도 소켓·loopback 포트에서 검증한다.
10. 호스트 재부팅 후 기존 share unseal과 과거 값 확인. 외부 백업은 `export-backup-auto.py`로 암호 입력 없이 암호화한 뒤 별도 PC로 전송한다. 복구 암호는 따로 보관하고 목적지 checksum까지 확인해야 완료다. 직접 암호를 지정하는 `export-backup.sh`도 제공한다.

## 입력·권한·종료

- 모든 Python 도구는 `--help`를 제공한다. 운영 변경 도구는 root로 실행한다. 기본 Python과 PyYAML이 필요하다.
- patcher는 기본 후보 생성이며 `--apply`가 쓰기 동작이다. rewrite는 기본 dry-run이며 `--execute`가 쓰기 동작이다. 백업 `prepare`, migration `finalize`, rotation은 명시적 변경 명령이다.
- 성공 0, 실패 nonzero. 오류 출력에는 Secret 값이 포함되지 않는다. backup 실패 시 자동 삭제/초기화 없이 state와 held manifest를 보존한다.
- `host-unseal.py`는 TTY의 숨김 입력만 받는다. stdin 파이프·CLI share·Init을 지원하지 않는다.
- 이 도구들은 kubeadm Static Pod·단일 노드·기본 경로를 기준으로 검증했다. 다른 provider·스키마·경로·다중 노드에는 별도 migration 설계가 필요하다.

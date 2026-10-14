# 초기화·갱신·복구 경계

이번 실행은 임시 디렉터리에서 **암호화된 저장소를 별도 디렉터리에 복사하여 기존 share로 unseal하고 회전 전 ciphertext를 복호화**하는 `TestBackupRestoreIntoSeparateDirectory`를 포함한다. 운영 KMS, etcd snapshot, 호스트 재부팅, 외부 백업 복원은 실행하지 않았다.

## 저장소와 초기화

- 기존 `initialization.json`, keys/ 및 모든 KEK 버전을 함께 보존한다. 단일 프로세스 flock은 파일의 존재가 아니라 커널의 잠금 소유로 판단한다. `.lock`을 삭제해 우회하지 않는다.
- atomic Put의 file sync 이전/rename 이전 실패는 이전 값이 유지된다. directory sync 실패는 새 값이 이미 보일 수 있으므로 오류를 반환하고 읽기 재검증한다. 성공했다고 숨기지 않는다.
- Init은 검증 레코드와 metadata 한 파일을 확정한 후 share를 반환한다. 응답 유실 시 reinit/share 재발급을 하지 않는다. 새 share를 받지 못했고 별도 보관 share가 없다면 그 Root는 복구 불가다. 기존 저장소를 그대로 보존하고 운영자가 사건을 판단해야 한다.
- metadata 없는 기존 keys는 migration-required다. 자동 migration/삭제/새 Root 생성은 제공하지 않는다. 현재 사용자 단계(5.1)는 제품 초기화 전이며 실제 저장소 초기화를 실행하지 않았다.

## 갱신과 회수

- TLS 서버 인증서, JWT 공개키, SAR client 인증서를 별도 보호 경로에서 atomic replace하고 계획된 프로세스 재시작/기존 share unseal을 한다. 파일별 hostPath inode 교체의 영향을 고려한다.
- CA/SAN/만료 거부와 새 유효 인증서의 연결은 로컬 TLS 시험으로 확인한다. 실제 인증서 발급, Tailscale 기기 회수, SAR 인증서 갱신은 운영 후 별도 검증이다.
- 사람 역할 파일은 매 요청 읽는다. 삭제/강등 즉시 이전 CSRF cookie로 쓰기를 할 수 없다. CSRF는 30분 만료 및 프로세스 재시작으로 무효화된다.
- Transit은 로컬 서명 검증이므로 개별 SA 토큰의 즉시 회수를 주장하지 않는다. 짧은 projected 토큰 수명, SAR 권한 회수와 캐시 TTL(기본 10초), 필요 시 공개키/프로세스 재시작을 조합한다. 결과 ingest는 매 요청 TokenReview로 활성 Pod/SA 바인딩을 확인한다.
- 감사 완료 저장이 실패하면 503이어도 원래 작업은 commit됐을 수 있다. init을 반복하지 말고 상태/Job/run ID/결과를 재조회한다.

## 이후 클러스터 단계의 필수 순서

1. 해당 릴리스의 소스·이미지 digest 확정, 실제 ARM64 이미지 검사 및 최소권한 배포 준비.
2. 역할/CA/SAR/SA/RBAC/PVC 준비 후 KMS Static Pod 시작. 사람이 최초 init/share 보관 및 수동 unseal.
3. 공식 KMS v2 RPC/회전/재시작을 실제 배포 소켓에서 재검증.
4. 현재 manifest를 감시 디렉터리 밖에 보존하고 정지/백업 절차 검증. apiserver는 소켓/암호화 설정만 멱등 병합.
5. 기존 Secret 재쓰기(`rewrite-secrets.py` 기본 dry-run), 전체 현재 etcd Secret prefix 검증, identity 제거 후 다시 읽기/쓰기.
6. KMS/apiserver 전체 재시작과 호스트 재부팅, API가 불가한 상태의 호스트 UDS unseal, 과거 Secret 복구.
7. 별도 경로 etcd 복원 및 외부 백업 검증, 실제 RPO/RTO 기록.

**암호화된 데이터가 남아 있는데 KMS provider만 제거하는 롤백은 금지한다.** 이 작업에는 apiserver manifest를 수정하거나 자동 rollback하는 스크립트를 넣지 않았다. 배포 단계에 실제 manifest를 기준으로 리뷰 후 구현·실행해야 한다.

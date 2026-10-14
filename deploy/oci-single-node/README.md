# 검토용 릴리스 입력

이번 작업에서는 컨테이너 빌드와 배포를 실행하지 않았다. `templates/`를 그대로 kubectl에 전달하지 않는다.

- `Dockerfile`: 공통 source/verify/build, 별도 final target server/admin-api/bench/demo-app. 각 final image에는 해당 제품 실행 파일만 복사한다. 공식 base digest는 docs/release/base-image-lock.json과 일치한다.
- `release-values.example.json`: 실제 릴리스 SHA/제품 이미지 digest와 노드/인증 정보를 정한 뒤 별도 파일로 복사해 채운다. 예시의 REQUIRED 값은 배포값이 아니다.
- `python3 scripts/render-release.py --values <비밀 없는 실제 입력.json> --output <새 디렉터리>`: 미치환·이미지 미고정·중복 YAML을 실패시킨다. 적용은 하지 않는다.
- `storage.yaml`과 `serviceaccounts-rbac.yaml`을 이후 단계에서 먼저 준비해야 한다. CA 개인키·인증서·SAR kubeconfig·GUI 역할은 templates에 포함하지 않았다.
- `kms-static-pod.yaml`은 hostPath만 사용한다. API에 apply하지 않고 나중에 kubelet manifest 절차로 배포한다.
- 관리 8201은 loopback, ingest는 사설 IP:8202, Prometheus는 loopback이다. 관리 NodePort/Funnel 정의는 없다. 사용자 앱만 HTTPS NodePort 30443이다.
- 실제 Job spec은 `internal/jobs/service.go`의 단일 고정 템플릿이다. 수동 Job YAML의 별도 적용은 허용된 제출 run 기록을 만들지 못한다. `scripts/create-bench-fixture.sh` 또는 GUI의 생성 API를 사용한다.
- `encryption-config.yaml`은 identity를 포함한 최초 전환 입력이다. v2 호환 시험과 백업, apiserver manifest 보존/멱등 병합, Secret 재쓰기/prefix 검사 후 identity를 제거하는 운영 단계가 아직 남아 있다.

출시 입력 확정 전 G1~G10 검증 결과와 `docs/release/limitations.md`를 확인한다. 이미지 build/import/apply, 로그인/MFA, 최초 init/share 입력은 이번 결과에 포함되지 않는다.

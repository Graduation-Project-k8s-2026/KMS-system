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

## 5.4 빌드 컨텍스트 누락 수정 (2026-10-11 KST)

기준 커밋 `a98f70932ada1793cc467763dd24f76fb30d04f5`의 사용자 빌드에서
`test_versions_and_final_target_contract`가 `/src/docs/release/base-image-lock.json`
부재로 실패했다. 파일은 Git에 있으나 루트 `.dockerignore`의 `docs/` 규칙으로
전달되지 않았다. `.github/workflows/ci.yml`도 같은 검사가 읽는데 기존 `.github`
제외 규칙으로 누락되는 상태였다. 호스트 Docker는 29.1.3이며 Buildx가 없었다.

루트와 Dockerfile 전용 ignore 모두에 위 공개 검증 파일 두 개만 포함하는 예외를
넣고, 나머지 문서/CI·환경변수·개인키·kubeconfig 디렉터리·데이터·백업·증거는
제외한다. 검증을 skip하거나 파일 누락 시 성공하도록 변경하지 않았다.
Dockerfile/기반 digest/애플리케이션 코드는 바꾸지 않았다.

실행한 로컬 검증:

- Docker가 사용하는 공식 `github.com/moby/patternmatcher v0.6.0`의 ignorefile
  parser와 `MatchesOrParentMatches`로 두 ignore 파일을 각각 적용했다.
  필수 입력 9개 포함, 민감/불필요 경로 17개 제외 확인: PASS.
- 각 규칙으로 임시 컨텍스트를 만들었으며 각각 178개 파일이 포함됐다.
- 루트 ignore 적용 컨텍스트에서 `bash scripts/verify-release-contract.sh`:
  전체 `go test ./... -count=1`과 Python 8개 시험 PASS.
- Dockerfile 전용 ignore 적용 컨텍스트에서 Python 8개 시험 PASS.
- `git diff --check`: PASS.

에이전트는 이미지 빌드/컨테이너 실행/배포를 재실행하지 않았다. 위 검증은 실제
Docker 빌드 성공의 증거가 아니다. 수정 파일을 커밋하고 새 SHA 기반 KMS_TAG와
release 디렉터리를 만든 뒤 안전한 별도 Bash 빌드 블록을 다시 실행한다.
실패한 이전 태그는 재사용하지 않고, build가 모두 성공하기 전에 save/import로
넘어가지 않는다. Docker 캐시·기존 이미지·기존 데이터는 삭제하지 않는다.

근거: [Docker build context / dockerignore 공식 설명](https://docs.docker.com/build/concepts/context/#dockerignore-files).

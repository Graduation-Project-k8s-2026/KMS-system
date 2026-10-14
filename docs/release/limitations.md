# 완료 범위와 남은 제약

현재 결과는 5.2.2 구현 및 5.2.3–5.2.5 설정·데이터·검증 계약의 로컬 보완/시험이다. [최신 준비 판단](contract-readiness.md)을 함께 읽는다. 이미지·클러스터·운영 암호화의 최종 제출 완료로 표시하지 않는다.

- 현재 소스는 기준 SHA `34a37352b64c9028c431d523941c517f165feb67` 위의 **미커밋 작업 트리**다. 새 릴리스 SHA와 제품 image digest는 아직 없다. 공식 이미지 메타데이터 고정과 로컬 ARM64 ELF 빌드를 이미지 빌드라고 부르지 않는다.
- Tailscale CLI/서비스는 이 호스트 조사에서 사용할 수 없었다. 기존 사설 HTTPS 설계를 보존했으며 설치/로그인/Serve/Funnel/정책 변경은 하지 않았다. 실제 헤더 처리·외부 접속 차단·MFA·기기 회수는 미검증이다.
- Kubernetes Job/RBAC/TokenReview는 fake client로 정상/거부/실패 경로를 시험했다. 실제 SA 최소권한, Pod UID extras, projected token 갱신, Plugin hostPath 접근, Job scheduling/deletion은 배포 뒤 시험해야 한다.
- 세 모드의 제품 Job은 basic/roundtrip만 제공한다. API 호출 수가 아닌 왕복 작업 수를 `requests`로 집계한다. 세 모드 지연은 다른 계층의 왕복 시간이며 서로 같은 암호 연산의 비용으로 해석하면 안 된다. 서버 버전은 관리자 고정 provenance이며 attestation이 아니다.
- 운영 PVC/Prometheus TSDB는 템플릿과 실제 query/query_range client를 준비했다. 실제 target up, PVC 바인딩과 재시작 후 역사 데이터, 디스크 quota는 미검증이다. local PV 용량 선언은 quota가 아니다.
- 감사는 프로세스/디스크 실패 전에 확정된 사건만 보장한다. 요청 intent 후 crash는 완료 여부 불명으로 남을 수 있다. 감사 완료 실패 시 API 503이어도 작업이 commit됐을 수 있다. init 응답 유실 시 share 재발급은 없다.
- ENOSPC/EROFS는 syscall 오류 주입으로 시험했다. 실제 운영 볼륨을 채우거나 read-only로 바꾸지 않았다. 실제 SIGKILL과 별도 디렉터리 복원은 임시 테스트 저장소에서 수행했다.
- 구형 metadata 없는 키 저장소는 migration-required로 거부한다. 기존 Root/share를 검증하여 변환하는 운영 migration 도구는 이번 범위에서 제공하지 않는다. 데이터를 지워 해결하지 않는다.
- TLS/SA 공개키/SAR 인증서는 시작 시 로드한다. 변경에는 계획된 재시작/수동 unseal이 필요하다. hot reload/CRL/OCSP/개별 Transit JWT 즉시 회수는 제공하지 않는다. Transit 회수 지연은 토큰 수명과 SAR 캐시에 의존한다.
- 운영 apiserver v2 연결, 전체 Secret 재쓰기/실제 raw etcd prefix, identity 제거, 전체 호스트 재부팅, etcd snapshot 복원 및 외부 백업은 실행하지 않았다. 이 단계의 manifest 멱등 병합 도구도 실제 원본을 기준으로 이후에 구현해야 한다.
- `govulncheck v1.8.0`: 마지막 검사에서 호출 가능한 취약점 0건. 요구 모듈 `golang.org/x/crypto`의 사용하지 않는 `openpgp` 경고 GO-2026-5932는 남는다. openpgp import/call이 없다는 도달성 결과이며 해당 모듈 전체가 무취약하다는 뜻은 아니다.
- 단일 노드/Boot Volume, 호스트 관리자 신뢰, RAM 내 Root/KEK, 수동 Shamir unseal의 가용성 한계는 그대로다. HA, 멀티테넌트 격리, 하드웨어 Root 보호를 주장하지 않는다.

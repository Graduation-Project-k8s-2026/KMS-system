# 반복 성능 시험

같은 ARM64 단일 노드, 같은 bench image digest, 모드별 100회 왕복·동시성 1·1024 bytes·3회 반복. `identity`는 apiserver KMS 연결 전, `kms-v2`는 연결·identity 제거·KEK 회전 후다. Transit/Plugin은 두 조건 모두 KMS 서비스를 사용한다.

| apiserver 저장 | 모드 | 반복 | 요청/오류 | 평균 왕복/s ± 표본 SD | 반복별 p95 평균(ms) |
|---|---|---:|---:|---:|---:|
| identity | transit | 3 | 300/0 | 653.66 ± 61.42 | 1.781 |
| identity | plugin | 3 | 300/0 | 1872.34 ± 62.40 | 0.735 |
| identity | e2e | 3 | 300/0 | 122.79 ± 1.82 | 10.357 |
| kms-v2 | transit | 3 | 300/0 | 636.33 ± 73.77 | 1.746 |
| kms-v2 | plugin | 3 | 300/0 | 1821.17 ± 75.28 | 0.831 |
| kms-v2 | e2e | 3 | 300/0 | 118.18 ± 2.74 | 10.754 |

## 해석 범위

- `requests`는 왕복 수다. Transit/Plugin은 encrypt+decrypt, E2E는 Secret create+get+delete이며 서로 다른 경로다.
- 평균 p95는 각 trial p95의 평균이며, 원시 표본을 합친 pooled p95가 아니다. 3회 반복만으로 모집단 신뢰구간·일반 성능 우열을 주장하지 않는다.
- 신뢰된 호스트 관리자 loopback으로 Job을 생성했다. 실제 Job·projected token·TLS ingest는 사용했지만 Tailscale 사람 로그인 시연은 이 시험에 포함되지 않는다.
- 같은 노드의 apiserver·etcd·Prometheus·KMS가 자원을 공유한다. 운영 검증 조회/재쓰기와 일부 시간대가 겹치므로 정밀한 독립 환경 실험이 아니다.
- 오류와 실패한 trial도 JSON/통계에 보존한다. 이번 18개 trial의 상세 JSON은 두 하위 디렉터리에 있다.

## Seal 실험

`seal-lab.jsonl`은 `CGO_ENABLED=1 go run -tags=tpm_lab ./cmd/seal-lab --repeats 5`의 실제 출력이다. Shamir는 3-of-5 조각이 이미 준비된 처리 시간만 측정한다. Dev는 개발 baseline, TPM은 소프트웨어 simulator, K8sSeal은 fake client이며 실물 TPM·별도 실제 클러스터의 성능으로 해석하지 않는다. 운영 k8s-secrets 저장소는 사용하지 않았다.

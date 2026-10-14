# 5.2 시작 상태와 작업 범위

2026-10-11 KST, 현재 OCI ARM64 작업 디렉터리에서 조사했다.

- 경로: `/home/ubuntu/workspace/KMS-system`
- 기준 HEAD: `34a37352b64c9028c431d523941c517f165feb67`
- 브랜치: `infra/oci-single-node`
- origin: `https://github.com/kyum0731/KMS-system-oci-lab.git` (보존)
- module: `github.com/Graduation-Project-k8s-2026/KMS-system` (보존)
- 시작 작업 트리: tracked diff 없음, 사용자 소유 `?? docs/review/`. 해당 파일은 수정하지 않았다.
- OS/아키텍처: Ubuntu 24.04.4 LTS, aarch64.
- 실제 kubectl/client와 kubelet: v1.35.9, linux/arm64. 단일 노드 조회 성공.
- 기존 control plane, etcd, CoreDNS, kube-proxy, Flannel Pod는 Running.
- containerd/kubelet active. Tailscale CLI는 현재 호스트 PATH에 없으며 tailscaled inactive. 로그인·설치·Serve 설정 변경을 수행하지 않았다.
- 시작 Go: PATH에 설치 없음. 시스템 경로를 변경하지 않고 `/home/ubuntu/kms-tools/go`에 공식 ARM64 Go 1.26.9를 별도 설치했다. 배포 archive SHA256: `4a97373d49fcacdcf3694fea368a500b00ee3e963974f3e7514132717632f052`.
- 시작 module: Go 1.23.3/toolchain 1.23.4, Kubernetes 0.32.13. 지원되는 Go 1.26.9와 실제 cluster minor/patch에 맞춘 k8s.io 0.35.9로 변경했다.
- OCI CLI는 발견되지 않았다. NSG, Security List, Boot Volume 복구 및 외부 IPv4/IPv6 경계는 검증하지 않았다.

## 보존한 control-plane manifest

읽기 전용 해시 조사이며 내용을 출력하거나 변경하지 않았다.

| 파일 | SHA256 |
|---|---|
| etcd.yaml | 2281deaeb44da6aa1508235cd09c57e6b00b6f400bd646fc1c7a219217b4d31b |
| kube-apiserver.yaml | a3dbf236a62e566d4070cdd0d2caac536fb86ec94160ef7816f056f139ac8e37 |
| kube-controller-manager.yaml | 7b1d3e13246ab17a6624c18c58e3044018c347536aa31e7ee82d91f4c525c7fe |
| kube-scheduler.yaml | c455da13ed672213b1a8aa1951b2f7b788d86c900003e0c6a8d27540bae04fd5 |

## 코드 감사 결과

기존 구현: Transit AES-GCM/envelope, Shamir 알고리즘, HTTP 관리 UDS, JWT/SAR 라이브러리, 키 회전 scheduler, 직접 scrape dashboard, Transit CLI.

추가 필요: G1 영속 init/Root 검증, G2 원자적 저장/프로세스 락/전체 RMW 락, G3 수동 unseal 연결, G4 필수 TLS와 안전한 기본값, G5 공식 KMS v2, G6 사람별 인가/CSRF/allowlist, G7 실제 Job 제어, G8 별도 인증 ingest, G9 Prometheus/PVC/감사, G10 독립 앱. rev2 문서를 구현 완료의 증거로 취급하지 않았다.

이번 작업은 5.2.2 구현과 로컬 시험이다. 5.3 이후 컨테이너 pull/build/import, 배포, 실제 init/unseal, 기존 Secret 읽기/쓰기, apiserver 암호화 설정 변경, 호스트 재부팅은 수행하지 않았다. 테스트는 임시 저장소·공개 fixture·fake Kubernetes API만 사용한다.

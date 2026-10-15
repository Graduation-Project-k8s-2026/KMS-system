# §16.1 완료 상태

2026-10-12 KST. PASS의 범위와 미검증 시나리오는 [verification.md](verification.md)에 구분한다.

- [x] 기존 checkout·작업 트리·미커밋 사용자 변경 보존.
- [x] 기존 G1–G10 코드에 전체 자동 회귀 실행. 독립 앱의 실제 배포는 아래 보류.
- [x] 제품 세 이미지의 단일 실행 파일·ARM64·비root·실제 digest 확인.
- [x] 신규 호스트 CLI·입력·오류·복구 계약과 시험 제공.
- [x] GUI viewer/Host/CSRF·Transit TLS/JWT/SAR 자동 회귀 및 실제 인증 벤치 완료.
- [x] 운영 PVC·Prometheus target/과거 데이터·실제 Job/결과 제출 확인.
- [ ] 사용자 데모 앱 실제 배포·HTTPS 시나리오: §10 사용자 보류.
- [x] Plugin 전용 소켓·강한 권한을 Transit/E2E와 구분.
- [x] 공식 v2 client와 실제 apiserver 연결 검증.
- [x] 전체 현재 Secret 재쓰기·raw envelope·identity 제거 확인.
- [x] KEK 회전·이전 KEK 보존·과거 ciphertext/Secret 읽기 확인.
- [x] 실제 호스트 재부팅·기존 share unseal·과거 ciphertext/Secret·결과 23개·감사 파일 4개 보존, 서비스 복구 검증.
- [x] 일관된 정지 백업과 별도 경로 KMS 복원 실제 실행.
- [x] 최종 별도 etcd/API/KMS 통합 복원과 과거 Secret API 읽기 검증.
- [x] 암호화 외부 백업 반출·목적지 checksum 확인: 사용자가 PC 다운로드·복구 암호 별도 보관 및 SHA256 일치 확인.
- [ ] 운영 인증서·SA 공개키·SAR·모든 실제 기기/계정의 갱신·회수: 자동 시험 이외 실제 운영 시연은 미검증.
- [x] 단일 노드·Flannel/local PV·Shamir·메모리/호스트 관리자 신뢰 한계 명시.
- [x] 구성도·구현표·설정계약·실제 image lock·시험표·benchmark JSON/차트·복구·시연·제약 문서 마련.

외부 작업과 사람이 필요한 share 입력을 수행하지 않은 채 체크하지 않는다. §18은 작업 범위에서 제외했다.

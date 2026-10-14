# 최종 시연 절차

§10의 데모 앱 시나리오를 보류한 현재 범위다. 운영 share/JWT/개인키/Secret 원문을 화면 녹화·로그에 넣지 않는다. 아래 공개 시험 문자열만 사용할 수 있다.

1. [구성도](architecture.md)와 [image lock](release-lock.json)을 보여준다. 제품 세 이미지와 보류된 독립 앱을 구분한다.
2. 실제 tailnet의 admin/viewer로 사설 HTTPS에 접속한다. viewer 쓰기 403과 Host/CSRF 차단의 자동 시험 증거는 verification.md에 있다. 사람 로그인·외부 기기 검사는 별도 실제 시연 항목이다.
3. §10을 재개한 뒤에만 데모 앱 HTTPS NodePort 화면을 시연한다. 현재 미배포 상태를 성공으로 표시하지 않는다.
4. GUI에서 `basic/roundtrip`, count 100, concurrency 1, payload 1024의 Transit Job을 생성한다. Job UID, run ID, submitted/stored 결과를 확인한다.
5. [반복 결과](benchmark/README.md)와 [차트](benchmark/throughput.svg)를 열어 Transit/Plugin/E2E를 각각 설명한다. E2E는 create/get/delete 왕복이다.
6. `sudo python3 scripts/migrate-secrets.py verify --evidence /tmp/kms-demo-verification.json`으로 공개 시험 Secret·전체 API 읽기·raw prefix·identity 제거 상태를 검증한다. 전체 Secret YAML을 출력하지 않는다.
7. [KEK 회전 증거](evidence/steps12-16/rotation.json), [복원 증거](evidence/steps12-16/restore.json), 최신 verification.md를 제시한다. 단순 prefix만으로 KEK 버전을 판정하지 않고 EncryptedObject의 keyID를 검사했다.
8. 단일 노드·사람이 필요한 Shamir·RAM 내 키·호스트 관리자 신뢰·외부 백업 상태를 설명한다.

## 장애 시

- KMS sealed: 호스트의 `sudo python3 scripts/host-unseal.py`로 기존 share만 입력한다. Init을 반복하지 않는다.
- 관리 화면 불가: 먼저 호스트 UDS와 apiserver readyz를 확인한다. GUI가 올라올 때까지 unseal을 미루지 않는다.
- apiserver 불가: `crictl`로 KMS/etcd/apiserver 상태를 확인한다. 백업의 `state.json`·`held/`를 확인해 해당 단계의 resume 도구를 사용한다.
- KMS가 연결된 후 원본 apiserver manifest로 즉시 되돌리지 않는다. 암호화 데이터를 읽는 provider와 모든 KEK를 유지한다.
- 외부 백업·재부팅 증거가 아직 미검증이면 시연에서 해당 항목을 완료라고 말하지 않는다.

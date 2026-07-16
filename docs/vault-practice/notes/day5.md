## Day 5 - Seal/Unseal
- 루트 키 계층: unseal key(들) -> 루트 키 -> keyring(my-key 등) -> 실제 데이터
  (Day 2의 DEK/KEK 봉투암호화가 한 겹 더 반복되는 구조)
- Shamir's Secret Sharing: 루트 키를 N개 조각으로 나눔, threshold개 이상 모여야 재구성
  - 기본값 5 shares / threshold 3
  - 목적: 단 한 명이 단독으로 시스템을 열 수 없게 함 (권한 분산)
- 실습: file storage backend로 실서버 구동 -> init -> sealed 확인 -> unseal 3개 -> 정상 작동 확인 -> seal -> 다시 막힘 확인
- 핵심 증명: 디스크(./data)를 통째로 훔쳐도 무의미함, 루트 키는 항상 조각으로부터 재구성되고 디스크엔 저장 안 됨
- Auto-Unseal: 실무에선 사람이 매번 조각 넣지 않고, 클라우드 KMS/HSM이 루트 키를 봉투 암호화로 보호 -> 재귀적 구조 (KMS로 또 다른 KMS를 지킴)

- 설계 질문 1: 우리 KMS의 "루트 키"는 어떻게 부트스트랩할까?
  (Shamir 방식을 직접 구현? 아니면 클라우드 KMS/K8s Secret에 위임?)
- 설계 질문 2: 쿠버네티스 위에서 재시작(Pod 재배포)될 때마다 unseal을 어떻게 자동화할까?
  -> 완전 자동화하면 편하지만 "디스크 도난 시 안전"이라는 오늘의 핵심 보장이 약해짐 (트레이드오프)
- 설계 질문 3: Vault Auto-Unseal처럼, 우리도 K8s Secret이나 외부 KMS에 루트 키 보호를 위임할 것인가?

## 추가 정리 - Initialize vs Sealed 구분
- Initialize: 서버가 "처음 setup을 완료했다"는 일회성 이벤트.
  루트 키 생성 + Shamir 조각화 + keyring 초기 구조를 디스크에 만듦.
  한 번 하면 재실행 불가 ("already initialized" 에러). -> 디스크에 영구적으로 남는 상태.
- Sealed: "루트 키가 지금 메모리에 로드되어 있는가"를 나타내는 상태.
  서버 프로세스 재시작마다 메모리가 비워지므로 매번 새로 unseal 필요. -> 그때그때 리셋되는 상태.

  | Initialized | Sealed | 의미 |
  |---|---|---|
  | false | true  | setup 자체가 안 됨 (루트 키도 없음) |
  | true  | true  | setup 됐지만 루트 키가 지금 메모리에 없음 |
  | true  | false | 정상 사용 가능 |

- sealed 상태에서의 에러는 403(permission denied)이 아니라 503(Vault is sealed)
  -> "권한 없음"이 아니라 "서버가 아예 처리 불가능한 상태"라는 뜻. Root Token이 있어도 무관하게 거부됨.

## 재부팅 실험으로 최종 확인한 것
1. secret/test에 foo=bar 저장 (디스크에 암호화되어 기록됨)
2. 서버 프로세스 완전히 껐다 켬 -> Initialized: true(유지), Sealed: true(리셋됨)
3. 조각 3개로 재unseal
4. vault kv get secret/test -> foo: bar 그대로 살아있음 확인
=> 사라지는 건 "루트 키(메모리)"뿐, 데이터(디스크)는 계속 안전하게 보존됨
   (dev 모드는 메모리 저장이라 재시작 시 데이터 자체가 통째로 소실 - 정반대 지점)

## 실습 중 겪은 시행착오
1. dev 모드(-dev)와 실제 서버(-config)를 헷갈림
   -> dev 모드가 init+unseal을 자동 처리해서 Shamir의 실제 동작을 가리고 있었던 것뿐
   -> "-dev를 써서 조각이 나뉜다"가 아니라 "-dev를 안 써서 원래 동작(5조각/threshold3)이 드러난 것"
2. 새 서버(vault-real)에 kv 엔진 미활성 상태로 kv put/get 시도 -> 403 에러
   -> dev 모드가 자동 마운트해주던 secret/ 엔진을, 진짜 서버에선 직접 enable해야 함
   -> 해결: vault secrets enable -path=secret kv-v2 (Day 2 개념이 실전에서 재현됨)

## 자동화 스크립트 (학습용 한정, 실무 부적합함을 인지하고 사용)
- unseal_keys.txt: 조각 3개를 한 파일에 저장
- unseal.sh: 파일을 읽어 자동으로 3번 unseal 실행
- 주의: 조각을 한 파일/한 곳에 모아두는 순간, Shamir가 막으려던
  "단독 접근 방지"라는 보안 목적이 사실상 무의미해짐 (편의 vs 보안 트레이드오프를 직접 체감)

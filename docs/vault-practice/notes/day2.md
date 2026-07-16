Day 2 — transit 엔진: 저장 없이 암복호화만
한 일
transit 엔진 활성화 → 암호화 키 생성 → 암호화/복호화 실행
핵심 명령어
bash# 엔진 활성화 (dev 모드에서도 기본으로는 꺼져있음)
vault secrets enable transit

# 암호화 키 생성 (실제 키 값은 절대 노출 안 됨)
vault write -f transit/keys/my-key
vault read transit/keys/my-key   # 메타데이터만 보임

# 암호화
vault write transit/encrypt/my-key plaintext=$(base64 <<< "hello kms")
# → ciphertext: "vault:v1:AbCdEf..."

# 복호화
vault write transit/decrypt/my-key ciphertext="vault:v1:붙여넣기"
echo "나온_base64값" | base64 -d

# 현재 마운트된 엔진 목록 확인
vault secrets list
vault read sys/mounts
개념 정리
1) kv vs transit
kv (Day 1)transit (Day 2)저장하는 것값 자체아무것도 저장 안 함Vault가 하는 일암호화+저장+복호화암복호화 연산만실제 클라우드 KMS와 비교Azure Key Vault "시크릿"에 가까움AWS/GCP KMS 기본 모델
2) 엔진(engine)은 "마운트"되는 것

secret/, transit/은 리눅스 파일 경로가 아니라 Vault API 내부의 논리적 이름공간(라우팅 이름)
dev 모드는 편의상 secret/(kv)을 미리 마운트해줌 — "원래 켜져 있던" 게 아님
운영 환경에서는 kv든 transit이든 관리자가 직접 enable 필요
실제 데이터가 앉는 물리적 위치는 별도의 저장 백엔드 설정이 결정 (dev 모드=메모리라 서버 끄면 다 날아감, 운영 모드=파일/Raft/Consul)

3) 봉투 암호화(envelope encryption) 실물

transit/encrypt 호출 시 내부적으로: 임시 DEK 생성 → DEK로 평문 암호화 → my-key(KEK)로 DEK를 감쌈(wrap) → DEK는 폐기, KEK만 영구 보관

4) ciphertext 포맷 — vault:v1:AbCdEf...
부분의미vault포맷 식별자 ("이건 Vault transit 결과물")v1이 데이터를 암호화한 키 버전 번호AbCdEf...실제 암호문 + IV 등 부속정보

핵심: 버전 정보가 ciphertext 안에 자체 내장돼 있어서, 별도 메타데이터 없이도 Vault가 알아서 맞는 키 버전을 찾아 복호화함
키를 회전(rotate)해서 v2, v3가 생겨도, v1으로 암호화된 옛날 데이터는 그대로 복호화 가능 (GCP KMS도 동일 원칙: 회전은 새 버전만 만들 뿐, 이전 버전을 지우지 않음)

# 내가 물어본 것 → 답

"kv는 원래 켜져있던 거고 transit만 활성화한 거지?" → 정확히는 "dev 모드가 편의상 kv를 미리 마운트해준 것"이지, kv가 기본으로 항상 켜져있는 건 아님. 운영 환경에선 둘 다 직접 켜야 함.
"경로는 서버상의 물리 경로야?" → 아니요, API 라우팅용 논리적 이름(마운트). 물리적 저장 위치는 별도의 저장 백엔드가 결정.
"vault:v1:값에서 vault랑 v1은 뭐야?" → vault=포맷 식별자, v1=키 버전 번호. ciphertext가 자기 버전을 스스로 기억하고 있어서 복호화 시 별도 정보 없이 알아서 맞는 키를 찾음.

오늘까지 쌓인 설계 질문 (Day 7에서 결정할 것들)

우리 KMS는 kv형(저장까지) vs transit형(연산만) — 실제 클라우드 KMS는 후자에 가까움
Vault처럼 엔진 단위 모듈화를 할 것인가
ciphertext에 키 버전을 자체 내장시킬 것인가, 별도 메타데이터(DB)로 관리할 것인가


Day 2 — transit 엔진: 저장 없이 암복호화만
명령어
bashvault secrets enable transit
vault write -f transit/keys/my-key
vault read transit/keys/my-key   # 메타데이터만, 실제 키 자료는 안 보임

vault write transit/encrypt/my-key plaintext=$(base64 <<< "hello kms")
vault write transit/decrypt/my-key ciphertext="vault:v1:붙여넣기"
echo "나온_base64값" | base64 -d

vault secrets list        # 마운트된 엔진 목록
vault read sys/mounts
핵심 개념

kv vs transit: kv=저장+암복호화, transit=암복호화 연산만 (실제 클라우드 KMS는 transit 모델에 가까움)
엔진 = "마운트": secret/, transit/은 리눅스 파일 경로가 아니라 Vault API 상의 논리적 라우팅 이름. dev 모드가 편의상 kv를 미리 마운트해줄 뿐, 원래 항상 켜져 있는 게 아님
실제 물리 저장 위치는 별도의 **저장 백엔드(storage backend)**가 결정 (dev=메모리, 운영=file/Raft/Consul)
봉투 암호화 실물: encrypt 호출 시 내부적으로 임시 DEK 생성 → DEK로 암호화 → my-key(KEK)로 DEK를 감쌈 → DEK 폐기
ciphertext 포맷 vault:v1:AbCdEf...:

vault = 포맷 식별자
v1 = 암호화에 쓴 키 버전 (self-describing, 별도 메타데이터 불필요)
나머지 = 암호문 + IV 등 부속정보
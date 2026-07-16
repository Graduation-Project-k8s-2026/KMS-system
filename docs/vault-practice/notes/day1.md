# Day 1 — kv 엔진: 저장 + 접근 위임
한 일
Vault 설치 → dev 서버 실행 → 시크릿 저장/조회
핵심 명령어
bash# 설치 (WSL/Ubuntu)
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y vault

# dev 서버 실행 (별도 터미널에서 계속 켜둠)
vault server -dev

# CLI 연결
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='(Root Token)'
vault status

# 시크릿 저장 / 조회
vault kv put secret/db-config username="admin" password="mypassword123"
vault kv get secret/db-config
개념 정리

kv 엔진: 값을 저장하고, Vault가 암호화/복호화를 대신 처리 (사용자는 위임만 함)
"키"라는 단어의 3가지 뜻 — 여기서 헷갈리기 쉬워서 못 박음:

부르는 이름정체볼 수 있나데이터 keyusername, password 같은 이름표✅pathsecret/db-config (저장 위치)✅암호화 key실제 암호화에 쓴 열쇠❌ 절대 못 봄
내가 물어본 것 → 답

"암호화에 쓴 키를 볼 수 있어?" → 못 본다. KMS의 제1원칙: 평문 암호화 키는 서비스 밖으로 절대 안 나감 (AWS KMS도 동일 원칙).
이 "볼 수 없는 암호화 key"도 사실 계층 구조(DEK가 KEK에 감싸짐) → Day 2에서 실물로 확인.


Day 1 — kv 엔진: 저장 + 접근 위임명령어
bash# 설치
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y vault

# dev 서버 (터미널 A, 계속 켜둠)
vault server -dev

# 연결 (터미널 B)
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='(Root Token)'
vault status

# 시크릿 저장/조회
vault kv put secret/db-config username="admin" password="mypassword123"
vault kv get secret/db-config핵심 개념

kv 엔진: 값을 저장하고, Vault가 암호화/복호화를 대신 처리
"키"의 3가지 뜻 — 헷갈리기 쉬운 포인트:
 부르는 이름정체볼 수 있나데이터 keyusername, password 이름표✅pathsecret/db-config (저장 위치) ✅암호화 key실제 암호화에 쓴 열쇠❌ 절대 못 봄
KMS 제1원칙: 평문 암호화 키는 서비스 밖으로 절대 안 나감 (AWS KMS도 동일)
암호화 key도 계층 구조(DEK가 KEK에 감싸짐) → Day 2에서 실물 확인
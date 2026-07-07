## Day 4 - 접근 제어 (Vault Policy)
- Vault 정책 = path + capabilities. 기본값은 deny-by-default (명시 허용만 통과)
- capabilities: create/read/update/delete/list/sudo/deny
  - encrypt/decrypt/rotate 같은 연산은 'update'로 표현됨 (HTTP POST 기반)
- 실습: app-policy(암복호화만) vs admin-policy(키 관리까지) 분리
  -> app-policy 토큰으로 rotate 시도 -> permission denied 확인
- 핵심 원칙: '이 키를 쓸 수 있다'와 '이 키를 관리할 수 있다'는 별개 권한이어야 함
  (AWS KMS의 키 관리자/키 사용자 분리와 동일한 철학)
- 글롭 패턴 주의: "path/*"는 그 뒤 전부를 포함 -> 의도보다 넓은 권한 부여 위험

- 설계 질문 1: 우리 KMS는 권한을 어느 단위로 나눌까?
  (키별? 네임스페이스별? 서비스 어카운트별?)
- 설계 질문 2: 쿠버네티스 RBAC(어떤 Pod/ServiceAccount가 API 호출 가능)와
  KMS 자체 정책(어떤 키에 뭘 할 수 있는지)을 어떻게 이어붙일까?
  -> 둘 다 있으면 이중 방어가 되지만, 설계/구현 복잡도가 올라감

## Day 4 실습 결과
- app-policy 토큰으로 encrypt 실행 -> 200 성공 (ciphertext 받음)
- 같은 토큰으로 rotate 실행 -> 403 permission denied
- 확인됨: 하나의 토큰이 '허용된 경로'와 '허용 안 된 경로'에서 다르게 반응함
  = deny-by-default + 명시적 허용 규칙이 실제로 서버에서 강제되고 있음을 증명


Day 4 — 접근 제어 (Vault Policy)
명령어
bashcat > app-policy.hcl << 'EOF'
path "transit/encrypt/my-key" { capabilities = ["update"] }
path "transit/decrypt/my-key" { capabilities = ["update"] }
EOF
vault policy write app-policy app-policy.hcl

cat > admin-policy.hcl << 'EOF'
path "transit/keys/*"    { capabilities = ["create","read","update","delete","list"] }
path "transit/encrypt/*" { capabilities = ["update"] }
path "transit/decrypt/*" { capabilities = ["update"] }
EOF
vault policy write admin-policy admin-policy.hcl

vault token create -policy="app-policy"   # 제한된 토큰 발급
export VAULT_TOKEN='(발급받은 토큰)'

vault write transit/encrypt/my-key plaintext=$(base64 <<< "test")   # 성공 (200)
vault write -f transit/keys/my-key/rotate                            # 실패 (403 permission denied)
핵심 개념

Vault 정책 = path + capabilities, 기본값은 deny-by-default (명시 허용만 통과)
경로(path)는 리눅스 파일 경로가 아니라 API URL 패턴 — 파일이 아니라 "그 URL로 오는 요청을 처리하는 서버 내부 코드(핸들러)"를 가리킴
capabilities는 HTTP 동작에 대응 (encrypt/decrypt/rotate 등은 내부적으로 POST라 update로 표현됨)
토큰 검증 흐름: 토큰 문자열 자체는 그냥 신분증 번호일 뿐 → 서버가 그 토큰에 연결된 정책을 조회 → 요청 경로가 정책 허용 범위 안인지 검사 → 허용/거부. 진짜 권한 정보는 서버 쪽에 저장돼 있음
실습 결과: 같은 토큰이 encrypt는 허용, rotate는 거부 → "이 키를 쓸 수 있다"와 "이 키를 관리할 수 있다"는 별개 권한이라는 원칙을 실물로 증명
글롭 패턴(*) 주의: "path/*"는 그 뒤 전부를 포함 → 의도보다 넓은 권한 부여 위험
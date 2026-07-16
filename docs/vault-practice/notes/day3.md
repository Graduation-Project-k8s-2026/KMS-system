
## Day 3 정정
- 오해: '두 버전 키가 같은 암호문을 둘 다 풀 수 있다' -> 틀림
- 정확: 각 ciphertext는 자기 버전의 키로만 복호화됨 (v1 ct는 v1 키만, v2 ct는 v2 키만)
- 회전이 하는 일: keyring에 새 버전을 '추가'하고, 옛 버전들은 지우지 않고 유지
  -> 그래서 옛 ciphertext도 여전히 풀리는 것이지, 새 키가 옛 걸 대신 푸는 게 아님
- 이게 중요한 이유: 만약 새 키가 옛 암호문도 풀 수 있다면 회전의 보안 의미가 없어짐
  (v1 유출 시에도 v2로 암호화한 데이터는 안전해야 함)

## Day 3 추가 정정 - rewrap과 min_decryption_version
- rewrap은 삭제가 아니라 '복사본 생성': OLD_CT(v1)는 그대로 남고, NEW_CT(v2)가 새로 만들어짐
- Vault는 ciphertext를 저장 안 하므로, OLD_CT를 NEW_CT로 바꾸는 건 애플리케이션(우리)의 책임
- v1을 진짜로 막으려면 3단계가 필요함:
  1) rotate (새 버전 생성)
  2) rewrap으로 기존 데이터 전부 마이그레이션 (DB의 ciphertext 값을 새 버전으로 교체)
  3-a) min_decryption_version 설정 -> 복호화 거부, 키 자체는 keyring에 남아있음
  3-b) min_available_version 설정 -> 키 자체를 삭제, 되돌릴 수 없음 (해당 버전 데이터 영구 손실 위험)
- 설계 질문: 우리 KMS도 이 3단계(rotate -> rewrap -> lock) 마이그레이션 흐름을
  표준 절차로 문서화하거나 자동화할 것인가?



Day 3 — 키 회전(rotation)
명령어
bashvault write transit/encrypt/my-key plaintext=$(base64 <<< "before rotation")   # v1 ciphertext 생성
vault write -f transit/keys/my-key/rotate                                      # 회전 -> v2 생성
vault read transit/keys/my-key                                                 # keys map[1:... 2:...]

vault write transit/decrypt/my-key ciphertext="OLD_CT(v1)"     # 회전 후에도 여전히 복호화됨

vault write transit/rewrap/my-key ciphertext="OLD_CT"          # 평문 노출 없이 최신 버전으로 재암호화(새 사본 생성)

vault write transit/keys/my-key/config min_decryption_version=2   # 특정 버전 이하 복호화 거부
핵심 개념 (정정 포함)

rotate = keyring에 새 버전 추가, 옛 버전은 삭제 안 됨 (옛 버전이 유지되니까 옛 ciphertext도 계속 풀림)
⚠️ 오해 정정: "두 버전이 같은 암호문을 둘 다 푼다"는 틀림. 각 ciphertext는 자기 버전의 키로만 복호화됨 (v1 ct는 v1 키만, v2 ct는 v2 키만). 새 키가 옛 암호문을 대신 푸는 게 아니라, 옛 키가 삭제 안 되고 살아있는 것뿐
rewrap = 삭제가 아니라 사본 생성. OLD_CT(v1)는 그대로 남고, NEW_CT(v2)가 새로 만들어짐. 평문을 노출하지 않아서 권한 없는 프로세스에게도 맡길 수 있음
Vault는 ciphertext를 저장 안 함 → OLD_CT를 NEW_CT로 실제 교체하는 건 애플리케이션(우리) 책임
v1을 진짜로 막으려면 3단계: ① rotate ② rewrap으로 전부 마이그레이션 ③ min_decryption_version(복호화 거부, 키는 남음) 또는 min_available_version(키 자체 삭제, 복구불가)
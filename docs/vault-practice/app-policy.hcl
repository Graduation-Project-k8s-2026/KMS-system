# my-key로 암호화/복호화만 허용 (키 관리는 불가)
path "transit/encrypt/my-key" {
  capabilities = ["update"]
}

path "transit/decrypt/my-key" {
  capabilities = ["update"]
}

#!/bin/bash
# Vault dev/학습 환경 전용 - 조각 파일을 읽어 자동으로 unseal
# 주의: 실무에서는 조각을 한 파일에 모아두면 안 됨 (Shamir 방식의 보안 의미가 사라짐)

set -e

KEYS_FILE="$(dirname "$0")/unseal_keys.txt"

if [ ! -f "$KEYS_FILE" ]; then
  echo "unseal_keys.txt 파일이 없습니다: $KEYS_FILE"
  exit 1
fi

while IFS= read -r key; do
  [ -z "$key" ] && continue
  vault operator unseal "$key"
done < "$KEYS_FILE"

echo "---"
vault status

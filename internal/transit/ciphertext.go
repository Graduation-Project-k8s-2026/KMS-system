// Package transit: keys(KEK 공급)와 crypto(봉투 암호화)를 엮어, 사용자에게
// 노출되는 Encrypt/Decrypt 연산을 제공한다.
package transit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ciphertextPrefix: 우리 KMS가 만든 암호문 문자열임을 식별하는 접두사.
const ciphertextPrefix = "kms"

var (
	// ErrInvalidCiphertextFormat: "kms:v{n}:{base64}" 형태를 갖추지 못했을 때
	// (접두사 불일치, 콜론 개수 오류 등) 반환.
	ErrInvalidCiphertextFormat = errors.New("transit: invalid ciphertext format")
	// ErrInvalidCiphertextVersion: 버전 부분이 "v" 접두사를 가진 1 이상의
	// 정수가 아닐 때 반환.
	ErrInvalidCiphertextVersion = errors.New("transit: invalid ciphertext version")
	// ErrInvalidCiphertextEncoding: envelope 부분이 유효한 base64가 아닐 때 반환.
	ErrInvalidCiphertextEncoding = errors.New("transit: invalid ciphertext base64 encoding")
)

// EncodeCiphertext는 (version, envelope)를 사용자에게 노출할 문자열 포맷으로
// 인코딩한다: "kms:v{version}:{base64(envelope)}"
//
// 버전을 문자열 헤더로 그대로 노출하고 나머지(실제 DEK+암호화된 데이터가 담긴
// envelope)만 base64로 감싸 숨기는 이유:
//   - Decrypt는 "이 암호문을 열려면 몇 번 KEK 버전이 필요한지"를 알아야 한다.
//     매번 envelope 내부를 파싱/복호화 시도 해보면서 버전을 추측할 필요 없이,
//     문자열만 보고 즉시 keys.GetDecryptionKEK(name, version)을 호출할 수 있다.
//   - 버전 번호 자체는 비밀이 아니다 — 로그나 에러 메시지에 그대로 노출되어도
//     안전하다. 반면 envelope에는 실제 키/데이터가 들어있으므로, 항상 봉투
//     암호화(crypto.Seal)를 거친 뒤 base64로만 감싸 전송/저장 가능한 문자열로
//     바꿀 뿐, 내용 자체는 여전히 암호화된 채로 숨겨둔다.
func EncodeCiphertext(version int, envelope []byte) string {
	return fmt.Sprintf("%s:v%d:%s", ciphertextPrefix, version, base64.StdEncoding.EncodeToString(envelope))
}

// DecodeCiphertext는 EncodeCiphertext가 만든 문자열을 (version, envelope)로
// 되돌린다. 형식이 조금이라도 어긋나면 이름 붙인 에러를 반환한다.
func DecodeCiphertext(s string) (version int, envelope []byte, err error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[0] != ciphertextPrefix {
		return 0, nil, ErrInvalidCiphertextFormat
	}

	versionPart := parts[1]
	if !strings.HasPrefix(versionPart, "v") {
		return 0, nil, ErrInvalidCiphertextVersion
	}
	version, err = strconv.Atoi(strings.TrimPrefix(versionPart, "v"))
	if err != nil || version < 1 {
		return 0, nil, ErrInvalidCiphertextVersion
	}

	envelope, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, nil, ErrInvalidCiphertextEncoding
	}

	return version, envelope, nil
}

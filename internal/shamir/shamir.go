package shamir

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// ShareOverhead: Split이 만드는 조각은 원본 비밀보다 정확히 1바이트 길다
// (마지막 1바이트가 x좌표).
const ShareOverhead = 1

var (
	// ErrEmptySecret: 빈 비밀은 나눌 수 없다.
	ErrEmptySecret = errors.New("shamir: cannot split an empty secret")
	// ErrInvalidParts: parts는 2 이상 255 이하여야 한다 — x좌표를 담는 바이트
	// 하나로 표현 가능한 범위(1~255, 0은 비밀 절편의 자리라 못 씀)에서 나온 제약.
	ErrInvalidParts = errors.New("shamir: parts must be between 2 and 255")
	// ErrInvalidThreshold: threshold는 2 이상, parts 이하여야 한다.
	ErrInvalidThreshold = errors.New("shamir: threshold must be between 2 and parts")
	// ErrTooFewShares: Combine에는 최소 2개의 조각이 필요하다.
	ErrTooFewShares = errors.New("shamir: need at least 2 shares to combine")
	// ErrShareTooShort: 조각은 최소 2바이트(비밀 1바이트 + x좌표 1바이트)여야 한다.
	ErrShareTooShort = errors.New("shamir: share must be at least 2 bytes")
	// ErrShareLengthMismatch: 모든 조각의 길이가 같아야 한다.
	ErrShareLengthMismatch = errors.New("shamir: all shares must be the same length")
	// ErrDuplicateShareX: 서로 다른 조각의 x좌표가 겹치면 다항식 보간이 성립하지 않는다.
	ErrDuplicateShareX = errors.New("shamir: duplicate x-coordinate among shares")
)

// polynomial은 GF(256) 위의 다항식이다. coefficients[0]이 상수항(절편) —
// Split에서는 이 자리에 비밀의 바이트 값 하나가 들어간다.
type polynomial struct {
	coefficients []byte
}

// newPolynomial은 절편이 intercept이고 차수가 degree인 다항식을 만든다.
// coefficients[1:](절편을 제외한 나머지 계수)는 crypto/rand로 매번 새로
// 무작위 생성한다 — 그래서 같은 비밀로 Split을 두 번 호출해도 매번 다른
// 다항식, 다른 조각이 나온다.
func newPolynomial(intercept byte, degree int) (polynomial, error) {
	coeffs := make([]byte, degree+1)
	coeffs[0] = intercept
	if _, err := rand.Read(coeffs[1:]); err != nil {
		return polynomial{}, err
	}
	return polynomial{coefficients: coeffs}, nil
}

// evaluate는 호너의 방법(Horner's method)으로 다항식을 x에서 계산한다 —
// 곱셈 횟수를 최소화하며 GF(256) 연산만으로 다항식 값을 구하는 표준적인 방법이다.
func (p polynomial) evaluate(x byte) byte {
	if x == 0 {
		return p.coefficients[0]
	}

	result := p.coefficients[len(p.coefficients)-1]
	for i := len(p.coefficients) - 2; i >= 0; i-- {
		result = Add(Mul(result, x), p.coefficients[i])
	}
	return result
}

// randomXCoordinates는 1~255 범위에서 서로 다른 n개의 바이트를 무작위로
// 골라 반환한다 (x=0은 비밀의 절편이 놓이는 자리이므로 조각의 x좌표로는
// 절대 쓰지 않는다). 255개짜리 배열을 Fisher-Yates로 섞은 뒤 앞 n개를
// 취하는 방식이라, 조각마다 x좌표가 겹칠 일이 없다.
func randomXCoordinates(n int) ([]byte, error) {
	pool := make([]byte, 255)
	for i := range pool {
		pool[i] = byte(i + 1)
	}

	for i := len(pool) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, err
		}
		jIdx := j.Int64()
		pool[i], pool[jIdx] = pool[jIdx], pool[i]
	}

	return pool[:n], nil
}

// Split은 secret을 parts개의 조각으로 나눈다. 그중 threshold개만 모이면
// Combine으로 원본을 복원할 수 있다. 각 조각은 secret보다 정확히 1바이트
// 길고, 형식은 [secret 길이만큼의 y값들][마지막 1바이트 = x좌표]다 —
// 이 형식은 HashiCorp Vault의 shamir 패키지와 동일해서, 두 구현이 만든
// 조각을 서로 섞어 써도(교차검증 테스트 참고) 문제없이 복원된다.
//
// 비밀의 바이트 하나하나에 대해 별도의 다항식을 만든다 — GF(256)의 원소
// 하나(=한 바이트)만 절편으로 표현할 수 있기 때문에, 여러 바이트로 된
// 비밀은 바이트 개수만큼의 다항식이 필요하다. 각 조각은 그 모든 다항식을
// 같은 x좌표에서 평가한 y값들의 모음이다.
func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	if parts < 2 || parts > 255 {
		return nil, ErrInvalidParts
	}
	if threshold < 2 || threshold > parts {
		return nil, ErrInvalidThreshold
	}

	xCoordinates, err := randomXCoordinates(parts)
	if err != nil {
		return nil, err
	}

	shares := make([][]byte, parts)
	for i := range shares {
		shares[i] = make([]byte, len(secret)+1)
		shares[i][len(secret)] = xCoordinates[i]
	}

	for byteIdx, secretByte := range secret {
		p, err := newPolynomial(secretByte, threshold-1)
		if err != nil {
			return nil, err
		}
		for i := 0; i < parts; i++ {
			shares[i][byteIdx] = p.evaluate(xCoordinates[i])
		}
	}

	return shares, nil
}

// interpolateAtZero는 (xs[i], ys[i]) 점들을 지나는 다항식을 라그랑주
// 보간법으로 복원해, x=0에서의 값(=원래 다항식의 절편, 즉 비밀 바이트)을
// 계산한다. xs에 필요한 만큼의 서로 다른 점이 없으면(threshold 미만) 결과는
// 원래 비밀과 다른 값이 나온다 — 보간 자체는 항상 "어떤" 다항식 값을
// 계산해내지만, 그게 Split 때 쓴 진짜 다항식과 같다는 보장은 점이
// threshold개 이상 모였을 때만 성립하기 때문이다.
func interpolateAtZero(xs, ys []byte) (byte, error) {
	var result byte
	for i := range xs {
		basis := byte(1)
		for j := range xs {
			if i == j {
				continue
			}
			// 목표 x값이 0이므로 분자는 (0 - xs[j]) == xs[j] (XOR 체이므로 부호가 없다).
			num := xs[j]
			denom := Sub(xs[i], xs[j])
			term, err := Div(num, denom)
			if err != nil {
				return 0, err
			}
			basis = Mul(basis, term)
		}
		result = Add(result, Mul(ys[i], basis))
	}
	return result, nil
}

// Combine은 Split이 만든 조각들 중 일부(shares)를 모아 원본 비밀을 복원한다.
// 최소 2개의 조각이 필요하고, 모든 조각의 길이가 같아야 하며, x좌표가
// 겹치는 조각이 있으면 안 된다(그러면 다항식 보간이 성립하지 않는다).
//
// Combine은 몇 개가 진짜 threshold였는지 알 방법이 없다 — 그래서 실제
// threshold보다 적은 조각을 넘기면 에러 없이 "그럴듯하지만 틀린" 바이트열을
// 반환할 수 있다. 이건 버그가 아니라 Shamir의 근본적인 성질이다: threshold
// 미만으로는 원본에 대해 아무 정보도 얻을 수 없어야 하므로, "부족하다"는
// 신호조차 새어나가면 안 된다.
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, ErrTooFewShares
	}

	shareLen := len(shares[0])
	if shareLen < 2 {
		return nil, ErrShareTooShort
	}
	for _, s := range shares[1:] {
		if len(s) != shareLen {
			return nil, ErrShareLengthMismatch
		}
	}

	secretLen := shareLen - 1
	xs := make([]byte, len(shares))
	seen := make(map[byte]bool, len(shares))
	for i, s := range shares {
		x := s[secretLen]
		if seen[x] {
			return nil, ErrDuplicateShareX
		}
		seen[x] = true
		xs[i] = x
	}

	secret := make([]byte, secretLen)
	ys := make([]byte, len(shares))
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		for i, s := range shares {
			ys[i] = s[byteIdx]
		}
		val, err := interpolateAtZero(xs, ys)
		if err != nil {
			return nil, err
		}
		secret[byteIdx] = val
	}
	return secret, nil
}

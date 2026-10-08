package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrUnauthenticated는 토큰 검증 실패를 나타내는 공통 에러다. 미들웨어는
// 이 에러의 구체적인 원인(서명 불일치/만료/발급자 불일치 등)을 응답
// 본문에는 절대 노출하지 않고 401만 반환한다 — 원인은 서버 로그에만
// 남긴다.
var ErrUnauthenticated = errors.New("authn: invalid or missing token")

// defaultClockSkew: exp/nbf 판정에 허용할 시계 오차. Config.ClockSkew가
// 0이면(제로값) 이 값을 쓴다.
const defaultClockSkew = 60 * time.Second

// allowedAlgs: 로컬 서명 검증이 허용하는 알고리즘. kube-apiserver가
// ServiceAccount 토큰 서명에 실제로 쓰는 두 가지(서명키가 RSA면 RS256,
// EC면 ES256)만 허용한다 — "alg: none"이나 대칭키 알고리즘(HS*)은 이
// 목록에 없으므로 자동으로 거부된다.
var allowedAlgs = []string{"RS256", "ES256"}

// Config는 Verifier의 검증 정책을 담는다.
type Config struct {
	// Issuer: 기대하는 iss 클레임 값. 비어 있으면 검사하지 않는다.
	Issuer string
	// Audience: 기대하는 aud 클레임 값. 비어 있으면 검사하지 않는다.
	Audience string
	// ClockSkew: exp/nbf 판정에 허용할 시계 오차. 0이면 defaultClockSkew를
	// 쓴다.
	ClockSkew time.Duration
}

// Verifier는 로드된 공개키들로 ServiceAccount 토큰의 서명과 클레임을
// 검증한다.
type Verifier struct {
	keys []crypto.PublicKey
	cfg  Config
}

// NewVerifier는 keys(LoadPublicKeys로 얻은 값)와 cfg로 Verifier를 만든다.
func NewVerifier(keys []crypto.PublicKey, cfg Config) *Verifier {
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = defaultClockSkew
	}
	return &Verifier{keys: keys, cfg: cfg}
}

// Verify는 토큰 문자열(Authorization 헤더의 Bearer 뒤 부분)을 검증하고,
// 성공하면 Identity를 반환한다.
//
// 먼저 서명 검증 없이 헤더의 alg만 읽어(ParseUnverified — 페이로드는 아직
// 신뢰하지 않고, 어떤 종류의 키로 시도할지 고르는 데만 쓴다) 후보 키를
// RSA/ECDSA 타입으로 좁힌 뒤, 각 키로 실제 서명 검증(ParseWithClaims)을
// 순서대로 시도한다. 서명 불일치는 "다음 키 시도"로 넘어가고(키 회전 중
// 여러 키가 있을 수 있으므로), 그 외 실패(만료/발급자 불일치 등)는 어떤
// 키를 썼든 결과가 같으므로 즉시 실패로 끝낸다.
func (v *Verifier) Verify(tokenString string) (Identity, error) {
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, &saClaims{})
	if err != nil {
		return Identity{}, fmt.Errorf("%w: malformed token: %v", ErrUnauthenticated, err)
	}
	alg := unverified.Method.Alg()

	var candidates []crypto.PublicKey
	for _, key := range v.keys {
		switch alg {
		case "RS256":
			if _, ok := key.(*rsa.PublicKey); ok {
				candidates = append(candidates, key)
			}
		case "ES256":
			if _, ok := key.(*ecdsa.PublicKey); ok {
				candidates = append(candidates, key)
			}
		}
	}
	if len(candidates) == 0 {
		return Identity{}, fmt.Errorf("%w: no configured key matches alg %q", ErrUnauthenticated, alg)
	}

	opts := []jwt.ParserOption{
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithLeeway(v.cfg.ClockSkew),
	}
	if v.cfg.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.cfg.Issuer))
	}
	if v.cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(v.cfg.Audience))
	}

	var lastErr error
	for _, key := range candidates {
		claims := &saClaims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(*jwt.Token) (interface{}, error) {
			return key, nil
		}, opts...)
		if err == nil {
			return v.finish(claims)
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			lastErr = err
			continue
		}
		return Identity{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	return Identity{}, fmt.Errorf("%w: signature invalid for all configured keys: %v", ErrUnauthenticated, lastErr)
}

// finish는 서명 검증을 통과한 클레임에 iat(발급 시각) 미래 여부를 마지막으로
// 확인하고 Identity를 추출한다. jwt/v5의 기본 검증기는 exp/nbf만 보고
// iat는 보지 않으므로(레거시 토큰은 iat 자체가 없어 nbf/exp로 대신 걸러지지
// 않기 때문에라도) 여기서 직접 확인한다.
func (v *Verifier) finish(claims *saClaims) (Identity, error) {
	if iat := claims.IssuedAt; iat != nil && iat.Time.After(time.Now().Add(v.cfg.ClockSkew)) {
		return Identity{}, fmt.Errorf("%w: token issued in the future", ErrUnauthenticated)
	}
	return identityFromClaims(claims)
}

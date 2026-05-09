package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrInvalidToken = errors.New("invalid token")

type JWTValidator struct {
	secret   string
	issuer   string
	audience string
}

type Claims struct {
	Subject   string                 `json:"sub"`
	Issuer    string                 `json:"iss"`
	Audience  string                 `json:"aud"`
	ExpiresAt int64                  `json:"exp"`
	IssuedAt  int64                  `json:"iat"`
	Scopes    []string               `json:"scope"`
	Roles     []string               `json:"roles"`
	Extra     map[string]interface{} `json:"-"`
}

func NewJWTValidator(secret, issuer, audience string) *JWTValidator {
	return &JWTValidator{
		secret:   secret,
		issuer:   issuer,
		audience: audience,
	}
}

func (v *JWTValidator) ValidateToken(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}

	if v.issuer != "" && claims.Issuer != v.issuer {
		return nil, errors.New("invalid issuer")
	}

	if v.audience != "" && claims.Audience != v.audience {
		return nil, errors.New("invalid audience")
	}

	return &claims, nil
}

func (v *JWTValidator) ExtractToken(authHeader string) string {
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return authHeader
}

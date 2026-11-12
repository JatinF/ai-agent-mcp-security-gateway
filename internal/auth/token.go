// Package auth issues and checks lab JWTs.
// The signer is an in-memory Ed25519 key. An external OIDC provider was not contacted.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/apperr"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/clock"
)

const IssuerName = "https://syn.lab/mcp-gateway"
const GatewayAudience = "mcp://gateway"

type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  string   `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	TenantID  string   `json:"tenant_id"`
	Roles     []string `json:"roles,omitempty"`
	Delegated bool     `json:"delegated,omitempty"`
	Tool      string   `json:"tool,omitempty"`
	JTI       string   `json:"jti"`
}

type Issuer struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	clock   *clock.Clock
}

func NewIssuer(clk *clock.Clock) (*Issuer, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Issuer{private: private, public: public, clock: clk}, nil
}

func Audience(serverID string) string { return "mcp://" + serverID }

func (i *Issuer) Issue(subject, audience, tenant string, roles []string, ttl time.Duration, delegated bool, tool string) (string, error) {
	now := i.clock.Now().Unix()
	rawID := make([]byte, 8)
	if _, err := rand.Read(rawID); err != nil {
		return "", err
	}
	claims := Claims{
		Issuer: IssuerName, Subject: subject, Audience: audience,
		ExpiresAt: now + int64(ttl/time.Second), IssuedAt: now, TenantID: tenant,
		Roles: roles, Delegated: delegated, Tool: tool,
		JTI: base64.RawURLEncoding.EncodeToString(rawID),
	}
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64(header) + "." + b64(payload)
	sig := ed25519.Sign(i.private, []byte(signing))
	return signing + "." + b64(sig), nil
}

func (i *Issuer) Parse(raw string) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, apperr.New("token_invalid", "token is not a compact JWT", 401)
	}
	signed := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(i.public, []byte(signed), sig) {
		return Claims{}, apperr.New("signature_invalid", "token signature did not verify", 401)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, apperr.New("token_invalid", "token payload is not valid", 401)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, apperr.New("token_invalid", "token payload is not valid JSON", 401)
	}
	if claims.Issuer != IssuerName || claims.Subject == "" || claims.Audience == "" {
		return Claims{}, apperr.New("token_invalid", "token claims are incomplete", 401)
	}
	if i.clock.Now().Unix() >= claims.ExpiresAt {
		return Claims{}, apperr.New("token_expired", "token is expired", 401)
	}
	return claims, nil
}

func b64(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

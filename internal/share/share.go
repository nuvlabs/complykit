package share

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	keyFile    = ".complykit-evidence/.share-secret"
	linksFile  = ".complykit-evidence/.share-links.json"
	DefaultTTL = 30 * 24 * time.Hour // 30 days
)

type Link struct {
	Token      string    `json:"token"`
	RecordID   string    `json:"record_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Label      string    `json:"label,omitempty"`
}

type Claims struct {
	RecordID string `json:"record_id"`
	jwt.RegisteredClaims
}

func secret() ([]byte, error) {
	if data, err := os.ReadFile(keyFile); err == nil {
		return data, nil
	}
	// generate a new secret
	if err := os.MkdirAll(filepath.Dir(keyFile), 0700); err != nil {
		return nil, err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	secret := []byte(hex.EncodeToString(buf))
	if err := os.WriteFile(keyFile, secret, 0600); err != nil {
		return nil, err
	}
	return secret, nil
}

func Create(recordID, label string, ttl time.Duration) (*Link, error) {
	key, err := secret()
	if err != nil {
		return nil, fmt.Errorf("cannot load signing key: %w", err)
	}

	now := time.Now()
	exp := now.Add(ttl)

	claims := Claims{
		RecordID: recordID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			Subject:   "complykit-share",
		},
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		return nil, fmt.Errorf("cannot sign token: %w", err)
	}

	link := &Link{
		Token:     token,
		RecordID:  recordID,
		CreatedAt: now,
		ExpiresAt: exp,
		Label:     label,
	}

	return link, saveLink(link)
}

func Verify(token string) (string, error) {
	key, err := secret()
	if err != nil {
		return "", err
	}

	parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return "", fmt.Errorf("invalid or expired token: %w", err)
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return "", fmt.Errorf("invalid claims")
	}
	return claims.RecordID, nil
}

func ListLinks() ([]Link, error) {
	data, err := os.ReadFile(linksFile)
	if err != nil {
		return nil, nil
	}
	var links []Link
	json.Unmarshal(data, &links)
	return links, nil
}

func saveLink(link *Link) error {
	links, _ := ListLinks()
	links = append([]Link{*link}, links...)
	data, err := json.MarshalIndent(links, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(linksFile, data, 0600)
}

func RevokeAll() error {
	links, _ := ListLinks()
	var active []Link
	for _, l := range links {
		if time.Now().Before(l.ExpiresAt) {
			active = append(active, l)
		}
	}
	data, _ := json.MarshalIndent(active, "", "  ")
	return os.WriteFile(linksFile, data, 0600)
}

package zrevampauth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/zebpay/zrevampauth/external"
)

var (
	authJWKSLock        sync.RWMutex
	AUTH_JWKS_PUBLICKEY *rsa.PublicKey
	AUTH_JWKS_KID       string
)

// GetAuthJWKS returns the currently cached JWKS key-id and RSA public key.
// It is safe for concurrent use.
func GetAuthJWKS() (kid string, publicKey *rsa.PublicKey) {
	authJWKSLock.RLock()
	defer authJWKSLock.RUnlock()
	return AUTH_JWKS_KID, AUTH_JWKS_PUBLICKEY
}

func setAuthJWKS(kid string, publicKey *rsa.PublicKey) {
	authJWKSLock.Lock()
	defer authJWKSLock.Unlock()
	AUTH_JWKS_KID = kid
	AUTH_JWKS_PUBLICKEY = publicKey
}

type JWKS_Keys struct {
	KID string `json:"kid"`
	E   string `json:"e"`
	N   string `json:"n"`
}

type JWKS struct {
	Keys []JWKS_Keys `json:"keys"`
}

func FetchJWKSData(jwksEndpoint string, fetchInterval time.Duration) error {
	err := GetAndSetAuthJWKS(jwksEndpoint)
	if err != nil {
		return fmt.Errorf("AUTH PKG ERROR! Unable to get and set auth jwks keys err: %v", err)
	}
	go func() {
		ticker := time.NewTicker(fetchInterval)
		defer ticker.Stop()
		for range ticker.C {
			err := GetAndSetAuthJWKS(jwksEndpoint)
			if err != nil {
				fmt.Printf("AUTH PKG ERROR! Unable to get and set auth jwks keys err: %v", err)
			}
		}
	}()
	return nil
}

func GetAndSetAuthJWKS(jwksEndpoint string) error {
	params := &external.HTTPCallParams{
		Method: http.MethodGet,
		URL:    fmt.Sprintf("%s/.well-known/openid-configuration/jwks", jwksEndpoint),
	}

	status, data, err := external.HTTPCall(params)
	if err != nil {
		return fmt.Errorf("GetAndSetAuthJWKS: error fetching auth JWKS keys: %w", err)
	}
	if !(status >= 200 && status < 300) {
		return fmt.Errorf("GetAndSetAuthJWKS: error fetching auth JWKS keys (status=%v)", status)
	}

	var jwks JWKS
	err = json.Unmarshal(data, &jwks)
	if err != nil {
		return fmt.Errorf("GetAndSetAuthJWKS: error unmarshalling JWKS response: %w", err)
	}

	if len(jwks.Keys) == 0 {
		return fmt.Errorf("GetAndSetAuthJWKS: jwks keys not present (length=0)")
	}

	keys := jwks.Keys[0]
	publicKey, err := parseRSAPublicKey(keys.N, keys.E)
	if err != nil {
		return fmt.Errorf("GetAndSetAuthJWKS: not able to parse public key from N=%+v and E=%+v values: %w", keys.N, keys.E, err)
	}

	if keys.KID == "" {
		return fmt.Errorf("GetAndSetAuthJWKS: invalid KID (empty)")
	}

	setAuthJWKS(keys.KID, publicKey)
	return nil
}

/*
parseRSAPublicKey takes the modulus (n) and exponent (e) values from JWKS
and generates the RSA Public key form them.

reference:
https://stackoverflow.com/questions/25179492/create-public-key-from-modulus-and-exponent-in-golang/25181584
https://stackoverflow.com/questions/75031229/expose-public-jwk-in-go
*/
func parseRSAPublicKey(modulus, publicExponent string) (*rsa.PublicKey, error) {
	// Convert n and e from hexadecimal to bytes
	nBytes, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		return nil, fmt.Errorf("error decoding modulus (n) from hexadecimal: %v", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(publicExponent)
	if err != nil {
		return nil, fmt.Errorf("error decoding public exponent (e) from Base64: %v", err)
	}

	if len(eBytes) < 4 {
		paddedBytes := make([]byte, 4)
		copy(paddedBytes[4-len(eBytes):], eBytes)
		eBytes = paddedBytes
	}

	// Create the RSA public key
	rsaPublicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(binary.BigEndian.Uint32(eBytes)),
	}

	return rsaPublicKey, nil
}

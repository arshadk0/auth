package zrevampauth

import (
	"fmt"
	"time"

	"github.com/arshadk0/auth/model"
	"github.com/arshadk0/auth/utility"
	"github.com/golang-jwt/jwt"
)

type ServerAuthClient struct {
	JwksEndpoint      string
	JwksFetchInterval time.Duration
}

func InitializeServerAuth(jwksEndpoint string, jwksFetchInterval time.Duration) (*ServerAuthClient, error) {
	client := ServerAuthClient{
		JwksEndpoint:      jwksEndpoint,
		JwksFetchInterval: jwksFetchInterval,
	}

	err := FetchJWKSData(jwksEndpoint, jwksFetchInterval)
	if err != nil {
		return nil, err
	}

	return &client, nil
}

func (sac *ServerAuthClient) VerifyAuthToken(accessToken string, scope string) (*model.UserClaims, error) {
	if AUTH_JWKS_KID == "" || AUTH_JWKS_PUBLICKEY == nil {
		return nil, fmt.Errorf("AuthorizeUser", "Auth JWKS values not set", fmt.Errorf("KID: %+v, PUBLIC_KEY: %+v", AUTH_JWKS_KID, AUTH_JWKS_PUBLICKEY))
	}

	userClaims, err := verifyAccessToken(accessToken, scope, sac.JwksEndpoint)
	if err != nil {
		return nil, err
	}

	return userClaims, nil
}

/*
verifyAccessToken verifies the accessToken based on the publicKey
The checks include signature, KID value, Signing method, Expiry
*/
func verifyAccessToken(accessToken string, scope string, jwksEndpoint string) (*model.UserClaims, error) {
	// some of these params can be read from config while initializing
	claims := &model.UserClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", jwtToken.Header["alg"])
		}

		key_id, ok := jwtToken.Header["kid"].(string)
		if !ok || key_id != AUTH_JWKS_KID {
			return nil, fmt.Errorf("invalid key ID")
		}

		return AUTH_JWKS_PUBLICKEY, nil
	})

	if err != nil {
		return claims, err
	}

	if scope != "" && !utility.StringInSlice(scope, claims.Scopes) {
		return claims, fmt.Errorf("invalid access")
	}

	if claims.Issuer != jwksEndpoint {
		return claims, fmt.Errorf("invalid issuer")
	}

	if !token.Valid {
		return claims, fmt.Errorf("authorization token is invalid or expired")
	}

	return claims, nil
}

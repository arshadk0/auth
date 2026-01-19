package zrevampauth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/zebpay/zrevampauth/model"
	"github.com/zebpay/zrevampauth/utility"
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
	kid, pubKey := GetAuthJWKS()
	if kid == "" || pubKey == nil {
		return nil, fmt.Errorf("AuthorizeUser: auth JWKS values not set (kid=%v, public_key=%v)", kid, pubKey)
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

		kid, pubKey := GetAuthJWKS()
		key_id, ok := jwtToken.Header["kid"].(string)
		if !ok || key_id != kid {
			return nil, fmt.Errorf("invalid key ID")
		}

		return pubKey, nil
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

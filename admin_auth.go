package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
)

type AdminAuthClient struct {
	PublicKey   *rsa.PublicKey
	APIKey      string
	RedisClient *redis.Client
	NonceTTL    time.Duration
}

func InitializeAdminAuth(publicKey *rsa.PublicKey, apiKey string, redisClient *redis.Client, nonceTTL time.Duration) *AdminAuthClient {
	return &AdminAuthClient{
		PublicKey:   publicKey,
		APIKey:      apiKey,
		RedisClient: redisClient,
		NonceTTL:    nonceTTL,
	}
}

/*
AuthorizeRequest middleware validates the jwt token recieved in request.
It decrypts incoming token and checks whether it's RSA encrypted as expected.
Along with token encryption it checks body hash (expected SHA), API key, Nonce etc.
It doesn't handle the user_info check.
*/
func (aac *AdminAuthClient) AuthorizeRequest(authHeader string, checkBodyHash bool, request *http.Request) (int, error) {
	// this x-api-key should come in every request
	// apiKey := c.GetHeader("X-API-KEY")
	// if config.AppConfig.AdminAuthKeys.APIKey != apiKey {
	// 	utility.PublishResponse(c, http.StatusUnauthorized, nil, cs.CustomResponse(http.StatusUnauthorized, "Invalid API Key."))
	// 	return
	// }

	// authorization header should be in this format: Bearer <JWT>
	authorization := strings.Split(authHeader, " ")
	if len(authorization) != 2 || authorization[0] != "Bearer" {
		return http.StatusBadRequest, fmt.Errorf("Authorization token format is invalid")
	}

	// parse and verify jwt token
	token, err := jwt.Parse(authorization[1], func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", jwtToken.Header["alg"])
		}

		return aac.PublicKey, nil
	})

	if err != nil {
		return http.StatusUnauthorized, fmt.Errorf("error parsing token: %w", err)
	}

	if !token.Valid {
		return http.StatusUnauthorized, fmt.Errorf("Authorization token is invalid or expired")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return http.StatusUnprocessableEntity, fmt.Errorf("Claims are invalid")
	}

	if checkBodyHash {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return http.StatusUnprocessableEntity, fmt.Errorf("Not able to read request body")
		}
		// since we can't read request more than once by default in golang
		request.Body = io.NopCloser(bytes.NewBuffer(body))

		if claims["bodyHash"] != getBodyHash(body) {
			return http.StatusBadRequest, fmt.Errorf("Request body has been tampered")
		}
	}

	// if claims["uri"] != c.Request.URL.Path || claims["sub"] != api_key {
	// 	utility.PublishResponse(c, http.StatusBadRequest, nil, cs.CustomResponse(http.StatusBadRequest, "Token claims don't match"))
	// 	return
	// }

	nonce, isValid := claims["nonce"].(string)
	if !isValid {
		return http.StatusBadRequest, fmt.Errorf("Nonce not provided or is invalid")
	}

	thisNonce := aac.APIKey + ":" + nonce
	nonceExists, err := aac.RedisClient.Exists(context.Background(), thisNonce).Result()
	if err != nil {
		return http.StatusFailedDependency, fmt.Errorf("Error fetching nonce from redis: %v", err.Error())
	} else if nonceExists == 1 {
		return http.StatusBadRequest, fmt.Errorf("This is a repeated request")
	} else {
		aac.RedisClient.Set(context.Background(), thisNonce, "", aac.NonceTTL).Err()
	}

	return http.StatusOK, nil
}

func getBodyHash(body any) string {
	var bytesBody []byte
	bytesBody, ok := body.([]byte)
	if !ok {
		bytesBody, _ = json.Marshal(body)
	}
	hasher := sha256.New()
	hasher.Write(bytesBody)
	return hex.EncodeToString(hasher.Sum(nil))
}

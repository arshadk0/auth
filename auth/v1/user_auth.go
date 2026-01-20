package v1

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"auth"
	"auth/model"
	"auth/utility"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

/*
AuthorizeUser is the middleware to verify the access_token
and check if the user is allowed to use the API.

It also fetches user data from redis and sets it into context.
*/

type UserAuthClient struct {
	RedisClient     *redis.Client
	MaxTimeDiffInMs int64
	AppClientIDs    []string
	UserServiceURL  string
	JwtEndpoint     string
}

var apiKeySecretCache sync.Map
var sessionClient *model.SessionClient
var apiKeyClient *model.ApiKeyInfoClient
var clientInfoClient *model.ClientInfoClient

func InitializeUserAuth(redisClient *redis.Client, maxTimeDiffInMs int64, appClientIDs []string, userServiceURL, JwtEndpoint, apiKeyInfoUrl, clientInfoUrl string, jwtFetchInterval time.Duration) *UserAuthClient {
	auth.InitKmsClient()
	if _, err := auth.InitializeServerAuth(JwtEndpoint, jwtFetchInterval); err != nil {
		panic("unable to initialize server auth: " + err.Error())
	}
	sessionClient = model.InitSessionClient(redisClient, userServiceURL)
	apiKeyClient = model.InitApiKeyInfoClient(redisClient, apiKeyInfoUrl)
	clientInfoClient = model.InitClientInfoClient(redisClient, clientInfoUrl)
	return &UserAuthClient{
		RedisClient:     redisClient,
		MaxTimeDiffInMs: maxTimeDiffInMs,
		AppClientIDs:    appClientIDs,
		UserServiceURL:  userServiceURL,
		JwtEndpoint:     JwtEndpoint,
	}
}

func getClientIP(c *gin.Context) string {
	// First check our custom header
	if originalIP := c.Request.Header.Get("X-Original-Client-IP"); originalIP != "" {
		return originalIP
	}

	// Fall back to standard method for Azure
	return c.ClientIP()
}

func (uac *UserAuthClient) AuthorizeUser(c *gin.Context, isApiKeyAuthAllowed bool, scopes []string) (int, int, error) {
	// Check for API key header
	var accountId, status int
	var err error
	isBot := false
	apiKey := c.GetHeader("X-AUTH-APIKEY")
	if apiKey != "" {
		isBot = true
		// check only the exchange API routes are allowed
		if !isApiKeyAuthAllowed {
			return accountId, http.StatusUnauthorized, fmt.Errorf("Invalid Access.")
		}

		// Perform signature-based authentication
		signature := c.GetHeader("X-AUTH-SIGNATURE")
		if signature == "" {
			return accountId, http.StatusUnauthorized, fmt.Errorf("missing signature")
		}

		// Verify timestamp
		var timestamp int64
		var payload string
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodDelete {
			timestampStr := c.Query("timestamp")
			if timestampStr == "" {
				return accountId, http.StatusBadRequest, fmt.Errorf("missing timestamp")
			}
			timestamp, err = strconv.ParseInt(timestampStr, 10, 64)
			payload = c.Request.URL.RawQuery
		} else if c.Request.Method == http.MethodPost || c.Request.Method == http.MethodPut {
			body, err := io.ReadAll(c.Request.Body)
			if err != nil {
				return accountId, http.StatusBadRequest, fmt.Errorf("Invalid request body.")
			}
			var requestBody map[string]interface{}
			if err := json.Unmarshal(body, &requestBody); err != nil {
				return accountId, http.StatusBadRequest, fmt.Errorf("Invalid request body.")
			}

			// Handle timestamp as both number and string
			if tsValue, exists := requestBody["timestamp"]; exists {
				switch v := tsValue.(type) {
				case float64:
					// Handle as number (default JSON unmarshaling for numbers)
					timestamp = int64(v)
				case string:
					// Handle as string - parse to int64
					if parsedTs, err := strconv.ParseInt(v, 10, 64); err == nil {
						timestamp = parsedTs
					} else {
						return accountId, http.StatusUnauthorized, fmt.Errorf("Invalid timestamp format.")
					}
				case int64:
					// Handle as int64 (in case of direct int type)
					timestamp = v
				case int:
					// Handle as int (in case of int type)
					timestamp = int64(v)
				default:
					return accountId, http.StatusUnauthorized, fmt.Errorf("Timestamp must be a number or string.")
				}
			} else {
				return accountId, http.StatusUnauthorized, fmt.Errorf("missing timestamp")
			}
			payload = string(body)
			c.Request.Body = io.NopCloser(bytes.NewReader(body)) // Preserve body
		}

		if err != nil || !uac.isTimestampValid(timestamp) {
			return accountId, http.StatusUnauthorized, fmt.Errorf("Invalid or expired timestamp.")
		}

		// Verify API key and signature
		apiKeyInfo, err := verifyAPIKeyAndSignature(apiKey, signature, payload, scopes, getClientIP(c))
		if err != nil {
			errMsg := "Unauthorized, invalid API key or signature."
			if err.Error() != "" {
				errMsg = err.Error()
			}
			return accountId, http.StatusUnauthorized, fmt.Errorf("%s", errMsg)
		}
		accountId = apiKeyInfo.AccountID
	} else {
		token := utility.GetTokenFromHeader(c)
		kid, pubKey := auth.GetAuthJWKS()
		if kid == "" || pubKey == nil {
			return accountId, http.StatusInternalServerError, fmt.Errorf("Internal server error.")
		}

		sessionToken := c.Request.Header.Get("sessiontoken")

		status, accountId, isBot, err = uac.verifyAccessToken(token, scopes, getClientIP(c), sessionToken)
		if err != nil {
			errMsg := "Unauthorized, invalid access token."
			if err.Error() != "" {
				errMsg = err.Error()
			}
			return accountId, status, fmt.Errorf("%s", errMsg)
		}
	}

	c.Set("isBot", isBot)
	return accountId, 0, nil
}

/*
verifyAccessToken verifies the accessToken based on the publicKey
The checks include signature, KID value, Signing method, Expiry
*/
func (uac *UserAuthClient) verifyAccessToken(accessToken string, scopes []string, clientIP string, sessionToken string) (int, int, bool, error) {
	claims := &model.UserClaims{}
	isBot := false
	token, err := jwt.ParseWithClaims(accessToken, claims, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", jwtToken.Header["alg"])
		}

		kid, pubKey := auth.GetAuthJWKS()
		key_id, ok := jwtToken.Header["kid"].(string)
		if !ok || key_id != kid {
			return nil, fmt.Errorf("invalid key ID")
		}

		return pubKey, nil
	})

	if err != nil {
		return http.StatusUnauthorized, claims.AccountID, isBot, err
	}

	if len(scopes) > 0 && !hasAnyScope(scopes, claims.Scopes) {
		return http.StatusUnauthorized, claims.AccountID, isBot, fmt.Errorf("invalid access")
	}

	if claims.Issuer != uac.JwtEndpoint {
		return http.StatusUnauthorized, claims.AccountID, isBot, fmt.Errorf("invalid issuer")
	}

	if !token.Valid {
		return http.StatusUnauthorized, claims.AccountID, isBot, fmt.Errorf("authorization token is invalid or expired")
	}

	// check if the client id is from app or web
	if utility.StringInSlice(claims.ClientId, uac.AppClientIDs) {
		if sessionToken != "" {
			session, err := uuid.Parse(sessionToken)
			if err != nil {
				return 440, claims.AccountID, isBot, fmt.Errorf("invalid session")
			}

			isValidSession := sessionClient.GetSession(claims.AccountID, session.String())
			if !isValidSession {
				return 440, claims.AccountID, isBot, fmt.Errorf("invalid session")
			}
		}

		return 0, claims.AccountID, isBot, nil
	}

	isBot = true
	// the below checks is for bot accounts
	clientInfo, err := clientInfoClient.GetClientInfo(&claims.ClientId)
	if err != nil {
		return http.StatusUnauthorized, claims.AccountID, isBot, err
	}

	// check if the clientInfo is enabled
	if !clientInfo.Enabled {
		return http.StatusUnauthorized, claims.AccountID, isBot, fmt.Errorf("client id is inactive")
	}

	if len(clientInfo.IpAddresses) > 0 {
		if !utility.StringInSlice(clientIP, clientInfo.IpAddresses) {
			return http.StatusUnauthorized, claims.AccountID, isBot, fmt.Errorf("ip address: %s is not whitelisted", clientIP)
		}
	}

	return 0, claims.AccountID, isBot, nil
}

func verifyAPIKeyAndSignature(apiKey, signature string, payload string, scopes []string, clientIP string) (*model.ApiKeyInfo, error) {
	// Retrieve API secret based on API key
	apiKeyInfo, err := apiKeyClient.GetApiKeyInfo(&apiKey)
	if err != nil {
		return nil, errors.New("invalid api key")
	}

	var apiSecret string
	if v, ok := apiKeySecretCache.Load(apiKey); ok {
		apiSecret = v.(string)
	} else {
		apiSecret, err = auth.KmsDecrypt(apiKeyInfo.ApiSecret)
		if err != nil {
			return nil, errors.New("internal error")
		}
		apiKeySecretCache.Store(apiKey, apiSecret)
	}
	// Compute HMAC-SHA256 signature
	h := hmac.New(sha256.New, []byte(apiSecret))
	h.Write([]byte(payload))
	expectedSig := h.Sum(nil)

	// Compare signatures
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return nil, errors.New("invalid signature")
	}
	isValid := hmac.Equal(expectedSig, sigBytes)
	if !isValid {
		return nil, errors.New("invalid signature")
	}

	if len(apiKeyInfo.AppIPAddresses) > 0 {
		if !utility.StringInSlice(clientIP, apiKeyInfo.AppIPAddresses) {
			return nil, fmt.Errorf("ip address: %s is not whitelisted", clientIP)
		}
	}

	if len(scopes) > 0 && !hasAnyScope(scopes, apiKeyInfo.AppScope) {
		return nil, fmt.Errorf("invalid access")
	}

	return apiKeyInfo, nil
}

func (uac *UserAuthClient) isTimestampValid(clientTimestamp int64) bool {
	serverTime := time.Now().UnixMilli()
	return abs(serverTime-clientTimestamp) <= uac.MaxTimeDiffInMs
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// hasAnyScope checks if any scope from the scope array is present in the appScope array
func hasAnyScope(scopes []string, appScopes []string) bool {
	for _, s := range scopes {
		if utility.StringInSlice(s, appScopes) {
			return true
		}
	}
	return false
}

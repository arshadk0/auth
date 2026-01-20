package utility

import (
	"fmt"

	"github.com/arshadk0/auth/constant"
	"github.com/gin-gonic/gin"
)

func StringInSlice(s string, list []string) bool {
	for _, b := range list {
		if b == s {
			return true
		}
	}
	return false
}

func GetTokenFromHeader(c *gin.Context) string {
	// Get token from cookie.
	cookie, err := c.Cookie("access_token")
	if err == nil && cookie != "" {
		return cookie
	}

	// Get the token from the header.
	token := c.GetHeader("Authorization")
	if len(token) > 7 && token[0:7] == "Bearer " {
		return token[len("Bearer "):]
	}

	return ""
}

func GetZebPaySessionRedisKey(accountId int, sessionToken string) string {
	return fmt.Sprintf("%s:Session:%d:%s", constant.USER_SERVICE_NAMESPACE, accountId, sessionToken)
}

func GetApiKeyInfoRedisKey(apiKey string) string {
	return fmt.Sprintf("%s:%s", constant.API_TRADE_NAMESPACE, apiKey)
}

func GetClientInfoRedisKey(clientId string) string {
	return fmt.Sprintf("%s:%s", constant.AUTH_NAMESPACE, clientId)
}

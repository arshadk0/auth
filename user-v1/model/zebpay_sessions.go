package model

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/arshadk0/auth/external"
	"github.com/arshadk0/auth/utility"
	"github.com/go-redis/redis/v8"
)

type SessionClient struct {
	RedisClient    *redis.Client
	UserServiceURL string
}

func InitSessionClient(redisClient *redis.Client, userServiceURL string) *SessionClient {
	return &SessionClient{
		RedisClient:    redisClient,
		UserServiceURL: userServiceURL,
	}
}
func (sc *SessionClient) getSessionInfoFromRedis(accountId int, sessionToken string) (bool, error) {
	return sc.RedisClient.Get(context.Background(), utility.GetZebPaySessionRedisKey(accountId, sessionToken)).Bool()
}

type SessionValidationRequest struct {
	AccountId    int    `json:"account_id" binding:"required"`
	SessionToken string `json:"session_token" binding:"required"`
}

type SessionValidationResponse struct {
	Data struct {
		AccountId    int    `json:"account_id"`
		SessionToken string `json:"session_token"`
		IsActive     bool   `json:"is_active"`
	} `json:"data"`
	StatusCode int `json:"status_code"`
}

func (sc *SessionClient) GetSession(accountId int, sessionToken string) bool {
	// fetch data from redis
	val, err := sc.getSessionInfoFromRedis(accountId, sessionToken)
	if err == nil {
		return val
	}

	body := SessionValidationRequest{
		AccountId:    accountId,
		SessionToken: sessionToken,
	}

	payload, err := json.Marshal(body)

	if err != nil {
		return false
	}

	params := &external.HTTPCallParams{
		Method:  http.MethodGet,
		URL:     fmt.Sprintf("%s/api/v0/session", sc.UserServiceURL),
		Payload: payload,
	}

	// make a call to user service
	status, data, err := external.HTTPCall(params)
	if err != nil {
		return false
	}

	if !(status >= 200 && status < 300) {
		return false
	}

	response := SessionValidationResponse{}
	err = json.Unmarshal(data, &response)
	if err != nil {
		return false
	}

	return response.Data.IsActive
}

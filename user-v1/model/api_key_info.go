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

// Request struct
type ApiKeyInfoRequest struct {
	ApiKey string `json:"ApptId"`
}

// Response struct
type ApiKeyInfo struct {
	UserID         int      `json:"userId"`
	Label          string   `json:"lable"`
	ApiKey         string   `json:"apiKey"`
	ApiSecret      string   `json:"apiSecret"`
	AppIPAddresses []string `json:"appIPAddresses"`
	AppScope       []string `json:"appScope"`
	AccountID      int      `json:"accountId"`
}

type ApiKeyInfoResponse struct {
	Data *ApiKeyInfo `json:"data"`
}

type ApiKeyInfoClient struct {
	RedisClient   *redis.Client
	ApiKeyInfoUrl string
}

func InitApiKeyInfoClient(redisClient *redis.Client, apiKeyInfoUrl string) *ApiKeyInfoClient {
	return &ApiKeyInfoClient{
		RedisClient:   redisClient,
		ApiKeyInfoUrl: apiKeyInfoUrl,
	}
}

/*
GetApiKeyInfo initially tries to fetch apiKey info from redis
if data is not found on redis, it makes a call to Z1 build api service to fetch api key info
*/
func (client *ApiKeyInfoClient) GetApiKeyInfo(apiKey *string) (*ApiKeyInfo, error) {
	apiKeyInfo, err := client.getApiKeyInfoFromRedis(*apiKey)
	if err == nil && apiKeyInfo.ApiKey == *apiKey {
		return &apiKeyInfo, nil
	}

	// Create an instance of the struct and assign the clientId
	apiKeyReq := ApiKeyInfoRequest{ApiKey: *apiKey}

	jsonData, err := json.Marshal(apiKeyReq)
	if err != nil {
		return nil, err
	}
	// fetch data from redis
	params := &external.HTTPCallParams{
		Method:  http.MethodGet,
		URL:     client.ApiKeyInfoUrl,
		Payload: jsonData,
	}

	// make a call to user service
	status, data, err := external.HTTPCall(params)
	if err != nil {
		return nil, err
	}
	if !(status >= 200 && status < 300) {
		return nil, fmt.Errorf("error: %s", fmt.Sprintf("api status is %d", status))
	}

	response := ApiKeyInfoResponse{}
	err = json.Unmarshal(data, &response)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal userinfo")
	}

	client.putApiKeyInfoOnRedis(*response.Data)

	return response.Data, nil
}

func (client *ApiKeyInfoClient) getApiKeyInfoFromRedis(apiKey string) (ApiKeyInfo, error) {
	var apiKeyInfo ApiKeyInfo
	data, err := client.RedisClient.Get(context.Background(), utility.GetApiKeyInfoRedisKey(apiKey)).Result()
	if err != nil {
		return apiKeyInfo, err
	}
	err = json.Unmarshal([]byte(data), &apiKeyInfo)
	return apiKeyInfo, err
}

func (client *ApiKeyInfoClient) putApiKeyInfoOnRedis(apiKeyInfo ApiKeyInfo) {
	cIBytes, err := json.Marshal(apiKeyInfo)
	if err != nil {
		return
	}
	client.RedisClient.Set(context.Background(), utility.GetApiKeyInfoRedisKey(apiKeyInfo.ApiKey), string(cIBytes), 0).Result()
}

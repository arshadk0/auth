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

type ClientInfo struct {
	ClientId    string   `json:"ClientId"`
	IpAddresses []string `json:"ClientIPAddresses"`
	Enabled     bool     `json:"Enabled"`
}
type ClientRequest struct {
	ClientID string `json:"clientId"`
}

type FetchClientInfoResponse struct {
	Data *ClientInfo `json:"data"`
}

type ClientInfoClient struct {
	RedisClient   *redis.Client
	ClientInfoURL string
}

func InitClientInfoClient(redisClient *redis.Client, clientInfoURL string) *ClientInfoClient {
	return &ClientInfoClient{
		RedisClient:   redisClient,
		ClientInfoURL: clientInfoURL,
	}
}

/*
GetUserInfo initially tries to fetch user info from redis
if data is not found on redis, it makes a call to user service to fetch user info
*/
func (client *ClientInfoClient) GetClientInfo(clientId *string) (*ClientInfo, error) {

	clientInfo, err := client.getClientInfoFromRedis(*clientId)
	if err == nil && clientInfo.ClientId == *clientId {
		return &clientInfo, nil
	}

	// Create an instance of the struct and assign the clientId
	clientReq := ClientRequest{ClientID: *clientId}

	jsonData, err := json.Marshal(clientReq)
	if err != nil {

		return nil, err
	}
	// fetch data from redis
	params := &external.HTTPCallParams{
		Method:  http.MethodGet,
		URL:     client.ClientInfoURL,
		Payload: jsonData,
	}

	// make a call to user service
	status, data, err := external.HTTPCall(params)
	if err != nil {
		return nil, err
	}
	if !(status >= 200 && status < 300) {
		return nil, fmt.Errorf("error: %s", string(data))
	}

	response := FetchClientInfoResponse{}
	err = json.Unmarshal(data, &response)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal userinfo")
	}

	client.putClientInfoOnRedis(*response.Data)

	return response.Data, nil
}

func (client *ClientInfoClient) getClientInfoFromRedis(clientId string) (ClientInfo, error) {
	var clientInfo ClientInfo
	data, err := client.RedisClient.Get(context.Background(), utility.GetClientInfoRedisKey(clientId)).Result()
	if err != nil {
		return clientInfo, err
	}
	err = json.Unmarshal([]byte(data), &clientInfo)
	return clientInfo, err
}

func (client *ClientInfoClient) putClientInfoOnRedis(clientInfo ClientInfo) {
	cIBytes, err := json.Marshal(clientInfo)
	if err != nil {
		return
	}
	client.RedisClient.Set(context.Background(), utility.GetClientInfoRedisKey(clientInfo.ClientId), string(cIBytes), 0).Result()
}

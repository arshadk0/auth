package external

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

type (
	HTTPMethod string
	Params     map[string]string
)

const (
	HttpMethodGet    = HTTPMethod(http.MethodGet)
	HttpMethodPost   = HTTPMethod(http.MethodPost)
	HTTPMethodDelete = HTTPMethod(http.MethodDelete)
)

const DefaultTimeOut = 60 * time.Second

var defaultHTTPClient = &http.Client{
	Timeout: DefaultTimeOut,
}

type HTTPCallParams struct {
	Method  HTTPMethod
	URL     string
	Payload []byte
	Headers map[string]string
	Params  map[string]interface{}
}

func HTTPCall(params *HTTPCallParams) (int, []byte, error) {
	req, err := http.NewRequest(string(params.Method), params.URL, bytes.NewBuffer(params.Payload))
	if err != nil {
		return 0, []byte{}, err
	}
	if len(params.Params) > 0 {
		q := req.URL.Query()
		for k, v := range params.Params {
			q.Add(k, fmt.Sprint(v))
		}
		req.URL.RawQuery = q.Encode()
	}
	if len(params.Headers) > 0 {
		for k, v := range params.Headers {
			req.Header.Add(k, v)
		}
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return http.StatusBadGateway, []byte{}, err
	}
	if resp == nil {
		return 500, []byte{}, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, []byte{}, err
	}
	return resp.StatusCode, bodyBytes, nil
}

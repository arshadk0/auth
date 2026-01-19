package model

import "github.com/golang-jwt/jwt"

type UserClaims struct {
	jwt.StandardClaims
	Name            string   `json:"name"`
	Email           string   `json:"email"`
	AccountGUID     string   `json:"accountguild"`
	CustomerGUID    string   `json:"customerguild"`
	CustomerId      int      `json:"customerid,string"`
	AccountID       int      `json:"accountid,string"`
	CountryCode     string   `json:"countrycode"`
	CurrencyCode    string   `json:"currencycode"`
	IsEmailVerified string   `json:"emailverified"`
	Scopes          []string `json:"scope"`
	ClientId        string   `json:"client_id"`
	Audience        []string `json:"aud,omitempty"`
}

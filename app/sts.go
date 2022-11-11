package app

import (
	"crypto/rsa"
	"time"

	sts "github.com/deliveryhero/pd-sts-go-sdk"
)

type (
	STSClient struct {
		TokenService sts.TokenService
	}
	STSOptions struct {
		Issuer   string
		ClientID string
		KeyID    string
		Key      *rsa.PrivateKey
		TimeOut  time.Duration
	}
)

func NewSTSClient(options STSOptions) STSClient {
	stsOptions := []sts.Option{
		sts.WithRefreshPeriod(options.TimeOut),
	}
	service := sts.NewTokenService(options.Issuer, options.ClientID, options.KeyID, options.Key, stsOptions...)
	return STSClient{
		TokenService: service,
	}
}

func (c STSClient) GetAccessToken() (string, error) {
	return c.TokenService.GetToken([]string{})
}

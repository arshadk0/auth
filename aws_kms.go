package zrevampauth

import (
	"context"
	"encoding/base64"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var KmsClient *kms.Client
var kmsOnce sync.Once

func InitKmsClient() {
	kmsOnce.Do(func() {
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			panic("unable to load SDK config, " + err.Error())
		}
		KmsClient = kms.NewFromConfig(cfg)
	})
}

func KmsDecrypt(encryptedData string) (string, error) {
	// Decode base64 ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	// Decrypt request
	input := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
	}

	// Decrypt
	result, err := KmsClient.Decrypt(context.Background(), input)
	if err != nil {
		return "", err
	}
	return string(result.Plaintext), nil
}

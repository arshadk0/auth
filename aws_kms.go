package zrevampauth

import (
	"encoding/base64"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

var KmsClient *kms.KMS

func InitKmsClient() error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("ap-southeast-1"),
	})
	if err != nil {
		return err
	}
	KmsClient = kms.New(sess)
	return nil
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
	result, err := KmsClient.Decrypt(input)
	if err != nil {
		return "", err
	}
	return string(result.Plaintext), nil
}

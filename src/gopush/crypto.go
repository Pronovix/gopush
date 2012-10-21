package gopush

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func (svc *GoPushService) genKeyPair() (string, error) {
	prikey, err := rsa.GenerateKey(rand.Reader, svc.keySize)
	if err != nil {
		return "", err
	}

	marshaled := x509.MarshalPKCS1PrivateKey(prikey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY",
		Headers: nil,
		Bytes: marshaled,
	})

	return string(privateKeyPEM), nil
}
package gopush

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func (svc *GoPushService) genKeyPair() (string, string, error) {
	prikey, err := rsa.GenerateKey(rand.Reader, svc.keySize)
	if err != nil {
		return "", "", err
	}

	marshaled := x509.MarshalPKCS1PrivateKey(prikey)
	marshaledPublic, errpk := x509.MarshalPKIXPublicKey(&prikey.PublicKey)
	if errpk != nil {
		return "", "", errpk
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY",
		Headers: nil,
		Bytes: marshaled,
	})

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PUBLIC KEY",
		Headers: nil,
		Bytes: marshaledPublic,
	})

	return string(privateKeyPEM), string(publicKeyPEM), nil
}
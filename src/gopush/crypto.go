package gopush

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"log"
)

func genKeyPair(keySize int) (string, string, error) {
	prikey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return "", "", err
	}

	marshaled := x509.MarshalPKCS1PrivateKey(prikey)
	marshaledPublic, errpk := x509.MarshalPKIXPublicKey(&prikey.PublicKey)
	if errpk != nil {
		return "", "", errpk
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   marshaled,
	})

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   marshaledPublic,
	})

	return string(privateKeyPEM), string(publicKeyPEM), nil
}

func stringToPublicKey(pkey string) *rsa.PublicKey {
	marshaled, _ := pem.Decode([]byte(pkey))
	pubkey, err := x509.ParsePKIXPublicKey(marshaled.Bytes)
	if err != nil {
		log.Println(err.Error())
		return nil
	}

	return pubkey.(*rsa.PublicKey)
}

func stringToPrivateKey(pkey string) *rsa.PrivateKey {
	marshaled, _ := pem.Decode([]byte(pkey))
	prikey, err := x509.ParsePKCS1PrivateKey(marshaled.Bytes)
	if err != nil {
		return nil
	}
	return prikey
}

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"log"
	"os"
)

func main() {
	cek, err := generateCEK()
	if err != nil {
		log.Fatal(err)
	}
}

func generateCEK() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// CreateJWKKey получение JWK ключа
func CreateJWKKey() *jwk.Key {
	var privateKey *ecdsa.PrivateKey
	if _, err := os.Stat("private_key.pem"); os.IsNotExist(err) {
		GenerateECDSAKey()
		privateKey = GetECDSAKey()
	} else {
		privateKey = GetECDSAKey()
	}

	publicKey := privateKey.PublicKey

	key, err := jwk.FromRaw(publicKey)
	if err != nil {
		log.Fatal(err)
	}
	if _, ok := key.(jwk.ECDSAPublicKey); !ok {
		fmt.Printf("expected jwk.ECDSAPrivateKey, got %T\n", key)
		return nil
	}

	buf, err := json.MarshalIndent(key, "", "    ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(buf))

	return &key
}

// GetECDSAKey получение ECDSA ключа
func GetECDSAKey() *ecdsa.PrivateKey {
	privatePEM, err := os.ReadFile("private_key.pem")
	if err != nil {
		log.Fatal(err)
	}

	block, rest := pem.Decode(privatePEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Got a %T, with remaining data: %q\n", privateKey, rest)

	return privateKey
}

// GenerateECDSAKey генерация приватного ECDSA ключа
func GenerateECDSAKey() {
	// Генерация ключа ECDSA
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Кодирование ключа в формат PEM
	ecPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecPrivateKey,
	}

	// Сохранение ключа в файл
	file, err := os.Create("private_key.pem")
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	err = pem.Encode(file, privateKeyPEM)
	if err != nil {
		panic(err)
	}
}

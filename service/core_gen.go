package service

import (
  "crypto/rand"
  "crypto/rsa"
  "crypto/x509"
  "encoding/pem"
  "golang.org/x/crypto/ssh"
  "io/ioutil"
  "log"
  "os"
)

// makeSSHKeyPair
// create RSA key
func makeSSHKeyPair(savePublicFileTo, savePrivateFileTo string) {
	privateKey, err := generatePrivateKey(bitSize)
	if err != nil {
		log.Fatal(err.Error())
	}

	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	// 这一块考虑原子性， 能还原问题
	// 后面再解决吧
  	err = writeKeyToFile(privateKeyBytes, savePrivateFileTo, 0600)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = writeKeyToFile(publicKeyBytes, savePublicFileTo, 0644)
	if err != nil {
		log.Fatal(err.Error())
	}
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// encodePrivateKeyToPEM
// encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	privateDER := x509.MarshalPKCS1PrivateKey(privateKey)

	privateBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateDER,
	}

	privatePEM := pem.EncodeToMemory(&privateBlock)

	return privatePEM
}

// generatePublicKey
// take a rsa.PublicKey and return bytes suitable for writing to .pub file
func generatePublicKey(privateKey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privateKey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	return pubKeyBytes, nil
}

// writePemToFile
// writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string, chmod os.FileMode) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, chmod)
	if err != nil {
		return err
	}
	return nil
}

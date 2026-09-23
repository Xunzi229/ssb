package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// makeSSHKeyPair
// create RSA key
func makeSSHKeyPair(savePublicFileTo, savePrivateFileTo string) error {
	if err := secureOwnerDir(filepath.Dir(savePrivateFileTo)); err != nil {
		return err
	}

	privateKey, err := generatePrivateKey(bitSize)
	if err != nil {
		return err
	}

	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	// 这一块考虑原子性， 能还原问题
	// 后面再解决吧
	if err = writeKeyToFile(privateKeyBytes, savePrivateFileTo, 0600); err != nil {
		return err
	}
	return writeKeyToFile(publicKeyBytes, savePublicFileTo, 0644)
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
func writeKeyToFile(keyBytes []byte, saveFileTo string, perm os.FileMode) error {
	if err := prepareOverwrite(saveFileTo, perm); err != nil {
		return err
	}
	if err := os.WriteFile(saveFileTo, keyBytes, perm); err != nil {
		return err
	}
	if perm == 0600 {
		return securePrivateKey(saveFileTo)
	}
	return os.Chmod(saveFileTo, perm)
}

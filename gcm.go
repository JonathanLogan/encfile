package encfile

import (
	"crypto/aes"
	"crypto/cipher"
)

func gcm(k []byte) cipher.AEAD {
	aesBC, err := aes.NewCipher(k[0:32])
	if err != nil {
		panic(err.Error())
	}
	ret, err := cipher.NewGCM(aesBC)
	if err != nil {
		panic(err.Error())
	}
	return ret
}

// encryptSector data with AES-GCM using key and nonce. No length check on key/nonce is done!
func encryptSector(key, nonce, data []byte) []byte {
	algo := gcm(key)
	return algo.Seal(nil, nonce[:algo.NonceSize()], data, nil)
}

// decryptSector data with AES-GCM using key and nonce. No length check on key/nonce is done!
func decryptSector(key, nonce, data []byte) ([]byte, error) {
	algo := gcm(key)
	return algo.Open(nil, nonce[:algo.NonceSize()], data, nil)
}

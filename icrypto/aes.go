package icrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

type Iaes struct {
	key, iv []byte
}

// Encrypt
func (ia *Iaes) Encrypt(origData []byte) ([]byte, error) {
	block, err := aes.NewCipher(ia.key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = pkcs7padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, ia.key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

// Decrypt
func (ia *Iaes) Decrypt(crypted []byte) ([]byte, error) {
	block, err := aes.NewCipher(ia.key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, ia.key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = pkcs7unpadding(origData)
	return origData, nil
}

// pkcs7padding 增加填充
func pkcs7padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// pkcs7padding 删除填充
func pkcs7unpadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

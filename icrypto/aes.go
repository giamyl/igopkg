// AES 加密解密

/*** 示例 ***

	ic := icrypto.Iaes{
		Key:[]byte("12345678901234567890123456789012"), //可以是16位,24位,32位
		Iv:[]byte("0000000000000000"),	//必须为16位
	}

	rs,_ := ic.Encrypt(`{"code":200201201,"data":"消息内容","msg":"成功"}`)
	base64string := base64.StdEncoding.EncodeToString(rs)
	fmt.Println(base64string)

	//base64string:="5zvUyzbVr0Z7bkT97NhfqgoKq6xUTidyY2yVtTLRUkoKUoRXepk5eVoe+2atDhFDFLitZpH1paMKGSj+wZMNrQ=="
	rsdata, _ := ic.Decrypt(base64string)
	fmt.Println(string(rsdata))

*/

package icrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

type Iaes struct {
	Key []byte	//可以是16位,24位,32位
	Iv []byte	//必须为16位
}

// Encrypt 加密数据,返回一个base64类型的string
func (ia *Iaes) Encrypt(Data string) ([]byte, error) {
	origData := []byte(Data)
	block, err := aes.NewCipher(ia.Key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = pkcs7padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, ia.Iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

// Decrypt 解密数据
func (ia *Iaes) Decrypt(base64string string) ([]byte, error) {
	b,err:=base64.StdEncoding.DecodeString(base64string)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(ia.Key)
	if err != nil {
		return nil, err
	}
	//blockSize := block.BlockSize()
	//blockMode := cipher.NewCBCDecrypter(block, ia.Key[:blockSize])
	blockMode := cipher.NewCBCDecrypter(block, ia.Iv)
	origData := make([]byte, len(b))
	blockMode.CryptBlocks(origData, b)
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

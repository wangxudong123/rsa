package safecustody_rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

const PublicKeyName = "PublicKey.pem"
const PrivateKeyName = "private.pem"

var Bits int = 3084

type RsaKeys struct {
	Pubk []byte
	Pk   []byte
}

//创建公私钥
func GetKeys() RsaKeys {

	block := CreateBlock()

	fp, err := os.Create(PrivateKeyName)
	if err != nil {
		panic(err)
	}
	defer fp.Close()
	pem.Encode(fp, &block.Pk)

	file, err := os.Create(PublicKeyName)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	pem.Encode(file, &block.Pubk)

	return RsaKeys{
		Pubk: pem.EncodeToMemory(&block.Pubk),
		Pk:   pem.EncodeToMemory(&block.Pk),
	}
}

type RsaBlock struct {
	Pubk pem.Block
	Pk   pem.Block
}

func CreateBlock() RsaBlock {
	//生成私钥
	privateKey, _ := rsa.GenerateKey(rand.Reader, Bits)
	x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	pemBlock := pem.Block{
		Type:  "privateKey",
		Bytes: x509PrivateKey,
	}

	//生成公钥
	publicKey := privateKey.PublicKey
	x509PublicKey, _ := x509.MarshalPKIXPublicKey(&publicKey)
	pemPublicKey := pem.Block{
		Type:  "PublicKey",
		Bytes: x509PublicKey,
	}

	return RsaBlock{
		Pubk: pemPublicKey,
		Pk:   pemBlock,
	}
}

//使用公钥进行加密
func RSAEncrypt(path string, msg []byte) []byte {
	return RSAEncryptInput(RSAUnmarshalByte(path), msg)
}

//使用私钥进行解密
func RSADecrypt(path string, cipherText []byte) []byte {
	return RSADecryptInput(RSAUnmarshalByte(path), cipherText)
}

//解析成字节
func RSAUnmarshalByte(path string) []byte {
	fp, _ := os.Open(path)
	defer fp.Close()

	fileinfo, _ := fp.Stat()
	buf := make([]byte, fileinfo.Size())
	_, _ = fp.Read(buf)
	return buf
}

//使用公钥的内容进行加密
func RSAEncryptInput(publicKey, msg []byte) []byte {
	block, _ := pem.Decode(publicKey)

	pub, _ := x509.ParsePKIXPublicKey(block.Bytes)
	cipherText, _ := rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), msg)
	return cipherText
}

//使用私钥的内容进行解密
func RSADecryptInput(privateKey, cipherText []byte) []byte {
	block, _ := pem.Decode(privateKey)
	PrivateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	afterDecrypt, _ := rsa.DecryptPKCS1v15(rand.Reader, PrivateKey, cipherText)
	return afterDecrypt
}

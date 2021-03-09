package test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	rsa "safecustody_rsa"
	"testing"
	"time"
)

func Test_Rsa1(t *testing.T) {
	msg := []byte("RSA非对称加密1")
	//加密
	ciphertext := rsa.RSAEncrypt(rsa.PublicKeyName, msg)

	//转化为十六进制方便查看结果
	fmt.Println(hex.EncodeToString(ciphertext))

	//解密
	result := rsa.RSADecrypt(rsa.PrivateKeyName, ciphertext)
	fmt.Println(string(result))
}

var bk = `-----BEGIN PublicKey-----
MIIFIjANBgkqhkiG9w0BAQEFAAOCBQ8AMIIFCgKCBQEA0zmdPh8e0O/4Cie9IeqE
1UOaP2HsCm+OblgPNSwDJvH3lkRagCqY6MoCx9cHHJD8zp9T3iuDmOfD5ew9t5II
1Z0T550LInh7YvcUnzmWvcLOGMJMMT+y8eq5JAiFrAtM31MOxDf+xbZzGp1ldACj
rIBBntzbMmy+FyGmex2YIfdeXO8y2Xvby6904QuPrkbq2myNJ+c0+/52DOHYOhUl
94rEr0XknGakcwUf0hdXcoatt5CHGQMqbKNjNufuIAr4otw+FmtgSJIVTZiQw3GM
b6bqYwPYGB2Flwx25/CDN52WK9nD0hTtK7QkS1XWfgPqoMK4bvfQMhbqf7gLND2E
rc2uQhyzhuPZFwvSKoIh0DPNy04VZPfSJyi0nK09N7m0jZuaVSD3T+x/kNWPc58R
ZJa0NQub1QUWvDNmf7ZH8aN5pSdDwI0u05249fKJtkPwI6SXoqXyDzcfQySU9a0n
2um2aCSgnTrZlcC7fU+CMQJmjDS4V3gwOhX+FPPtOaFxzpAHqjiETyyrUrKEjyFy
hg/ct68paF78BRUiYwA6FRvfheHdXmG/E3tyK3bRlrsRU/NL5NU32bzAzoMAJgFy
cOAN8gkydkpFG0s9AZK2qKiqyzPanBSk2yRBsU9U9tyjjPKod5NzFLROdLeg/t25
C5WaZFQ5Z719KxfB5V4SZVPxA1Eyqapw8nU1OgvqFe6FOps3bbecqOp+l4C/XKt3
ucNR+dFrLVdHUHRdCMue4a2Uo2bY/gci17xOSXj+KmZ/89huFPIlQOpJ4iY/zp8X
gL/N8AAw2vm28KSFTPQuCnSZOcIpIUwHIH1clAFZwM/0bMz/ihkrGlTIj65kBw4E
K5ZpPGaeOI3/pa55pSVFGKimfp6KSSYH419SPL0+Bqvht3Q54VMt7g1wAeuTWfRy
AGs9lGkB+nBuNWI9auJyVcAbK+g22mD0SI4KQ5CeOvCJWqBQo2V5jE0zZGWKPdbX
bg/2IXO9Iw3613gQuBw5g+hw1ZyGQ9dHgOM91vctbQc0gQbvuHdSuel1bTkGKVNc
eKEyZTG+B0pdvsTZ57ZugYClygHjLdtd2c8QOdpFpFHo0qGc/9upT+3dfdqyFQ81
PWBF/gwf2ZGILCzFAWwK7+1bOfMR09o3+SgxDPa3ge8uGzYC0XmKT0f+922Qg0D3
JBdcMrSbb28+nLjZ6rzwNcDmgCgvpAU/Cw54OryY+/9u/azgW+yn5lKw/pEswJ+u
zaDt8BheJzfGDZG4C1O2lWSk+Xu13OZtQ6Dy/ozg6WyTpdDYwXUYhmL8aAE0+ZEB
Xu2nPzFXVdZp6OQ492oIRFwj9bXgd/yFYCCqwFL1htkPLaG1v4jgX072LTXDHpyf
PAu/wQXz6aPbFd+arPouQtn1epT/i4DYO71D2/BIBjWsmKf4gYwuv6FOWU4E0t5w
MNkKGPiq/c91HzjAQIP0XpNqM8vyAWSquzjSyasyBeC85qHDf1nI85fhwS7Mr2kE
1s7zHjkX4uWfOhlQRtoLYDBjGK6EC1oVehYqe/CZcJB3+a0Ksoa8PzjPnHAGLNdD
WWeWsdC6PcTi97nIc8fvFOXWjbWd10KVzHs2V5ecdvPMR7YRYAe21egZcrW1WEXw
8k1Bm/nT93HktGELL4MwKC07WF7z/6egfJ5L1vwsDt39x7O5oWM03JUTOVSPXfdV
VhISaY2rNsXkhqJ26UWg8cUCAwEAAQ==
-----END PublicKey-----
`

var pk = `-----BEGIN privateKey-----
MIIEpAIBAAKCAQEAuPi+xewEu/OCUiIyIRRg0HmJa1acz+ClKzynUSkB7CXZu8or
3TP/kvqPkKy+zTTWr+FVBusF214xs50geqy6afEqTonWKoeoDw8xLeKZucN+yc7i
EK3WmDtPmbLGA7r4oV5I5ehrxXiJy6bL9VszKj79J41rJKUQEjHWH92oAzvNeMJG
GGVtqM2plQosBqMmJWRwaMJXnVBf60W5UfF7EOtI1Y07MGFWeWxaS7gLOvRHGAmu
iRmLlREwA+IoTU3b5VRb/D5JulIU1ybtVOrLzzxYJGSUAZbCWZguIxLinYqU9ZTQ
zvV9nIX1oK1XUXAyVdD55iyVzz4zhQhS/VrOnQIDAQABAoIBAQChypGztVn+vGRF
Szvly1lTgLs+dCf9fFV8mDURvHi+Ae2NYK01cwIdoaRpu2+5NnqCpOomfvREiQOY
Q9vg8aysdhG3WMFHuhi582Pk6svjvKfuBVOfmy6VQWvC2KhzItvO6hWBY+bAd0qw
I1lLZ1Y9oZL1QbFyAB8qiwTsIomPKQZfNaPbeJ0ueqCh6UqYFMIGTcqd9JpMSasb
YS7diI1RJrOpgp/NoGptGtsDb1r63XoqXD0Bk9AndUnR+TaZS8KqfpdXyC91r+cB
gyxzXkkbPJ8DiZfXa6hzSfNN6UxqhY80hB5wHM9pRxmAW3TvSWIkMpbqshPldfhA
b2YbAXTRAoGBAMsdnOcnm7SorGyLCKzJy5P6TtVH0zm2SDH3QDJmbOUYbTQJ4aIm
gqq64RqSU87bFYzUlSlT/U/BkLMYHesGvFE1hq6MzOhH/z/oxRmtwnbUH4/l7x4I
7wVMGSPZkS5FHRIWLpTOQwV4qxEv+mrI6nkwG5+kz8dpg86YcgI74Vm7AoGBAOkh
xM4+BvABgZRe5uDa2LRvN1PxuYH4F3SUjvUyQmzOTJQEgFg/Ogqy/5xDm5Vp2oZs
ugeQ9cizMs/0BhTJOoL1reh/t/HBo8kU2aCtalXClcLCW/j6DQGrrv3j/IXLVYNT
7NbuQ/f2BjdrA5tnST/Uf41SKuJoCsD/xiRoeyeHAoGAD5rP0iaF3ORUkuY/nV7H
iC/j3JjvDnEFrOkNApJB7Xvp7+SOdDG3OjyvTKZPUAYe6rnuV8V/IaCCaHAC5GqZ
Dzgoh8KDf5kAcD2G3wktdomnfxuwOkN/cY2+JLXzZHWk3R3dKEuMdKAnrGNePtP+
x569kI9N80kU+ktV/vvwvT8CgYEAtCr8xcb55ZHEar3NAAkhYJBy2dT94Iuy1M3a
jXQCEcR9OgcgiRKT8KDVGhbFrnrX/vsX6bEFwc17f2q/KGE7buofNIc/yP41bblH
Vv2uKAjxZEqAebIFSz07R8th5KR3ub6qUpBgxsjDlSCG8RqpaUL4MGdH7SEq7my8
3HZCdxECgYBTK4r5dWNBkvrIaqTsx8l1TALIE2UU1YRT8rwB0L1KdKZRlJi9vaNn
w1KsWbzv/iiPkOcAgkKDXadW1mJOIsvmFZahE67FizUnKAYGkLxIdbekm0GxhdqA
C+LCzs3N3Q1uwtksTueDfaSMyvq9DzB87I3xEN2z+9TOv5pjcTAHdw==
-----END privateKey-----`

func Test_Rsa2(t *testing.T) {

	msg := []byte("RSA非对称加密2")
	ciphertext := rsa.RSAEncryptInput([]byte(bk), msg)

	result := rsa.RSADecryptInput([]byte(pk), ciphertext)
	fmt.Println(string(result))
}

//获取公私钥
func Test_GetKeys(t *testing.T) {
	keys := rsa.GetKeys()
	fmt.Println(string(keys.Pk))
	fmt.Println(string(keys.Pubk))
}

func Test_GetFee(t *testing.T) {

	type GasBody struct {
		Version    float64 `json:"Version"`
		To         string  `json:"To"`
		From       string  `json:"From"`
		Nonce      int64   `json:"Nonce"`
		Value      string  `json:"Value"`
		GasLimit   int64   `json:"GasLimit"`
		GasFeeCap  string  `json:"GasFeeCap"`
		GasPremium string  `json:"GasPremium"`
		Method     int     `json:"Method"`
		Params     []byte  `json:"Params"`
	}

	type respGas struct {
		Jsonrpc string  `json:"jsonrpc"`
		Result  GasBody `json:"result"`
	}

	param1 := GasBody{
		Version:    0,
		To:         "f13jhzdiy6zbodxwagk3pqxd44dmsy5uwb7cnjyia",
		From:       "f1tapcyapyaq6icvqkceztm7wgte5pv7bnqibxz7q",
		Value:      "0.01",
		GasLimit:   0,
		GasFeeCap:  "0",
		GasPremium: "0",
		Method:     0,
		Params:     nil,
	}

	param2 := struct {
		MaxFee string `json:"MaxFee"`
	}{
		"0",
	}

	var param3 []interface{}

	param3 = append(param3, param1)
	param3 = append(param3, param2)
	param3 = append(param3, nil)

	jrpcParams := struct {
		Jsonrpc string      `json:"jsonrpc"`
		Method  string      `json:"method"`
		Params  interface{} `json:"params"`
		Id      int         `json:"id"`
		T       int64       `json:"t"`
	}{
		"2.0",
		"Filecoin.GasEstimateMessageGas",
		param3,
		1,
		time.Now().Unix(),
	}

	b, err := json.Marshal(jrpcParams)
	fmt.Println(err)
	fmt.Println(string(rsa.RSAEncryptInput([]byte(bk), b)))
}

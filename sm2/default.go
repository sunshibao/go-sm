/*
createTime: 2022/7/7
*/
package sm

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
)

type Sm2Cypher struct {
	prv    *sm2.PrivateKey
	pub    *sm2.PublicKey
	mode   int
	random string
}

type Option struct {
	Mode    int
	Random  string
	PubStr  string
	PrvStr  string
	KeyType string
}

func NewSm2(opt Option) (*Sm2Cypher, error) {
	cipher := Sm2Cypher{}

	if len(opt.Random) != 0 && len(opt.Random) != 40 {
		return nil, errors.New("random length is must 40")
	}
	cipher.mode = opt.Mode
	cipher.random = opt.Random

	if opt.KeyType == "hex" {
		if opt.PrvStr != "" {
			prv, err := x509.ReadPrivateKeyFromHex(opt.PrvStr)
			if err != nil {
				return nil, err
			}
			cipher.prv = prv
		}
		if opt.PubStr != "" {
			pub, err := x509.ReadPublicKeyFromHex(opt.PubStr)
			if err != nil {
				return nil, err
			}
			cipher.pub = pub
		}
	}

	if opt.KeyType == "pem" {
		if opt.PrvStr != "" {
			prvByte, err := ioutil.ReadFile(opt.PrvStr)
			prv, err := x509.ReadPrivateKeyFromPem(prvByte, nil)
			if err != nil {
				return nil, err
			}
			cipher.prv = prv
		}
		if opt.PubStr != "" {
			pubByte, err := ioutil.ReadFile(opt.PubStr)
			pub, err := x509.ReadPublicKeyFromPem(pubByte)
			if err != nil {
				return nil, err
			}
			cipher.pub = pub
		}
	}

	return &cipher, nil
}

func (s *Sm2Cypher) Encrypt(msg []byte) ([]byte, error) {
	if s.pub == nil {
		return nil, errors.New("publicKey is nil")
	}
	if s.random != "" {
		return sm2.Encrypt(s.pub, msg, strings.NewReader(s.random), s.mode)

	} else {
		return sm2.Encrypt(s.pub, msg, rand.Reader, s.mode)
	}
}
func (s *Sm2Cypher) Decrypt(msg []byte) ([]byte, error) {
	if s.prv == nil {
		return nil, errors.New("privateKey is nil")
	}

	//判断数据是否为压缩数据
	if msg[0] != byte(0x04) {
		msg = append([]byte{4}, msg...)
	}
	return sm2.Decrypt(s.prv, msg, s.mode)
}

func (s *Sm2Cypher) Sign(msg []byte) ([]byte, error) {
	if s.prv == nil {
		return nil, errors.New("privateKey is nil")
	}
	if s.random != "" {
		return s.prv.Sign(strings.NewReader(s.random), msg, nil)
	} else {
		return s.prv.Sign(rand.Reader, msg, nil)
	}

}

func (s *Sm2Cypher) Verify(msg, sign []byte) bool {
	if s.pub == nil {
		log.Fatalln("publicKey is nil")
		return false
	}
	return s.pub.Verify(msg, sign)
}

func (s *Sm2Cypher) SignHex(msg string) (string, error) {
	if s.prv == nil {
		return "", errors.New("privateKey is nil")
	}
	var signByte []byte
	var err error
	if s.random != "" {
		signByte, err = s.prv.Sign(strings.NewReader(s.random), []byte(msg), nil)
	} else {
		signByte, err = s.prv.Sign(rand.Reader, []byte(msg), nil)
	}
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signByte), nil
}

func (s *Sm2Cypher) VerifyHex(msg, sign string) bool {
	if s.pub == nil {
		log.Fatalln("publicKey is nil")
		return false
	}

	signByte, err := hex.DecodeString(sign)
	if err != nil {
		return false
	}
	
	return s.pub.Verify([]byte(msg), signByte)
}

func GenerateKey(random, keyType, filePath string) (string, string, error) {
	if len(random) != 0 && len(random) != 40 {
		return "", "", errors.New("random is must length 40")
	}

	var prv *sm2.PrivateKey
	var err error
	if len(random) == 0 {
		prv, err = sm2.GenerateKey(nil)
		if err != nil {
			return "", "", err
		}
	} else {
		prv, err = sm2.GenerateKey(strings.NewReader(random))
		if err != nil {
			return "", "", err
		}
	}

	if keyType == "hex" {
		var prvHex string
		var pubHex string
		prvHex = x509.WritePrivateKeyToHex(prv)

		pubKey, _ := prv.Public().(*sm2.PublicKey)
		pubHex = x509.WritePublicKeyToHex(pubKey)
		return prvHex, pubHex, nil
	}

	if keyType == "pem" {
		prvFile := path.Join(filePath, "prv.pem")
		pubFile := path.Join(filePath, "pub.pem")
		prvPem, err := x509.WritePrivateKeyToPem(prv, nil)
		if err != nil {
			return "", "", err
		}
		writeFile(prvFile, prvPem)

		pubKey, _ := prv.Public().(*sm2.PublicKey)
		pubPem, err := x509.WritePublicKeyToPem(pubKey)
		if err != nil {
			return "", "", err
		}
		writeFile(pubFile, pubPem)
	}

	return "", "", err
}

func writeFile(path string, content []byte) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("失败", err)
		}
	}()

	if fileObj, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644); err == nil {
		defer fileObj.Close()
		writeObj := bufio.NewWriter(fileObj)

		lineStr := fmt.Sprintf("%s", content)
		_, err := fmt.Fprintln(writeObj, lineStr)
		if err != nil {
			fmt.Println("文件write失败：", err)
		}
		err = writeObj.Flush()
		if err != nil {
			fmt.Println("文件flush失败：", err)
		}
	}
}

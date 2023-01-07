/*
createTime: 2022/7/7
*/
package sm

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/tjfoc/gmsm/sm4"
)

type Sm4Cypher struct {
	Key []byte
	Iv  []byte
}

func NewSm4(key, iv string) (*Sm4Cypher, error) {
	if len(key) != 16 {
		return nil, errors.New("key length is must 16")
	}
	if len(iv) != 16 && len(iv) != 0 {
		return nil, errors.New("iv length is must 16")
	}
	return &Sm4Cypher{
		Key: []byte(key),
		Iv:  []byte(iv),
	}, nil
}

//ECB 方式加密
func (s *Sm4Cypher) EcbEncode(msg []byte) ([]byte, error) {
	return sm4.Sm4Ecb(s.Key, msg, true)
}

func (s *Sm4Cypher) EcbDecode(msg []byte) ([]byte, error) {
	return sm4.Sm4Ecb(s.Key, msg, false)
}

func (s *Sm4Cypher) EcbEncodeBase64(msg string) (string, error) {
	enByte, err := sm4.Sm4Ecb(s.Key, []byte(msg), true)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(enByte), nil
}

func (s *Sm4Cypher) EcbDecodeBase64(msg string) (string, error) {
	msgByte, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return "", err
	}
	deByte, err := sm4.Sm4Ecb(s.Key, msgByte, false)
	if err != nil {
		return "", err
	}
	return string(deByte), nil
}

func (s *Sm4Cypher) EcbEncodeHex(msg string) (string, error) {
	enByte, err := sm4.Sm4Ecb(s.Key, []byte(msg), true)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(enByte), nil
}

func (s *Sm4Cypher) EcbDecodeHex(msg string) (string, error) {
	msgByte, err := hex.DecodeString(msg)
	if err != nil {
		return "", err
	}
	deByte, err := sm4.Sm4Ecb(s.Key, msgByte, false)
	if err != nil {
		return "", err
	}
	return string(deByte), nil
}

//CBC 方式加密
func (s *Sm4Cypher) CbcEncode(msg []byte) ([]byte, error) {
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return nil, err
		}
	}

	return sm4.Sm4Cbc(s.Key, msg, true)
}

func (s *Sm4Cypher) CbcDecode(msg []byte) ([]byte, error) {
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return nil, err
		}
	}
	return sm4.Sm4Cbc(s.Key, msg, false)
}

func (s *Sm4Cypher) CbcEncodeBase64(msg string) (string, error) {
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return "", err
		}
	}
	enByte, err := sm4.Sm4Cbc(s.Key, []byte(msg), true)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(enByte), nil
}

func (s *Sm4Cypher) CbcDecodeBase64(msg string) (string, error) {
	msgByte, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return "", err
	}
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return "", err
		}
	}
	deByte, err := sm4.Sm4Cbc(s.Key, msgByte, false)
	if err != nil {
		return "", err
	}
	return string(deByte), nil
}

func (s *Sm4Cypher) CbcEncodeHex(msg string) (string, error) {
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return "", err
		}

	}
	enByte, err := sm4.Sm4Cbc(s.Key, []byte(msg), true)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(enByte), nil
}

func (s *Sm4Cypher) CbcDecodeHex(msg string) (string, error) {
	msgByte, err := hex.DecodeString(msg)
	if err != nil {
		return "", err
	}
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return "", err
		}
	}
	deByte, err := sm4.Sm4Cbc(s.Key, msgByte, false)
	if err != nil {
		return "", err
	}
	return string(deByte), nil
}

//CFB 方式加密
func (s *Sm4Cypher) CfbEncode(msg []byte) ([]byte, error) {
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return nil, err
		}
	}
	return sm4.Sm4CFB(s.Key, msg, true)
}

func (s *Sm4Cypher) CfbDecode(msg []byte) ([]byte, error) {
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return nil, err
		}
	}
	return sm4.Sm4CFB(s.Key, msg, false)
}

func (s *Sm4Cypher) CfbEncodeBase64(msg string) (string, error) {
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return "", err
		}
	}
	enByte, err := sm4.Sm4CFB(s.Key, []byte(msg), true)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(enByte), nil
}

func (s *Sm4Cypher) CfbDecodeBase64(msg string) (string, error) {
	msgByte, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return "", err
	}
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return "", err
		}
	}
	deByte, err := sm4.Sm4CFB(s.Key, msgByte, false)
	if err != nil {
		return "", err
	}
	return string(deByte), nil
}

func (s *Sm4Cypher) CfbEncodeHex(msg string) (string, error) {
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return "", err
		}
	}
	enByte, err := sm4.Sm4CFB(s.Key, []byte(msg), true)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(enByte), nil
}

func (s *Sm4Cypher) CfbDecodeHex(msg string) (string, error) {
	msgByte, err := hex.DecodeString(msg)
	if err != nil {
		return "", err
	}
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return "", err
		}
	}
	deByte, err := sm4.Sm4CFB(s.Key, msgByte, false)
	if err != nil {
		return "", err
	}
	return string(deByte), nil
}

//OFB 方式加密
func (s *Sm4Cypher) OfbEncode(msg []byte) ([]byte, error) {
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return nil, err
		}
	}
	return sm4.Sm4OFB(s.Key, msg, true)
}

func (s *Sm4Cypher) OfbDecode(msg []byte) ([]byte, error) {
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return nil, err
		}
	}
	return sm4.Sm4OFB(s.Key, msg, false)
}

func (s *Sm4Cypher) OfbEncodeBase64(msg string) (string, error) {
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return "", err
		}
	}
	enByte, err := sm4.Sm4OFB(s.Key, []byte(msg), true)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(enByte), nil
}

func (s *Sm4Cypher) OfbDecodeBase64(msg string) (string, error) {
	msgByte, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return "", err
	}
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return "", err
		}
	}
	deByte, err := sm4.Sm4OFB(s.Key, msgByte, false)
	if err != nil {
		return "", err
	}
	return string(deByte), nil
}

func (s *Sm4Cypher) OfbEncodeHex(msg string) (string, error) {
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return "", err
		}
	}
	enByte, err := sm4.Sm4OFB(s.Key, []byte(msg), true)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(enByte), nil
}

func (s *Sm4Cypher) OfbDecodeHex(msg string) (string, error) {
	msgByte, err := hex.DecodeString(msg)
	if err != nil {
		return "", err
	}
	if len(s.Iv) == 16 {
		err := sm4.SetIV(s.Iv)
		if err != nil {
			return "", err
		}
	}
	deByte, err := sm4.Sm4OFB(s.Key, msgByte, false)
	if err != nil {
		return "", err
	}
	return string(deByte), nil
}

func (s *Sm4Cypher) GCMEncode(msg []byte) ([]byte, error) {
	if len(s.Iv) == 0 {
		return nil, errors.New("gcm is must iv")
	}
	return nil, nil
}

func (s *Sm4Cypher) GCMDecode(msg []byte) ([]byte, error) {
	if len(s.Iv) == 0 {
		return nil, errors.New("gcm is must iv")
	}
	return nil, nil
}

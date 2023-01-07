/*
createTime: 2022/11/24
*/
package sm3

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/tjfoc/gmsm/sm3"
)

type Sm3Cypher struct{}

func NewSm3() (*Sm3Cypher, error) {
	return &Sm3Cypher{}, nil
}

func (*Sm3Cypher) EncryptHex(msg string) string {
	enByte := sm3.Sm3Sum([]byte(msg))
	return hex.EncodeToString(enByte)
}

func (*Sm3Cypher) EncryptBase64(msg string) string {
	enByte := sm3.Sm3Sum([]byte(msg))
	return base64.StdEncoding.EncodeToString(enByte)
}

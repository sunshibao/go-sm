## 接口使用规则

### #加解密
    
采用国密(SM4)进行加解密操作，加密后需对密文数据进行base64编码，解密前需对密文内容进行base64解码。

加密密钥：`3ExYW0tVEHuQecgz`

加密：原始数据字符串 &rarr; SM4(ECB加密)  &rarr; Base64编码<br>
解密：密文数据字符串  &rarr; Base64解码  &rarr; SM4(ECB解密)

`Query`参数（请求地址携带）

明文内容：`package=com.freeme.searchbox`<br>
密文内容：`a4U4W2/Jg3dNwV2LxiLfYuOC7QzM+gcbk/ySshtm+AA=`<br>
示例：`http://127.0.0.1:8001/v1/task/list?a4U4W2/Jg3dNwV2LxiLfYuOC7QzM+gcbk/ySshtm+AA=`

`Body`数据

明文内容(application/json)：`{"id": 1, "name": "test", "timestamp": 1669086216}`<br>
密文内容(text/plain)：`SJ+m2n3xJnCFa4EMhcmRvc718XaPkdlSeG3fRyqy2sj177Z1NmtwrStkXhxDYjmQRe1g0QmBJ4cjv9ThQkuEIw==`
    
### #签名

采用国密(SM2)进行非对称签名及验签，私钥用于签名，公钥用于验签。<br>
签名内容为请求密文内容的字符串，签名后的字节内容转换为十六进制字符串(hex)。

私钥(hex): 

```text
eddfdc084554442392da5d68d9c3f8a8b4159d2c6c07162d700947a8a1492501
```

公钥(hex): 

```text
044afb59af7cf1a300f89d807c3e4201dc5d8abf0efe31a665cb609d6e7a35941813987b26fb833d9fca1455e87db20072ee42dd3240d776145b8b7bb3e089643d
```

模式: 

```text
C1C2C3
```

示例：

```text
SJ+m2n3xJnCFa4EMhcmRvc718XaPkdlSeG3fRyqy2sj177Z1NmtwrStkXhxDYjmQRe1g0QmBJ4cjv9ThQkuEIw==
```

签名结果: 

```text
.....
```

> 内容添加Unix时间戳，有助于防止请求被重放。签名后的字节内容转十六进制字符串。

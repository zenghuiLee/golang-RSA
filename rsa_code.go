package main
 
import (
   "crypto/rand"
   "crypto/rsa"
   "crypto/x509"
   "encoding/pem"
   "errors"
   "flag"
   "fmt"
   "io/ioutil"
   "os"
   "crypto"
   "crypto/sha256"
   "encoding/base64"
   "io"
   "time"
)
 
var decrypted string
var privateKey, publicKey []byte
 
func init() {
   var err error
   flag.StringVar(&decrypted, "d", "", "加密过的数据")
   flag.Parse()
   publicKey, err = ioutil.ReadFile("public.pem")
   if err != nil {
      os.Exit(-1)
   }
   privateKey, err = ioutil.ReadFile("private.pem")
   if err != nil {
      os.Exit(-1)
   }
}
 
func genLicense(theMsg string) string {
   b64theMsg := base64.RawStdEncoding.EncodeToString([]byte(theMsg))
   h := sha256.New()
   io.WriteString(h, b64theMsg)
   sha256Byte := h.Sum(nil)
   sig, _ := RsaSignature(sha256Byte)
   license := base64.RawStdEncoding.EncodeToString(sig)
   return license
}
 
// 私钥签名
func RsaSignature(message []byte) ([]byte, error) {
   rng := rand.Reader
   hashed := sha256.Sum256(message)
   block, _ := pem.Decode(privateKey)
   if block == nil {
      return nil, errors.New("private key error")
   }
   private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return nil, err
   }
   signature, err := rsa.SignPKCS1v15(rng, private, crypto.SHA256, hashed[:])
   if err != nil {
      return nil, err
   }
   return signature, nil
}
 
// 公钥解密
func RsaSignatureVerify(message []byte, signature []byte) error {
   hashed := sha256.Sum256(message)
   block, _ := pem.Decode(publicKey)
   if block == nil {
      return errors.New("public key error")
   }
   pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
   if err != nil {
      return err
   }
   pub := pubInterface.(*rsa.PublicKey)
   return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
}

func main() {
   var theMsg = `the message you want to encode`
   license := genLicense(theMsg)
   fmt.Println(license)
}

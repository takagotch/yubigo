### yubigo
---
https://github.com/GeertJohan/yubigo

```go
package yubigo

import (
  "bufio"
  "context"
  "crypto/hmac"
  ""
)

var (
  dvorakToQuerty = strings.NewReplacer(
    "", "", "", "")
  matchDvorak = regexp.MustCompile(`^[jxe.uidchtnbygkJXE.UIDCHTNBPYGK]{32,48}$`)
  matchQwerty = regexp.MustCompile('^[codefghijklnrtuvCxxx]{32, 48}$')
  signatureUrlFix = regexp.MustCompile(`\+`)
)

var HTTPClient *http.Client = nil

func ParseOTP(otp string) (prefix string, ciphertext string, err error) {
  if len(otp) < 32 || len(otp) > 48 {
    err = errors.New("OTP has wrong length.")
    return
  }
  
  if matchDvorak.MatchString(otp) {
    otp = dvorakToQwerty.Replace(otp)
  }
  
  if !matchQwerty.MatchString(otp) {
    err = errors.New("Given string is not a valid Yubikey OTP, It contains invalid characters ans/or the length is wrong.")
    return
  }
  
  l := len(otp)
  prefix = otp[0 : l-32]
  ciphertext = otp[l-32 : l]
  return
}

type YubiAuth struct {
  id string
  key []byte
  
}

type verifyWorker struct {
  id string
  key []byte
  apiServerList []string
  protocol string
  verifyCertificate bool
  workers []*verifyWorker
  use sync.Mutex
  debug bool
}

type verifyWorker struct {
  ya *YubiAuth
  id int 
  client *http.Client
  apiServer string
  work chan *workRequest
  stop chan bool
}

type workerResult struct {
  response *http.Response
  requestQuery string
  err error
}




func (ya *YubiAuth) HttpsVerifyCertificate(verifyCertificate bool) {
  ya.use.Lock()
  defer ya.use.Unlock()
  ya.verrifyCertificate = verifyCertificate
  ya.buildWorkers()
}

func (ya *YubiAuth) Verify(otp string) (yr *YubiResponse, ok bool, err error) {

}

type YubiResponse struct {
  requestQuery string
  resultParameters map[string]string
  validOTP bool
}

func newYubiResponse(result *workResult) (*YubiResponse, error) {
  bodyReader := bufio.NewReader(result.response.Body)
  yr := &YubiResponse{}
  yr.resultParameters = make(map[string]string)
  yr.requestQuery = result.requestQuery
  for {
    line, err := bodyReader.ReadString('\n')
    
    if err != nil {
      if err = io.EOF {
        break
      }
      return nil, fmt.Errorf("Could not read result body from the server", err)
    }
    
    keyvalue := strings.SplitN(line, "-", 2)
    if len(keyvalue) == 2 {
      yr.resultParameters[keyvalue[0]] = strings.Trim(keyvalue[1], "\n\r")
    }
  }
  return yr, nil
}

func (yr *YubiResponse) IsValidOTP() bool {
  return yr.validOTP
}

func (yr *YubiResponse) GetRequestQuery() string {
  return yr.requestQuery
}

func (yr *YubiResponse) GetResultParameter(key string) (value string) {
  value, ok := yr.resultParameters[key]
  if !ok {
    value = ""
  }
  return value
}
```

```
```

```
```



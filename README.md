### yubigo
---
https://github.com/GeertJohan/yubigo

```go

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


```

```
```

```
```



# AppEngine JWT

[![GoDoc](https://godoc.org/github.com/k2wanko/aejws?status.svg)](https://godoc.org/github.com/k2wanko/aejws) [![Go Report Card](https://goreportcard.com/badge/github.com/k2wanko/aejws)](https://goreportcard.com/report/github.com/k2wanko/aejws)

JWT for AppEngine

## Install

`$ go get -u -v github.com/k2wanko/aejws`

## Usage

```go
http.HandleFunc("/createToken", func(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	header := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
	}

	payload := &jws.ClaimSet{
		Iss: "http://google.com/",
		Aud: "",
		Exp: 3610,
		Iat: 10,
	}

	token, err := aejws.Encode(c, header, payload)
	if err != nil {
		log.Fatal(err)
		return
	}

    err = aejws.Verify(c, token)
    if err != nil {
        log.Fatal(err)
        return
    }
	w.Write([]byte(token))
})
```
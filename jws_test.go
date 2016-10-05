package aejws

import (
	"log"
	"net/http"
	"os"
	"testing"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/jws"

	"google.golang.org/appengine"
	"google.golang.org/appengine/aetest"
)

var aeInstance aetest.Instance

func TestMain(m *testing.M) {
	var err error
	aeInstance, err = aetest.NewInstance(nil)
	if err != nil {
		panic(err)
	}

	code := m.Run()

	aeInstance.Close()
	os.Exit(code)
}

func newTestContext() context.Context {
	r, _ := aeInstance.NewRequest("GET", "/", nil)
	return appengine.NewContext(r)
}

func ExampleEncode() {
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

		token, err := Encode(c, header, payload)
		if err != nil {
			log.Fatal(err)
			return
		}
		w.Write([]byte(token))
	})
}

func TestSignAndVerify(t *testing.T) {
	t.Parallel()
	c := newTestContext()

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

	token, err := Encode(c, header, payload)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Token\n%v", token)

	err = Verify(c, token)
	if err != nil {
		t.Fatal(err)
	}
}

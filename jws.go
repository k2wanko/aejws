package aejws

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/jws"

	"google.golang.org/appengine"
)

// Encode encodes a header and claim set with the appengine identity api.
func Encode(ctx context.Context, header *jws.Header, c *jws.ClaimSet) (token string, err error) {
	kid, _, err := appengine.SignBytes(ctx, []byte("dummy"))
	if err != nil {
		return "", err
	}

	header.KeyID = kid

	var kn string
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
			sg := func(data []byte) (sig []byte, err error) {
				kn, sig, err = appengine.SignBytes(ctx, data)
				return
			}
			token, err = jws.EncodeWithSigner(header, c, sg)
			if err != nil {
				return "", err
			}
			if header.KeyID == kn {
				return
			}
			header.KeyID = kn
		}
	}
}

func decodeHeader(payload string) (*jws.Header, error) {
	s := strings.Split(payload, ".")
	if len(s) < 2 {
		return nil, errors.New("aejws: invalid token received")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s[0])
	if err != nil {
		return nil, err
	}
	h := &jws.Header{}
	err = json.NewDecoder(bytes.NewBuffer(decoded)).Decode(h)
	return h, err
}

func parseRSAPublicKeyFromPEM(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("aejws: Invalid Key")
	}

	pkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			pkey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	key, ok := pkey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("aejws: Invalid RSA public key")
	}
	return key, nil
}

// Verify tests
func Verify(ctx context.Context, token string) error {
	h, err := decodeHeader(token)
	if err != nil {
		return err
	}

	certs, err := appengine.PublicCertificates(ctx)
	if err != nil {
		return err
	}
	for _, cert := range certs {
		if h.KeyID != cert.KeyName {
			continue
		}
		key, err := parseRSAPublicKeyFromPEM(cert.Data)
		if err != nil {
			return err
		}
		return jws.Verify(token, key)
	}
	return errors.New("aejws: Not found public key")
}

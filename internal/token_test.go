package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"text/template"
	"time"

	"github.com/google/go-cmp/cmp"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Claims struct {
	*jwt.Claims
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

func TestValidate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       key,
	}

	options := jose.SignerOptions{}
	options.WithType("JWT")

	signer, err := jose.NewSigner(signingKey, &options)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	claims := Claims{
		Claims: &jwt.Claims{
			Issuer:   "issuer",
			Audience: []string{"audience"},
			Subject:  "subject",
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(300 * time.Second)),
		},
		Username: "username",
		Groups:   []string{"group1", "group2"},
	}

	builder := jwt.Signed(signer)

	token, err := builder.Claims(claims).CompactSerialize()
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	pubkey := PublicKey{
		Data: key.Public(),
	}

	template := IdentityTemplate{
		UID:         createTemplate("UID", "{{ .sub }}"),
		Username:    createTemplate("Username", "{{ .username }}"),
		Group:       createTemplate("Group", "{{ . }}"),
		GroupsField: "groups",
	}

	issuer := Issuer{
		Name:      "name",
		Issuer:    "issuer",
		PublicKey: pubkey,
		Template:  template,
	}

	config := Config{
		Address: "0.0.0.0",
		Port:    443,
		Issuers: []Issuer{issuer},
	}

	identity, err := config.validate(token)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	expected := Identity{
		UID:      "subject",
		Username: "username",
		Groups:   []string{"group1", "group2"},
	}

	if !cmp.Equal(identity, expected) {
		t.Errorf("token identity did not match expected value:\n%s", cmp.Diff(expected, identity))
		return
	}
}

func createTemplate(name string, t string) *template.Template {
	return template.Must(template.New(name).Option("missingkey=error").Parse(t))
}

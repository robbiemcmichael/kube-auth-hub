package internal

import (
	"bytes"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Identity struct {
	UID      string
	Username string
	Groups   []string
}

func (c *Config) validate(tokenString string) (Identity, error) {
	token, err := jwt.ParseSigned(tokenString)
	if err != nil {
		return Identity{}, fmt.Errorf("parse JWT: %v", err)
	}

	var publicClaims jwt.Claims
	if err := token.UnsafeClaimsWithoutVerification(&publicClaims); err != nil {
		return Identity{}, err
	}

	found := Issuer{}
	for _, i := range c.Issuers {
		if i.Issuer == publicClaims.Issuer {
			publicKey, err := i.GetPublicKey()
			if err != nil {
				log.Warnf("get public key for issuer %q: %v", i.Name, err)
				continue
			}

			var ignore jwt.Claims
			if err := token.Claims(publicKey, &ignore); err == nil {
				found = i
				break
			}
		}
	}

	if found.Issuer == "" {
		return Identity{}, fmt.Errorf("failed to find issuer with matching public key")
	}

	expected := jwt.Expected{
		Time: time.Now(),
	}

	if err := publicClaims.Validate(expected); err != nil {
		return Identity{}, err
	}

	identity, err := fromClaims(*token, found.Template)
	if err != nil {
		return Identity{}, err
	}

	return identity, nil
}

func fromClaims(token jwt.JSONWebToken, template IdentityTemplate) (Identity, error) {
	var claims interface{}
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return Identity{}, err
	}

	claimsMap, ok := claims.(map[string]interface{})
	if !ok {
		return Identity{}, fmt.Errorf("failed to cast JWT claims to map[string]interface{}")
	}

	var uid bytes.Buffer
	if err := template.UID.Execute(&uid, claimsMap); err != nil {
		return Identity{}, fmt.Errorf("%v", err)
	}

	var username bytes.Buffer
	if err := template.Username.Execute(&username, claimsMap); err != nil {
		return Identity{}, fmt.Errorf("%v", err)
	}

	groupsArray, ok := claimsMap[template.GroupsField].([]interface{})
	if !ok {
		return Identity{}, fmt.Errorf("failed to cast %q claim to array", template.GroupsField)
	}

	groups := make([]string, len(groupsArray))
	for i, v := range groupsArray {
		var group bytes.Buffer
		if err := template.Group.Execute(&group, v); err != nil {
			return Identity{}, fmt.Errorf("%v", err)
		}

		groups[i] = group.String()
	}

	identity := Identity{
		UID:      uid.String(),
		Username: username.String(),
		Groups:   groups,
	}

	return identity, nil
}

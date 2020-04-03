package internal

import (
	"fmt"
	"time"

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
			var ignore jwt.Claims
			if err := token.Claims(i.PublicKey, &ignore); err == nil {
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

	identity, err := fromClaims(*token)
	if err != nil {
		return Identity{}, err
	}

	return identity, nil
}

func fromClaims(token jwt.JSONWebToken) (Identity, error) {
	var claims interface{}
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return Identity{}, err
	}

	claimsMap, ok := claims.(map[string]interface{})
	if !ok {
		return Identity{}, fmt.Errorf("failed to cast JWT claims to map[string]interface{}")
	}

	uid, ok := claimsMap["sub"].(string)
	if !ok {
		return Identity{}, fmt.Errorf("failed to cast %q claim to string", "sub")
	}

	username, ok := claimsMap["username"].(string)
	if !ok {
		return Identity{}, fmt.Errorf("failed to cast %q claim to string", "username")
	}

	interfaceArray, ok := claimsMap["groups"].([]interface{})
	if !ok {
		return Identity{}, fmt.Errorf("failed to cast %q claim to array", "groups")
	}

	groups := make([]string, len(interfaceArray))
	for i, v := range interfaceArray {
		group, ok := v.(string)
		if !ok {
			return Identity{}, fmt.Errorf("failed to cast group to string: %v", v)
		}

		groups[i] = group
	}

	identity := Identity{
		UID:      uid,
		Username: username,
		Groups:   groups,
	}

	return identity, nil
}

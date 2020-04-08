package internal

import (
	"fmt"
	"text/template"
)

type Config struct {
	Address string   `yaml:"address"`
	Port    int      `yaml:"port"`
	Issuers []Issuer `yaml:"issuers"`
}

type Issuer struct {
	Name      string           `yaml:"name"`
	Issuer    string           `yaml:"issuer"`
	PublicKey interface{}      `yaml:"publicKey"`
	Template  IdentityTemplate `yaml:"template"`
}

type IdentityTemplate struct {
	UID         *template.Template
	Username    *template.Template
	Group       *template.Template
	GroupsField string
}

func (x *IdentityTemplate) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var wrapper struct {
		UID         string `yaml:"uid"`
		Username    string `yaml:"username"`
		Group       string `yaml:"group"`
		GroupsField string `yaml:"groupsField"`
	}

	if err := unmarshal(&wrapper); err != nil {
		return fmt.Errorf("unmarshal IdentityTemplate: %v", err)
	}

	uid, err := template.New("UID").Option("missingkey=error").Parse(wrapper.UID)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	username, err := template.New("username").Option("missingkey=error").Parse(wrapper.Username)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	group, err := template.New("group").Option("missingkey=error").Parse(wrapper.Group)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	*x = IdentityTemplate{
		UID:         uid,
		Username:    username,
		Group:       group,
		GroupsField: wrapper.GroupsField,
	}

	return nil
}

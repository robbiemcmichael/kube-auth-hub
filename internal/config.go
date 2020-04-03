package internal

type Config struct {
	Address string   `yaml:"address"`
	Port    int      `yaml:"port"`
	Issuers []Issuer `yaml:"issuers"`
}

type Issuer struct {
	Name      string      `yaml:"name"`
	Issuer    string      `yaml:"issuer"`
	PublicKey interface{} `yaml:"publicKey"`
}

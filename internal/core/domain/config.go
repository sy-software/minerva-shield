package domain

import (
	"crypto/rsa"
	"encoding/json"
	"os"

	"github.com/rs/zerolog/log"
	mCrypto "github.com/sy-software/minerva-go-utils/crypto"
)

// Token contains the required settings to manipulate auth tokens
type Token struct {
	// For JWT signature using RS256 algorithm
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`

	// We need to parse the key into *rsa.PrivateKey to be usable
	rsaKey *rsa.PrivateKey
}

// KeyPair parses private and public key string into a *rsa.PrivateKey instance
func (t *Token) KeyPair() (*rsa.PrivateKey, error) {
	if t.rsaKey != nil {
		return t.rsaKey, nil
	}

	pk, err := mCrypto.StrToPrivateKey(t.PrivateKey, t.PublicKey)

	if err != nil {
		return nil, err
	}

	t.rsaKey = pk
	return pk, nil
}

type TokenValidator string

const (
	ExternalTokenValidator TokenValidator = "external"
	InternalTokenValidator TokenValidator = "internal"
)

// Route represents a resource accessible behind shield layer
type Route struct {
	// The internal resource path
	Path string `json:"path"`
	// The internal resource host
	Host string `json:"host"`
	// The internal resource scheme
	Scheme string `json:"scheme"`
	// If set will try to validate the token with the specified validator
	TokenValidator *TokenValidator `json:"tokenValidator"`
	// If set, will verify the token "use" claim against this value
	TokenUse *string `json:"tokenUse,omitempty"`
}

// Config all options required by this service to run
type Config struct {
	// Token related configuration
	Token Token `json:"token"`
	// The host to run this server
	Host string `json:"host,omitempty"`
	// The port to run this server
	Port string `json:"port,omitempty"`
	// A map between external resources to the internal resources
	RouteTable map[string]Route `json:"routeTable,omitempty"`
}

// DefaultConfig returns a configuration object with the default values
func DefaultConfig() Config {
	return Config{
		Token:      Token{},
		Host:       "0.0.0.0",
		Port:       "8080",
		RouteTable: map[string]Route{},
	}
}

// LoadConfiguration reads configuration from the specified json file
func LoadConfiguration(file string) Config {
	config := DefaultConfig()
	configFile, err := os.Open(file)

	if err != nil {
		log.Warn().Err(err).Msg("Can't load config file. Default values will be used instead")
	}

	defer configFile.Close()

	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&config)
	return config
}

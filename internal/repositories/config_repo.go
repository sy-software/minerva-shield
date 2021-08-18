package repositories

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sy-software/minerva-shield/internal/core/domain"
)

type ConfigRepo struct{}

const (
	DEFAULT_CONFIG_FILE = "./config.json"
	CONFIG_FILE_VAR     = "CONFIG_FILE"
	CONFIG_SERVER_VAR   = "CONFIG_SERVER"
)

func (repo *ConfigRepo) Get() domain.Config {
	log.Info().Msg("Loading configuration")
	config := domain.DefaultConfig()
	configServer := os.Getenv(CONFIG_SERVER_VAR)

	if configServer != "" {
		log.Info().Msgf("Looking for configuration from: %s", configServer)
		var netClient = &http.Client{
			Timeout: time.Second * 10,
		}

		if !strings.HasSuffix(configServer, "/") {
			configServer = configServer + "/"
		}

		response, err := netClient.Get(fmt.Sprintf("%s%s", configServer, "shield"))

		if err != nil {
			log.Error().Err(err).Msg("Can't load config:")
			panic(err)
		}

		buf, err := ioutil.ReadAll(response.Body)

		if err != nil {
			log.Error().Err(err).Msg("Can't load config:")
			panic(err)
		}

		err = json.Unmarshal(buf, &config)

		if err != nil {
			log.Error().Err(err).Msg("Can't load config:")
			panic(err)
		}

		log.Info().Msg("Configuration loaded")
		return config
	}

	configFile := os.Getenv(CONFIG_FILE_VAR)
	if configFile == "" {
		configFile = DEFAULT_CONFIG_FILE
	}

	log.Info().Msgf("Looking for configuration from: %s", configFile)
	config = domain.LoadConfiguration(configFile)
	log.Info().Msg("Configuration loaded")
	return config
}

package repositories

import (
	"encoding/json"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/rs/zerolog/log"
	"github.com/sy-software/minerva-shield/internal/core/domain"
)

type MinervaTokenValidator struct {
	config *domain.Config
}

func NewMinervaTokenValidator(config *domain.Config) *MinervaTokenValidator {
	return &MinervaTokenValidator{
		config: config,
	}
}

func (val *MinervaTokenValidator) Validate(token string) (domain.User, error) {
	return val.validate(token, nil)
}

func (val *MinervaTokenValidator) ValidateUse(token string, use string) (domain.User, error) {
	return val.validate(token, &use)
}

func (val *MinervaTokenValidator) validate(token string, use *string) (domain.User, error) {
	keys, err := val.config.Token.KeyPair()

	if err != nil {
		return domain.User{}, err
	}

	var decoded jwt.Token
	if use == nil {
		decoded, err = jwt.Parse(
			[]byte(token),
			jwt.WithVerify(jwa.RS256, keys.PublicKey),
			jwt.WithValidate(true),
		)
	} else {
		decoded, err = jwt.Parse(
			[]byte(token),
			jwt.WithVerify(jwa.RS256, keys.PublicKey),
			jwt.WithValidate(true),
			jwt.WithClaimValue("use", *use),
		)
	}

	if err != nil {
		log.Debug().Err(err).Msg("Token validation error:")
		// Token is expired
		if err.Error() == "exp not satisfied" {
			return domain.User{}, domain.ErrExpiredToken
		} else if err.Error() == "use not satisfied" {
			return domain.User{}, domain.ErrInvalidTokenUse
		} else {
			return domain.User{}, domain.ErrInvalidToken
		}
	}

	userMap, ok := decoded.Get("user")
	if !ok {
		return domain.User{}, domain.ErrNoUsrInToken
	}

	// TODO: Find a more efficient way
	userBytes, err := json.Marshal(userMap)
	if err != nil {
		return domain.User{}, domain.ErrNoUsrInToken
	}
	var user domain.User
	err = json.Unmarshal(userBytes, &user)
	if err != nil {
		return domain.User{}, domain.ErrNoUsrInToken
	}

	return user, nil
}

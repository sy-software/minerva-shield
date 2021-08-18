package repositories

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"github.com/rs/zerolog/log"
	"github.com/sy-software/minerva-shield/internal/core/domain"
	"google.golang.org/api/option"
)

type FirebaseTokenValidator struct {
	config       *domain.Config
	firebaseAuth *auth.Client
}

func NewFirebaseTokenValidator(config *domain.Config) *FirebaseTokenValidator {
	optionsJSON, err := base64.StdEncoding.DecodeString(config.Firebase)
	if err != nil {
		panic(fmt.Sprintf("Firebase load error: %v", err))
	}

	opt := option.WithCredentialsJSON(optionsJSON)
	//Firebase admin SDK initialization
	firebaseApp, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		panic(fmt.Sprintf("Firebase load error: %v", err))
	}

	//Firebase Auth
	firebaseAuth, err := firebaseApp.Auth(context.Background())
	if err != nil {
		panic(fmt.Sprintf("Firebase load error: %v", err))
	}

	return &FirebaseTokenValidator{
		config:       config,
		firebaseAuth: firebaseAuth,
	}
}

func (val *FirebaseTokenValidator) Validate(token string) (domain.User, error) {
	return val.validate(token, nil)
}

func (val *FirebaseTokenValidator) ValidateUse(token string, use string) (domain.User, error) {
	return domain.User{}, errors.New("not implemented")
}

func (val *FirebaseTokenValidator) validate(token string, use *string) (domain.User, error) {
	tokenDecoded, err := val.firebaseAuth.VerifyIDToken(context.Background(), token)
	if err != nil {
		log.Error().Err(err).Msgf("Firebase token validation:")
		return domain.User{}, domain.ErrInvalidToken
	}

	// TODO: check if this data is always present
	return domain.User{
		Username: tokenDecoded.Claims["email"].(string),
		Name:     tokenDecoded.Claims["name"].(string),
		Picture:  tokenDecoded.Claims["picture"].(string),
		Provider: tokenDecoded.Firebase.SignInProvider,
		TokenID:  token,
	}, nil
}

package repositories

import (
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sy-software/minerva-go-utils/crypto"
	"github.com/sy-software/minerva-go-utils/datetime"
	"github.com/sy-software/minerva-shield/internal/core/domain"
	"github.com/sy-software/minerva-shield/internal/core/ports"
)

const PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAqKIQvqxSMVaplK3aBdRJyRYf5IhvCPH4IF2DlmmPd6ilFzH3\njJTjnDt2+6GmAQGhHau6LPExdSHmbLCck124JS8mbis83zAOQ3hfqmvgvAO4smAE\n3dxE4XX2SRsFl1aOV6oPM4ckZgTLMDNkocxfo4TVV4Yg3ycf74MKfh+47hwJAyLZ\nJFImCnheDij2YARsEHSKAdX9iEP9IFSDqhX0+XJyGxB07wHWX6fHjcXaUfKq68CI\nrX5d22m8ZN1zCmJYNTfJNpfvquy+uosSUDNU4W9WFHJmOJS6jE5lQYcbCCROlZRW\njuBfy9UJnl4jYDgWjClYYU3qrv1UGD05Vn9eIwIDAQABAoIBAE7aQYQ3ZdOmV3Or\ne5hgNQRvcQhW97yyELlpoN9Tiv+D/3aCKeQ1ttzWPYPaiZpM3b7XDx52xg6khG/s\ngbqzByl0C79WPoeKnBDWl71D5nlkMBhQp9XqatcWZsy2cv3aPoMlhSguGEoQEcb/\nMR4rR8lZkrzzfil6zQcdOmnRgZLtDL2l2gC1NIZtU/4bS3fWe7AxcnT7a6UIrxyL\nkfzOuxgUawLR5Bth/mCDbmJgsDXndT4WNO3CWBzEZ0WLXdkyAbFgPzIPMoeR+Y68\nYLBw1OhrzrMP4FrNYs6cua3HGR2PzcH3/qec1i8grMyVwCUWVLcRn36ZGZnrhjIy\nKO9cCgkCgYEAzA8QKEXAVwAyxrjPC+cwywBLk7BsYn+4MKUw3z9h8DgzKLIojxCC\nw4WSO+mZ+VFOS9lOkGPG5/d0s/8ZWo8WrOApa6pXiz5JC8IeOEh3xPNN9xpJPW7P\nbjcbaQ+gppj/fTullfrEo4O3/5YDldy7enk8xDrhtbC9iS25QNDm6s8CgYEA046U\nIGDvpOx3iv3G1dqXPFQGSe1JJ4wytqAwz8chlj63R2lIV6LiIlgEqdd0TyZag8yB\nCBGE0j+TmDc6+4xHqRCwkKL+1e2s3tR0X/Vs4CP9PXiywAbY0vhI2CtguIuBYf1Z\nruFZ5bMkf+sT4evJlSMRrmdtKoAumYXXfYJFXG0CgYEAkQb7osPAKZU4gUgDzx/m\n68Av9q1iuravP9OH4oL3pnUq1veYH+XKKhAamH40Mp/4l6vATJq9WUvkI7FgYZ5k\nrUU76wtL4OjJnZO/Sp0mklGhzcde2kyRHHIKBydWNFF085qa2vc5HkWVVg9WSQJy\nNF9KMuTuWeVdL8vRaCGQnL0CgYEAm7OyHWp6td071lYUw0xQRpxozHwRfUPYB0U6\n55FdjOC3r50zGxzMZg510DK8bYyCzcHzrWaHZN5Z2Iu9o2mJTEr2SF1ORVDaDF49\nEGrnKMgUF+v/Uwk3B36ozkCOvQQfw2jdWrKMoVwJnwP67CnHgTYAS2XfmIoiwecZ\nxEvelLkCgYEAgGqcnf4RRoIU7joEjXCorBDebDubj5C0ektbenu9rNTiCSiU7T+b\np6S9CGtMfMbl3b/w2JlojbElGvkqaBdkbWhsRpRzlRh8IC0/Gn4l03i2u9YNhVia\nQrdb/UxBM3vRVzCf216QcgCHGNQXKKQtBHu71+cFMUp5sExm6XRQ0Qc=\n-----END RSA PRIVATE KEY-----"
const PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqKIQvqxSMVaplK3aBdRJ\nyRYf5IhvCPH4IF2DlmmPd6ilFzH3jJTjnDt2+6GmAQGhHau6LPExdSHmbLCck124\nJS8mbis83zAOQ3hfqmvgvAO4smAE3dxE4XX2SRsFl1aOV6oPM4ckZgTLMDNkocxf\no4TVV4Yg3ycf74MKfh+47hwJAyLZJFImCnheDij2YARsEHSKAdX9iEP9IFSDqhX0\n+XJyGxB07wHWX6fHjcXaUfKq68CIrX5d22m8ZN1zCmJYNTfJNpfvquy+uosSUDNU\n4W9WFHJmOJS6jE5lQYcbCCROlZRWjuBfy9UJnl4jYDgWjClYYU3qrv1UGD05Vn9e\nIwIDAQAB\n-----END PUBLIC KEY-----"

const ALT_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA0xCoT7NTdgez8zTkq/w858wevi0p0I+HvJs7ftL4iae5BfIv\n0fX38l4Qpl6J1WdHCIumVJF/xIZSik3xgs8WtSVSTYZvHEbfP8iyaPbEb0ojlROC\n5Yk9hqCChY5Rz6r8XfwoIo10KY2jnGscejKmFAKwC+1ebdniyV++xPFmMXUTZMZx\n1YPkT9Rzg3pOZhpOYAaof1W5/uz+CrRj6sFIj4lD4UFR/7LRRAcy5oDbAFG3S37p\nTiXI1lhkKWNgUeUSXgWb2K0gx9oZip+c4om2ZaU/6GickQAX/iEMBSVYEDfcXtcj\nkZ4IxwI23PXGPTONQVWyTH/hwhVbrfg+a5+j1wIDAQABAoIBAQCDfeQtyx2a8c+V\nHAW+c+WJz2vztPVQ/qpkwRz+tPar47bsUmaiWqe+8gVTcKBUOART+ZSFKSQ9TiWM\nDmUAxn1yGy88Jx1/s1OQTDuCEwJsBvdF/6LT131iKwtFo1Wql+6jqt1iMVgGLzyX\nzU8vffBjlQ0SUS48J7sXE7Qow++TrSekSzjFBD1yZKpINpwJG+agHDLnOvmsTzrl\nMlT+rhinNN+lrQgCbnGul6o0zUo6U6hI8L/83YeCmkTBQCn5wMl51aRBmX58sCuP\nMJrrD1WYHA06qRdlt72bhhj2PtE/+S4OjaTXfxeGsQ5xlj3LoO1WY3ardjwkoHy1\njFEbq7iRAoGBAPKGGlm9PEGS2+aqoSQeKvxPIAS+2yiYWyfNvAU0hmTkSSfftqii\npgo83N66e2qnfDAsvlxWqvHg/cK9mOB63zlXjtYetMRDVPsn1nGBCrR8sExb3MXv\neVttoU7vSY373UXizZgXQFpu3P+CwciLQuSM27wZC9yidNV9sfCJCspZAoGBAN7L\nDdmhjmpY/Ojvo//0ITTvbrfx7Ni4geDYK+CTvOcvPolaMI5+T0h/grTabqTWBc9F\nq48YPNUwfpsalotW+JXM1DISSqySksX4OA3+xcYAzDzfcMuYzCtKu+P1IvONCx1e\nGYMef16w4CHF5+BdVW53fSWD6T9V6MJktf6ujbmvAoGBAJgdiNWUngC7LnZlu6C9\n01RiBME1PJ0fwr0ai73wDgOmNERwS09GhUKSni6NZO+mkXxd9CBSs/H2nvPQm9zg\n9LYwtwSSSet4GAtYF2cl+yLtul6Kl9UGuWWhQ7YQ3F/UBBvbf/zPSKvwMWmKCCXT\nQ2e6+e/m/curkgB+UGeAbWYxAoGAd1mHneJyDH6HXbGixWbesyDgyyGKo76TtQOY\n3cHHHIGump36DRuVFV1Zg9DQHPWaPyMveISfcgV8jVJ8+0AoAverZPdvkWsjvXHv\ndW/aOuwKfUGlhyvflAGBDekwRBB2t9DFEfywduWB7BW81fCp53eTTxmPRiKbgie5\nZynTOnkCgYEAv3YtQmriMyPfJ5gNPtKCt9YQSZim1ibrvzwtOv/hap+4A+zKUoPb\nWHzEUlnyjXt+6FUXMLFbxN1FEDG3yqVmvARshmvvhZpLJA0jHQjKOfIQdSyy2xfg\nNCN9+b2S0asEPJZy2zZ4YtK0OdBTd/cpCER3K7GQtiZS+mBs4J0ntZo=\n-----END RSA PRIVATE KEY-----"
const ALT_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0xCoT7NTdgez8zTkq/w8\n58wevi0p0I+HvJs7ftL4iae5BfIv0fX38l4Qpl6J1WdHCIumVJF/xIZSik3xgs8W\ntSVSTYZvHEbfP8iyaPbEb0ojlROC5Yk9hqCChY5Rz6r8XfwoIo10KY2jnGscejKm\nFAKwC+1ebdniyV++xPFmMXUTZMZx1YPkT9Rzg3pOZhpOYAaof1W5/uz+CrRj6sFI\nj4lD4UFR/7LRRAcy5oDbAFG3S37pTiXI1lhkKWNgUeUSXgWb2K0gx9oZip+c4om2\nZaU/6GickQAX/iEMBSVYEDfcXtcjkZ4IxwI23PXGPTONQVWyTH/hwhVbrfg+a5+j\n1wIDAQAB\n-----END PUBLIC KEY-----"

func TestValidate(t *testing.T) {
	config := domain.DefaultConfig()
	config.Token.PrivateKey = PRIVATE_KEY
	config.Token.PublicKey = PUBLIC_KEY

	user := domain.User{
		Id:       "myId",
		Username: "IronMan",
		Name:     "Tony Stark",
		Picture:  "https://picture.me/tony",
		Role:     "hero",
		Provider: "minerva",
		TokenID:  "myTokenId",
	}

	userBytes, _ := json.Marshal(user)
	var userMap map[string]interface{}
	json.Unmarshal(userBytes, &userMap)

	key, _ := config.Token.KeyPair()

	t.Run("Test a valid token", func(t *testing.T) {
		token, _ := createToken(
			"myId",
			datetime.UnixNow().Add(time.Duration(24)*time.Hour),
			"access",
			&userMap,
			key,
		)

		validator := NewMinervaTokenValidator(&config)
		got, err := validator.Validate(token)

		if err != nil {
			t.Errorf("Expected validation without error, got: %v", err)
		}

		if !cmp.Equal(got, user) {
			t.Errorf("Expected user: %+v, got: %+v", user, got)
		}
	})

	t.Run("Test an expired token", func(t *testing.T) {
		token, _ := createToken(
			"myId",
			datetime.UnixNow().Add(time.Duration(-24)*time.Hour),
			"access",
			&userMap,
			key,
		)

		validator := NewMinervaTokenValidator(&config)
		_, err := validator.Validate(token)

		if err == nil {
			t.Errorf("Expected validation with error, got: %v", err)
		}

		if err != ports.ErrExpiredToken {
			t.Errorf("Expected error: %q got: %q", ports.ErrExpiredToken, err)
		}
	})

	t.Run("Test an invalid token", func(t *testing.T) {
		token := "thisIsNotAValidToken"

		validator := NewMinervaTokenValidator(&config)
		_, err := validator.Validate(token)

		if err == nil {
			t.Errorf("Expected validation with error, got: %v", err)
		}

		if err != ports.ErrInvalidToken {
			t.Errorf("Expected error: %q got: %q", ports.ErrInvalidToken, err)
		}
	})

	t.Run("Test an token without user", func(t *testing.T) {
		token, _ := createToken(
			"myId",
			datetime.UnixNow().Add(time.Duration(24)*time.Hour),
			"access",
			nil,
			key,
		)

		validator := NewMinervaTokenValidator(&config)
		_, err := validator.Validate(token)

		if err == nil {
			t.Errorf("Expected validation with error, got: %v", err)
		}

		if err != ports.ErrNoUsrInToken {
			t.Errorf("Expected error: %q got: %q", ports.ErrNoUsrInToken, err)
		}
	})

	t.Run("Test an token with invalid signature", func(t *testing.T) {
		altKey, _ := crypto.StrToPrivateKey(ALT_PRIVATE_KEY, ALT_PUBLIC_KEY)
		token, _ := createToken(
			"myId",
			datetime.UnixNow().Add(time.Duration(24)*time.Hour),
			"access",
			nil,
			altKey,
		)

		validator := NewMinervaTokenValidator(&config)
		_, err := validator.Validate(token)

		if err == nil {
			t.Errorf("Expected validation with error, got: %v", err)
		}

		if err != ports.ErrInvalidToken {
			t.Errorf("Expected error: %q got: %q", ports.ErrInvalidToken, err)
		}
	})
}

func TestValidateWithUse(t *testing.T) {
	config := domain.DefaultConfig()
	config.Token.PrivateKey = PRIVATE_KEY
	config.Token.PublicKey = PUBLIC_KEY

	user := domain.User{
		Id:       "myId",
		Username: "IronMan",
		Name:     "Tony Stark",
		Picture:  "https://picture.me/tony",
		Role:     "hero",
		Provider: "minerva",
		TokenID:  "myTokenId",
	}

	userBytes, _ := json.Marshal(user)
	var userMap map[string]interface{}
	json.Unmarshal(userBytes, &userMap)

	key, _ := config.Token.KeyPair()

	t.Run("Test a valid token", func(t *testing.T) {
		token, _ := createToken(
			"myId",
			datetime.UnixNow().Add(time.Duration(24)*time.Hour),
			"access",
			&userMap,
			key,
		)

		validator := NewMinervaTokenValidator(&config)
		got, err := validator.ValidateUse(token, "access")

		if err != nil {
			t.Errorf("Expected validation without error, got: %v", err)
		}

		if !cmp.Equal(got, user) {
			t.Errorf("Expected user: %+v, got: %+v", user, got)
		}
	})

	t.Run("Test an expired token", func(t *testing.T) {
		token, _ := createToken(
			"myId",
			datetime.UnixNow().Add(time.Duration(-24)*time.Hour),
			"access",
			&userMap,
			key,
		)

		validator := NewMinervaTokenValidator(&config)
		_, err := validator.ValidateUse(token, "access")

		if err == nil {
			t.Errorf("Expected validation with error, got: %v", err)
		}

		if err != ports.ErrExpiredToken {
			t.Errorf("Expected error: %q got: %q", ports.ErrExpiredToken, err)
		}
	})

	t.Run("Test an invalid token", func(t *testing.T) {
		token := "thisIsNotAValidToken"

		validator := NewMinervaTokenValidator(&config)
		_, err := validator.ValidateUse(token, "access")

		if err == nil {
			t.Errorf("Expected validation with error, got: %v", err)
		}

		if err != ports.ErrInvalidToken {
			t.Errorf("Expected error: %q got: %q", ports.ErrInvalidToken, err)
		}
	})

	t.Run("Test an token without user", func(t *testing.T) {
		token, _ := createToken(
			"myId",
			datetime.UnixNow().Add(time.Duration(24)*time.Hour),
			"access",
			nil,
			key,
		)

		validator := NewMinervaTokenValidator(&config)
		_, err := validator.ValidateUse(token, "access")

		if err == nil {
			t.Errorf("Expected validation with error, got: %v", err)
		}

		if err != ports.ErrNoUsrInToken {
			t.Errorf("Expected error: %q got: %q", ports.ErrNoUsrInToken, err)
		}
	})

	t.Run("Test an token with invalid signature", func(t *testing.T) {
		altKey, _ := crypto.StrToPrivateKey(ALT_PRIVATE_KEY, ALT_PUBLIC_KEY)
		token, _ := createToken(
			"myId",
			datetime.UnixNow().Add(time.Duration(24)*time.Hour),
			"access",
			nil,
			altKey,
		)

		validator := NewMinervaTokenValidator(&config)
		_, err := validator.ValidateUse(token, "access")

		if err == nil {
			t.Errorf("Expected validation with error, got: %v", err)
		}

		if err != ports.ErrInvalidToken {
			t.Errorf("Expected error: %q got: %q", ports.ErrInvalidToken, err)
		}
	})

	t.Run("Test an token with invalid use", func(t *testing.T) {
		token, _ := createToken(
			"myId",
			datetime.UnixNow().Add(time.Duration(24)*time.Hour),
			"access",
			nil,
			key,
		)

		validator := NewMinervaTokenValidator(&config)
		_, err := validator.ValidateUse(token, "refresh")

		if err == nil {
			t.Errorf("Expected validation with error, got: %v", err)
		}

		if err != ports.ErrInvalidTokenUse {
			t.Errorf("Expected error: %q got: %q", ports.ErrInvalidTokenUse, err)
		}
	})
}

// Utils

func createToken(
	subject string,
	expire time.Time,
	use string,
	user *map[string]interface{},
	key *rsa.PrivateKey,
) (string, error) {
	token := jwt.New()
	token.Set(jwt.IssuerKey, "mockIssuer")
	token.Set(jwt.ExpirationKey, expire)
	token.Set(jwt.SubjectKey, subject)
	token.Set(jwt.AudienceKey, "mockAudience")

	token.Set("use", use)

	if user != nil {
		token.Set("user", user)
	}

	serialized, err := jwt.Sign(token, jwa.RS256, key)

	if err != nil {
		return "", nil
	}

	return string(serialized), nil
}

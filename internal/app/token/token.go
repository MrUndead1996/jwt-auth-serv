package token

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

type accessClaims struct {
	Guid      string `json:"guid"`
	TimeStamp string `json:"create_at"`
	jwt.StandardClaims
}
type refreshClaims struct {
	AccessToken string `json:"access"`
	TimeStamp   string `json:"create_at"`
	jwt.StandardClaims
}

type TokensPair struct {
	User string `json:"user,omitempty"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func CreatePair(guid string) (*TokensPair, error) {
	accessToken := createAccess(guid)
	accessTokenSting, err := accessToken.SigningString()
	if err != nil {
		return nil, err
	}
	refreshToken, _ := createRefresh(accessTokenSting).SigningString()
	pair := TokensPair{
		User: guid,
		AccessToken:  accessTokenSting,
		RefreshToken: refreshToken,
	}
	return &pair, nil
}


func createAccess(guid string) (token *jwt.Token) {
	date := time.Now().String()
	accessClaims := accessClaims{
		Guid:      guid,
		TimeStamp: date,
	}
	token = jwt.NewWithClaims(jwt.SigningMethodHS512,accessClaims)
	return
}

func createRefresh(tokenString string) (token *jwt.Token) {
	date := time.Now().String()
	refClaims := &refreshClaims{
		AccessToken: tokenString,
		TimeStamp:   date,
	}
	token = jwt.NewWithClaims(jwt.SigningMethodHS512, refClaims)
	return
}

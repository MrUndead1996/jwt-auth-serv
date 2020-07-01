package controller

import (
	"github.com/MrUndead1996/jwt-auth-serv/internal/app/token"
	"github.com/MrUndead1996/jwt-auth-serv/internal/dataAccess"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"regexp"
)

//DataAccess and Token Create Controller, to use call func New(database *Database).
type Controller struct {
	database *dataAccess.Database
}

//Constructor
// @params: database pointer
// return: Controller pointer
func New(database *dataAccess.Database) *Controller {
	return &Controller{
		database: database,
	}
}

//Create new pair of accessToken, refreshToken from GUID. Check GUID value regexp and empty and save in database.
// @params: string GUID
// return: pointer for pair of accessToken, refreshToken or error
func (c *Controller) CreatePair(guid string) (*token.TokensPair, error) {
	if len(guid) < 1 {
		return nil, errors.New("GUID can't be empty")
	}
	pattern := "(\\{){0,1}[0-9a-fA-F]{8}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{12}(\\}){0,1}"
	isGUID, err := regexp.Match(pattern, []byte(guid))
	if err != nil || isGUID == false {
		return nil, errors.New("GUID should be like (a0e9b0af-206a-4cc9-92e2-0dc3e8676059)")
	}

	pair, err := token.CreatePair(guid)
	if err != nil {
		return nil, err
	}
	if err = c.database.AddPair(*pair); err != nil {
		return nil, err
	}
	return pair, nil
}

//Replace pair of accessToken, refreshToken in database by user. Check for user.refreshToken == database.RefreshToken by hash snapshot
// @params: pointer for old pair of refreshToken, accessToken
// return: pointer for new pair of refreshToken, accessToken or error
func (c *Controller) Refresh(clientPair *token.TokensPair) (*token.TokensPair, error) {
	pairFromDB, err := c.database.FindByAccessToken(clientPair.AccessToken)
	if err != nil {
		return nil, err
	}
	if err = bcrypt.CompareHashAndPassword(
		[]byte(pairFromDB.RefreshToken),
		[]byte(clientPair.RefreshToken)); err != nil {
		return nil, err
	}
	newPair, err := token.CreatePair(pairFromDB.User)
	if err != nil {
		return nil, err
	}
	if err = c.database.ReplacePair(clientPair.AccessToken, *newPair); err != nil {
		return nil, err
	}
	return newPair, nil
}

//Delete from database pair of accessToken, refreshToken by refreshToken.
// @params: string token for remove
// return: nil or error
func (c *Controller) RemoveRefreshToken(removingToken string) error {
	pairs,err := c.database.FindAllRefreshTokens()
	remP := token.TokensPair{}
	if err != nil{
		return err
	}
	for _, v := range *pairs{
		if err = bcrypt.CompareHashAndPassword([]byte(v.RefreshToken), []byte(removingToken));err != nil{
			continue
		}else {remP = v}
	}
	if len(removingToken) < 1 {
		return errors.New("Token can't be empty")
	}

	if err := c.database.RemovePair(remP); err != nil {
		return err
	}
	return nil
}

//Delete from database all pairs of accessToken, refreshToken by user.
// @params: GUID string
// return: integer count for remove or error
func (c *Controller) RemoveAllTokensByUser(guid string) (int64, error) {
	if len(guid) < 1 {
		return 0, errors.New("GUID can't be empty")
	}

	count, err := c.database.RemoveAllByUser(guid)
	if err != nil {
		return 0, nil
	}

	return count, nil
}

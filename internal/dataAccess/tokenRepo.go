package dataAccess

import (
	"context"
	"github.com/MrUndead1996/jwt-auth-serv/internal/app/token"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"time"
)

//Database struct, to use call func New(config *Config)
type Database struct {
	Config Config
	client *mongo.Client
}

//Database constructor
//param: database config
//return: database pointer
func New(config *Config) *Database {
	return &Database{
		Config: *config,
	}
}

//Get client for database
func (db *Database) Connect() error {
	client, err := mongo.NewClient(options.Client().ApplyURI(db.Config.URL))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		return err
	}
	db.client = client
	err = db.client.Ping(context.TODO(), nil)
	if err != nil {
		return err
	}
	return nil
}

//Close connection to database
func (db *Database) Close() error {
	if err := db.client.Disconnect(context.TODO()); err != nil{
		return err
	}
	return nil
}

//Add new refresh, access tokens to database
// @params: struct of user, accessToken, refreshToken
// return: nil or error
func (db *Database) AddPair(pair token.TokensPair) error {
	ctx := context.TODO()
	session, err := db.client.StartSession()
	if err != nil {
		return err
	}

	err = session.StartTransaction()
	if err != nil {
		session.EndSession(ctx)
		return err
	}
	bSon, err := createBSON(pair)
	if err != nil {
		session.EndSession(ctx)
		return err
	}
	collection := db.client.Database("JWT").Collection("pairs")
	res, err := collection.InsertOne(ctx, bSon)
	if err != nil {
		session.EndSession(ctx)
		return err
	}
	if err = session.CommitTransaction(context.TODO()); err != nil {
		session.EndSession(ctx)
		return err
	}
	log.Print(res.InsertedID)
	session.EndSession(ctx)
	return nil
}

//Find token pair in database by accessToken signInString
// @params: jwt accessToken signInSting
// return: found pair pointer or error
func (db *Database) FindByAccessToken(accessToken string) (*token.TokensPair, error) {
	opt := options.FindOne()
	filter := bson.M{"accessToken": accessToken}
	result := &token.TokensPair{}
	ctx := context.TODO()
	collection := db.client.Database("JWT").Collection("pairs")
	cur := collection.FindOne(ctx, filter, opt)
	err := cur.Decode(result)
	if err != nil {
		return nil, err
	}
	logrus.Info(result.User)
	return result, nil
}

//Get all pairs from collection
// return: token pairs array or error
func (db *Database) FindAllRefreshTokens() (*[]token.TokensPair ,error) {
	ctx := context.TODO()
	res := &[]token.TokensPair{}
	collection := db.client.Database("JWT").Collection("pairs")
	cur, err := collection.Find(ctx,bson.M{})
	if err != nil{
		return nil, err
	}
	for cur.TryNext(ctx){
		logrus.Info(cur.Current)
	}
	 if err = cur.All(ctx, res); err != nil{
	 	return nil, err
	 }
	 return res, nil
}

//Replace tokens pair for database by accessToken signInString
// @params: jwt accessToken signInSting, struct of user, refreshToken, accessToken
// return: nil or error
func (db *Database) ReplacePair(accessToken string, newPair token.TokensPair) error {
	ctx := context.Background()
	filter := bson.M{"accessToken": accessToken}
	session, err := db.client.StartSession()
	if err != nil{
		return err
	}
	err = session.StartTransaction()
	if err != nil{
		session.EndSession(ctx)
		return err
	}
	pairBson,err := createBSON(newPair)
	if err != nil{
		session.EndSession(ctx)
		return err
	}
	collection := db.client.Database("JWT").Collection("pairs")
	collection.FindOneAndReplace(ctx,filter,pairBson,options.FindOneAndReplace())
	if err = session.CommitTransaction(ctx); err != nil{
		err = session.AbortTransaction(ctx)
		session.EndSession(ctx)
		return err
	}
	session.EndSession(ctx)
	return nil
}

//Removing pair of tokens from database by refreshToken
// @params: string refreshToken
// return: nil or error
func (db *Database) RemovePair(pair token.TokensPair) error {
	ctx := context.TODO()
	session, err := db.client.StartSession()
	filter := bson.M{
		"user":         pair.User,
		"refreshToken": []byte(pair.RefreshToken),
		"accessToken": pair.AccessToken,
	}
	if err != nil{
		return err
	}
	if err = session.StartTransaction(); err != nil{
		session.EndSession(ctx)
		return err
	}
	collection := db.client.Database("JWT").Collection("pairs")
	collection.FindOneAndDelete(ctx,filter,options.FindOneAndDelete())
	if err = session.CommitTransaction(ctx); err != nil{
		err = session.AbortTransaction(ctx)
		session.EndSession(ctx)
		return err
	}
	session.EndSession(ctx)
	return nil
}

//Remove all tokens from database by user
// @params: string username
// return: integer count for remove or error
func (db *Database) RemoveAllByUser(user string) (int64, error) {
	ctx := context.TODO()
	session, err := db.client.StartSession()
	filter := bson.M{
		"user": user,
	}
	if err != nil{
		return 0,err
	}
	if err = session.StartTransaction(); err != nil{
		session.EndSession(ctx)
		return 0,err
	}
	collection := db.client.Database("JWT").Collection("pairs")
	res, err := collection.DeleteMany(ctx, filter, options.Delete())
	if err != nil {
		err = session.AbortTransaction(ctx)
		session.EndSession(ctx)
		return 0,err
	}
	if err = session.CommitTransaction(ctx); err != nil{
		err = session.AbortTransaction(ctx)
		session.EndSession(ctx)
		return 0,err
	}
	session.EndSession(ctx)
	return res.DeletedCount,nil
}

//Create Bson.M from token pairs and hash refreshToken for database
// params: pair of jwt accessToken, refreshToken
// return: bson.M pointer or error
func createBSON(pair token.TokensPair) (result *bson.M, err error) {
	cryptRef, err := bcrypt.GenerateFromPassword([]byte(pair.RefreshToken), 8)
	if err != nil {
		return nil, err
	}
	result = &bson.M{
		"user":         pair.User,
		"accessToken":  pair.AccessToken,
		"refreshToken": cryptRef,
	}
	return result, nil
}



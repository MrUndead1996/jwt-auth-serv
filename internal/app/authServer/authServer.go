package authServer

import (
	"github.com/MrUndead1996/jwt-auth-serv/internal/app/token"
	"github.com/MrUndead1996/jwt-auth-serv/internal/controller"
	"github.com/MrUndead1996/jwt-auth-serv/internal/dataAccess"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"net"
	"net/http"
	"os"
)
//Server for authorization by JWT, to use call func New(config *Config).
type AuthServer struct {
	config   *Config
	logger   *logrus.Logger
	router   *mux.Router
	database *dataAccess.Database
	controller *controller.Controller
}
//Constructor
// @params: config
func New(config *Config) *AuthServer {
	return &AuthServer{
		config: config,
		logger: logrus.New(),
		router: mux.NewRouter(),
	}
}
//Starting server function, configure software for server and start request listening
// return: nil or error
func (s *AuthServer) Start() error {
	s.logger.Info("Starting auth server")
	if err := s.configureLogger(); err != nil {
		return err
	}
	s.configureRouter()
	s.configureDatabase()
	s.configureController()
	s.logger.Info("Server started")
	return http.ListenAndServe(s.config.Port, s.router)
}
//Configuration for logger
func (s *AuthServer) configureLogger() error {
	level, err := logrus.ParseLevel(s.config.LogLevel)
	if err != nil {
		return err
	}
	s.logger.SetLevel(level)

	return nil
}

//Configuration for database
func (s *AuthServer) configureDatabase() {
	s.database = dataAccess.New(s.config.Database)
	err := s.database.Connect()
	if err != nil {
		s.logger.Error(err)
	}
}

//Configuration for database and token controller
func (s *AuthServer) configureController(){

	control := controller.New(s.database)
	s.controller = control
}

//Configuration router and routs
func (s *AuthServer) configureRouter() {
	s.router.HandleFunc("/create", s.createHandler).Methods("post","get")
	s.router.HandleFunc("/refresh", s.refreshHandler).Methods("post","get")
	s.router.HandleFunc("/remove", s.removePairHandler).Methods("delete")
	s.router.HandleFunc("/remove/all", s.removeAllHandler).Methods("delete")
}

//Handle func for create new tokens pair
func (s *AuthServer) createHandler(resp http.ResponseWriter, req *http.Request) {
	guid := getParamFromRequest(req,"guid")
	pair,err := s.controller.CreatePair(guid)
	if err != nil{
		s.logger.Error(err)
		resp.WriteHeader(http.StatusBadRequest)
		return
	}
	pair.User = ""
	_, err = resp.Write([]byte("accessToken=" + pair.AccessToken + "\nrefreshToken=" + pair.RefreshToken))
	if err != nil{
		s.logger.Error(err)
		resp.WriteHeader(http.StatusInternalServerError)
	}
}

//Handle func for refresh tokens
func (s *AuthServer) refreshHandler(resp http.ResponseWriter, req *http.Request) {
	refreshToken := getParamFromRequest(req,"refreshToken")
	accessToken := getParamFromRequest(req,"accessToken")
	s.logger.Debug(refreshToken)
	s.logger.Debug(accessToken)
	var userPair = &token.TokensPair{
		RefreshToken: refreshToken,
		AccessToken: accessToken,
	}
	newPair,err := s.controller.Refresh(userPair)
	if err != nil{
		s.logger.Error(err)
		resp.WriteHeader(http.StatusBadRequest)
		return
	}
	resp.WriteHeader(http.StatusAccepted)
	newPair.User = ""
	_, err = resp.Write([]byte("accessToken=" + newPair.AccessToken + "\nrefreshToken=" + newPair.RefreshToken))
	if err != nil{
		s.logger.Error(err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}
}

//Handle func for remove token pair
func (s *AuthServer) removePairHandler(resp http.ResponseWriter, req *http.Request){
	refreshToken := getParamFromRequest(req,"refreshToken")
	s.logger.Debug(refreshToken)
	if err := s.controller.RemoveRefreshToken(refreshToken); err != nil{
		s.logger.Error(err)
		resp.WriteHeader(http.StatusInternalServerError)
	}
	resp.WriteHeader(http.StatusNoContent)
}

//Handle func for remove all tokens by user GUID
func (s *AuthServer) removeAllHandler(resp http.ResponseWriter, req *http.Request){
	guid := getParamFromRequest(req,"guid")
	count, err := s.database.RemoveAllByUser(guid)
	if err != nil{
		s.logger.Error(err)
		resp.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	resp.WriteHeader(http.StatusAccepted)
	_, err = resp.Write([]byte(string(count)))
	if err != nil{
		s.logger.Error(err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}
}

//Helper for request handlers. Return request key value.
// @params: http.Request pointer, key string
// return: value string
func getParamFromRequest(req *http.Request, key string) string {
	switch req.Method {
	case "GET":
		return req.URL.Query().Get(key)
	case "POST":
		return req.FormValue(key)
	case "PUT":
		return req.FormValue(key)
	case "DELETE":
		return req.FormValue(key)
	}
	return ""
}



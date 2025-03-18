package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"time"

	"example.com/m/v2/helper"
	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

type APIGateway struct {
	router        *mux.Router
	redisClient   *redis.Client
	serviceRoutes map[string]string
	jwtSecret     []byte
	googleConfig  *oauth2.Config
}
type SessionInfo struct {
	UserID   string    `json:"user_id"`
	JWTToken string    `json:"jwt_token"`
	ExpireAt time.Time `json:"expires_at"`
}

func NewAPIGateway(jwtSecret string, REDIS_HOST string, REDIS_PW string, googleConf *oauth2.Config) *APIGateway {
	redisOption := &redis.Options{Addr: REDIS_HOST, Password: REDIS_PW, DB: 0}
	redisClient := redis.NewClient(redisOption)
	muxRouter := mux.NewRouter()
	serviceRoutes := make(map[string]string)
	serviceRoutes["todo"] = "http://todo-service-loadbalancer:8080"
	serviceRoutes["youtube"] = "http://youtube-api-service:8080"
	serviceRoutes["editor"] = "http://editor-api-service:8080"
	secret := []byte(jwtSecret)
	apiGateway := &APIGateway{redisClient: redisClient, router: muxRouter, serviceRoutes: serviceRoutes, jwtSecret: secret, googleConf: googleConf}
	apiGateway.setupRoutes()
	return apiGateway
}
func (gateway *APIGateway) setupRoutes() {
	gateway.router.HandleFunc("/login", gateway.handleLogin).Methods("POST")
	gateway.router.HandleFunc("/oauth/google/callback", gateway.handleGoogleCallback).Methods("GET")
	apiRouter := gateway.router.PathPrefix("/api").Subrouter()
	apiRouter.Use(gateway.authMiddleware)
	apiRouter.PathPrefix("/todo").HandlerFunc(gateway.forwardToService("todo"))
	apiRouter.PathPrefix("/youtube").HandlerFunc(gateway.forwardToService("youtube"))
	apiRouter.PathPrefix("/editor").HandlerFunc(gateway.forwardToService("editor"))
}
func (gateway *APIGateway) forwardToService(serviceName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// serviceURL := gateway.serviceRoutes[serviceName]

		// later replace with a re
		log.Printf("Forwarding request to %s service", serviceName)
		w.Write([]byte("Request forwarded to " + serviceName + " service"))

	}
}
func (gateway *APIGateway) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {

}
func (gateway *APIGateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	verifier := oauth2.GenerateVerifier()
	randomStr := helper.RandomString(15)
	url := gateway.googleConfig.AuthCodeURL(randomStr, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, 201)
}
func (gateway *APIGateway) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1 cookie check, if exits?
		// 2. session time check if err ? internal error
		// 3. time check
		sessionCookie, err := r.Cookie("session_id")
		if err != nil {
			http.Error(w, "Unauthorised, No session cookie", http.StatusUnauthorized)
			return
		}

		sessionData, err := gateway.redisClient.Get(sessionCookie.Value).Result()
		if err != nil {
			http.Error(w, "Unauthorised - Invalid session", http.StatusUnauthorized)
			return
		}
		var session SessionInfo
		if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// deal with the client, from client side
		if time.Now().After(session.ExpireAt) {
			http.Error(w, "Unauthorized - Session expired", http.StatusUnauthorized)
			return
		}

		r.Header.Set("Authorization", "Bearer "+session.JWTToken)
		next.ServeHTTP(w, r)
	})

}
func (gateway *APIGateway) Start(port string) error {
	log.Printf("API Gateway starting on  port %s", port)
	return http.ListenAndServe(":"+port, gateway.router)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	var REDIS_HOST string = os.Getenv("REDIS_HOST")
	var REDIS_PASSWORD string = os.Getenv("REDIS_PASSWORD")
	var SECRET string = os.Getenv("SECRET_KEY")
	var ORIGIN string = os.Getenv("ORIGIN")
	var OAUTH_KEY string = os.Getenv("GOOGLE_OAUTH_CLIENT_ID")
	var OAUTH_SECRET string = os.Getenv("GOOGLE_OAUTH_SECRET")
	var OAUTH_REDIRECT_URL string = os.Getenv("GOOGLE_OAUTH_REDIRECT_URL")
	var googleConf *oauth2.Config = &oauth2.Config{
		ClientID:     OAUTH_KEY,
		ClientSecret: OAUTH_SECRET,
		Scopes:       []string{"email", "profile"},
		RedirectURL:  ORIGIN + OAUTH_REDIRECT_URL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
	}
	server := NewAPIGateway(SECRET, REDIS_HOST, REDIS_PASSWORD, googleConf)
	log.Fatal(server.Start("5000"))

}

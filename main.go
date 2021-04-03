package main

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"
	_ "time"

	_ "github.com/draftms/go_web/billingService"
	"github.com/draftms/go_web/statisticsService"
	"github.com/unrolled/render"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/urfave/negroni"
)

var rd *render.Render
var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

type User struct {
	ID string 			`json:"id"`
	Name string 		`json:"name"`
	Email string 		`json:"email"`
	Class string 		`json:"class"`
	Authenticated bool
}

var users = map[string] string{
	"user1":"password1",
	"user2":"password2",
}

var jwtKey = []byte("AllYourBase")

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

type JWTClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}


func BillingService(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello Billing Service")
}

func IndexMain(w http.ResponseWriter, r *http.Request) {
	//rd.Text(w, http.StatusOK, uuid.New().String())
	//rd.Text(w, http.StatusOK, os.Getenv("SESSION_KEY"))
	rd.Text(w, http.StatusOK, "test")
}

func getUserInfoHandler(w http.ResponseWriter, r *http.Request) {

	user := User{Name: "testName", Email:"test@test.com"}

	rd.JSON(w, http.StatusOK, user)
}

func setUserInfoHandler(w http.ResponseWriter, r *http.Request) {
	user := new(User)

	err := json.NewDecoder(r.Body).Decode(user)
	if err != nil {
		rd.Text(w, http.StatusBadRequest, err.Error())
		return
	}

	rd.JSON(w, http.StatusOK, user)	
}

func MainHandler(next http.HandlerFunc) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		log.Println("Log test : ", r.URL.Path)
		next(w, r)
	}
}

////////////////////////////////////////////

func getUser(s * sessions.Session) User {
	val := s.Values["user"]
	var user = User{}
	user, ok := val.(User)
	if !ok {
		return User{Authenticated:false}
	}
	return user
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if checkauthenticate(w, r){
		t, _ := template.ParseFiles("templates/home.gohtml")
		t.Execute(w, "welcome home")
	}else {
		t, _ := template.ParseFiles("templates/login.gohtml")
		t.Execute(w, "test login template")
	}
}

func DBAuthCheck() bool {
	return true
}

func JWTloginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword, ok := users[creds.Username]

	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5*time.Minute)
	claims := &JWTClaims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "token",
		Value: tokenString, 
		Expires: expirationTime,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "teleon")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user := &User {
		ID: r.PostFormValue("txtID"),
		Authenticated: true,
	}
	if  DBAuthCheck() {
		session.Values["user"] = user
		session.Save(r, w)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "teleon")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["user"] = User{}
	session.Options.MaxAge = -1
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func checkauthenticate(w http.ResponseWriter, r *http.Request) bool {
	session, _ := store.Get(r, "teleon")

	user := getUser(session)

	if auth := user.Authenticated; !auth {
		session.AddFlash("You don't have access!")
		session.Save(r,w)
		return false
	}

	return true

	/* 
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		return false
	} else {
		return true
	}
 	*/
}

func checkAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		log.Println("Check Auth : ", r.URL.Path)

		if checkauthenticate(w, r) {
			next.ServeHTTP(w, r)
		} else {
			t, _ := template.ParseFiles("templates/login.gohtml")
			t.Execute(w, "test login template")
		} 
	})
}

func main() {

 	store.Options = &sessions.Options{
		MaxAge : 60 * 60,
		HttpOnly: true,
	}

	gob.Register(User{})
	template.Must(template.ParseGlob("templates/*.gohtml"))

 
	rd = render.New()
	router := mux.NewRouter()

	router.NotFoundHandler = http.HandlerFunc(rootHandler)

	router.HandleFunc("/", rootHandler)
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/logout", logoutHandler).Methods("POST")

	router.HandleFunc("/jwtlogin", JWTloginHandler).Methods("POST")

	billingRouter := router.PathPrefix("/billing").Subrouter()
	billingRouter.HandleFunc("", BillingService)
	billingRouter.Use(checkAuthMiddleware)

	statisticsRouter := router.PathPrefix("/statistics").Subrouter()
	statisticsRouter.HandleFunc("", (&statisticsService.Statistics{}).GetStatisticsModality)
	statisticsRouter.Use(checkAuthMiddleware)

	neg := negroni.Classic()
	neg.UseHandler(router)
	http.ListenAndServe(":7500", neg)

	/*
	to-do
	1. 로그인 시 user 정보 저장
	*/
}
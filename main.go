package main

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	_"strings"
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
	ID string 			`json:"userid"`
	Name string 		`json:"name"`
	Password string 	`json:"password"`
	Email string 		`json:"email"`
	Class string 		`json:"class"`
	Authenticated bool
}

var users = map[string] string{
	"teleid":"teleon",
	"user2":"password2",
}

var jwtKey = []byte(os.Getenv("SESSION_KEY"))

type JWTClaims struct {
	UserID string `json:"userid"`
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

func JWTRootHandler(w http.ResponseWriter, r *http.Request) {
	if checkJWTAuthenticate(r){
		t, _ := template.ParseFiles("templates/home.gohtml")
		t.Execute(w, "welcome home")
	}else {
		t, _ := template.ParseFiles("templates/login.gohtml")
		t.Execute(w, "test login template")
	}
}

func DBAuthCheck(id string, pw string) bool {
	return true
}

func JWTloginHandler(w http.ResponseWriter, r *http.Request) {

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !DBAuthCheck(user.ID, user.Password) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5*time.Minute)
	claims := &JWTClaims{
		UserID: user.ID,
		Username: user.Name,
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
		Name: "access-token",
		Value: tokenString, 
		Expires: expirationTime,
		MaxAge: 60*60,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "teleon")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user := &User {
		ID: r.PostFormValue("txtID"),
		Password: r.PostFormValue("txtPW"),
		Authenticated: true,
	}
	if  DBAuthCheck(user.ID, user.Password) {
		session.Values["user"] = user
		session.Save(r, w)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func JWTlogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: "access-token",
		Value: "", 
		Expires: time.Unix(0,0),
		MaxAge: -1,
		HttpOnly: true,
	})

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

func checkJWTAuthenticate(r *http.Request) bool {
	JWTTokenStringFromCookie, err := r.Cookie("access-token")

	if err != nil {
		return false
	}

	token, err := jwt.Parse(JWTTokenStringFromCookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Thre was an error!")
		}
		return jwtKey, nil
	})

	if err != nil {
		return false
	}

	if token.Valid {
		return true
	}

	return false
}

func isAuthorizedByJWT(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tokenString, _ := r.Cookie("access-token"); tokenString != nil {
			token, err := jwt.Parse(tokenString.Value, func(token *jwt.Token)(interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return jwtKey, nil
			})

			if err != nil {
				fmt.Fprint(w, err.Error())
			}

			if token.Valid {
				endpoint(w, r)
			}
		} else {
			fmt.Fprintf(w, "Not Authorized")
		}

	})
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

	//router.NotFoundHandler = http.HandlerFunc(rootHandler)
	//router.HandleFunc("/", rootHandler)
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/logout", logoutHandler).Methods("POST")


	router.NotFoundHandler = http.HandlerFunc(JWTRootHandler)
	router.HandleFunc("/", JWTRootHandler)
	router.HandleFunc("/jwtlogin", JWTloginHandler)
	router.HandleFunc("/jwtlogout", JWTlogoutHandler)

	billingRouter := router.PathPrefix("/billing").Subrouter()
	billingRouter.HandleFunc("", BillingService)
	billingRouter.Use(checkAuthMiddleware)

	statisticsRouter := router.PathPrefix("/statistics").Subrouter()
	statisticsRouter.HandleFunc("", (&statisticsService.Statistics{}).GetStatisticsModality)
	statisticsRouter.Use(checkAuthMiddleware)

	neg := negroni.Classic()
	neg.UseHandler(router)
	http.ListenAndServe(":7500", neg)
}
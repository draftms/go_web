package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	_"github.com/draftms/go_web/billingService"
	"github.com/draftms/go_web/statisticsService"
	"github.com/unrolled/render"

	_"github.com/google/uuid"
	"github.com/gorilla/mux"
	_"github.com/gorilla/securecookie"
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

func BillingService(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello Billing Service")
}

func IndexMain(w http.ResponseWriter, r *http.Request) {
	//rd.Text(w, http.StatusOK, uuid.New().String())
	rd.Text(w, http.StatusOK, os.Getenv("SESSION_KEY"))
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
	/*
	w.Header().Add("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	data, _ := json.Marshal(user)
	fmt.Fprint(w, string(data))	
	*/
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

func login(w http.ResponseWriter, r *http.Request) {
	session, _:= store.Get(r, "tele-on")

	//json.NewDecoder(r.Body).Decode(user)

	session.Values["authenticated"] = true
	session.Save(r,w)
}

func checkAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		log.Println("Check Auth : ", r.URL.Path)

		session, err := store.Get(r, "tele-on")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		user := getUser(session)

		if auth := user.Authenticated; !auth {
			session.AddFlash("you don't have access!")
			err = sessions.Save(r, w)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w,r, "/forbidden.html", http.StatusFound)
		}

		log.Println("Check Auth : ", r.URL.Path, user.Name)

		next.ServeHTTP(w, r)
	})
}

func main() {

	rd = render.New()
	router := mux.NewRouter()
	secureRouter := mux.NewRouter()

	router.HandleFunc("/", IndexMain)
	router.HandleFunc("/login", login).Methods("GET")

	secureRouter.HandleFunc("/billing", BillingService).Methods("GET")
	secureRouter.HandleFunc("/statistics", (&statisticsService.Statistics{}).GetStatisticsModality)

	secureRouter.Use(checkAuthMiddleware)

	neg := negroni.Classic()
	neg.UseHandler(router)
	neg.UseHandler(secureRouter)
	http.ListenAndServe(":8000", neg)
}
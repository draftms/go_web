package main 

import (
	"fmt"
	"log"
	"net/http"
)

func BillingService(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello Billing Service")
}

func StatisticsService(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello Statistics Service")
}

func IndexMain(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello")
}

func MainHandler(f http.HandlerFunc) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		log.Println("Log : ", r.URL.Path)
		f(w, r)
	}
}

func main() {

	mux := http.NewServeMux()

	mux.HandleFunc("/", MainHandler(IndexMain))
	mux.HandleFunc("/billing", MainHandler(BillingService))
	mux.HandleFunc("/statistics", MainHandler(StatisticsService))

	http.ListenAndServe(":8000", mux)
}
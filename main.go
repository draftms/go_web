package main 

import (
	"fmt"
	"log"
	"net/http"

	"github.com/draftms/go_web/billingService"
	"github.com/draftms/go_web/statisticsService"
)

func BillingService(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello Billing Service")
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
	mux.HandleFunc("/statistics", MainHandler((&statisticsService.Statistics{}).GetStatisticsModality))
	mux.HandleFunc("/billingAnalyze", MainHandler((&billingService.Billing{}).GetBillMonth))

	http.ListenAndServe(":8000", mux)

	/* TO-DO
	1. Login & Session Control
	2. Get ASP.NET Sesstion State data
	*/
}
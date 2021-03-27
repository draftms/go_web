package statisticsService

import (
	"fmt"
	"net/http"
)

type Statistics struct {}

func (s *Statistics) GetStatisticsModality(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello Statistics Modal")
}
package billingService

import (
	"fmt"
	"net/http"
)

type Billing struct {

}

func (b *Billing) GetBillMonth(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "struct billing")
}
package hmacval_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/ifraixedes/go-hmac-validator"
)

func Example_shopify() {
	secret := "hush"
	// We create a Val configured to check HMAC digests as Shopify generates
	val := hmacval.NewVal(
		sha256.New,
		[]string{"signature", "hmac"},
		[]string{"&", "%26", "%", "%25", "=", "%3D"},
		[]string{"&", "%26", "%", "%25"},
		"=",
		"&")

	// We create an request to simulate how Shopify would send requests to our application proxy
	request, err := http.NewRequest("GET", "http://yourdomain.com?shop=some-shop.myshopify.com&timestamp=1337178173&signature=6e39a2ea9e497af6cb806720da1f1bf3&hmac=c2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c7", nil)
	if err != nil {
		log.Fatalf("Error creating request: %s", err)
	}

	// We can think the the following lines would be in one (or more) of our http.Handler
	pq, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		log.Fatalf("Error parsing URL query: %s", err)
	}

	payload := make(map[string]string, len(pq))
	for n, v := range pq {
		// Shopify doesn't define how to join queyr parameters which are present more than once
		// so we assume that we can just join them
		payload[n] = strings.Join(v, "")
	}

	digest, err := hex.DecodeString(payload["hmac"])
	if err != nil {
		log.Fatalf("Error decoding provided HMAC value: %s", err)
	}

	isValid := val(secret, "", payload, digest)
	fmt.Println(isValid)
	// Output: true
}

func Example_twilio() {
	secret := "12345"
	// We create a Val configured to check HMAC digests as Twilio generates
	val := hmacval.NewVal(sha1.New, nil, nil, nil, "", "")

	// We create an request to simulate how Twilio would send requests to us
	body := []byte(`{"Digits":"1234","To":"+18005551212","From":"+14158675309","Caller":"+14158675309","CallSid":"CA1234567890ABCDE"}`)
	request, err := http.NewRequest("POST", "https://mycompany.com/myapp.php?foo=1&bar=2", bytes.NewBuffer(body))
	request.Header.Set("X-Twilio-Signature", "RSOYDt4T1cUTdK1PDd93/VVr8B8=")
	if err != nil {
		log.Fatalf("Error creating request: %s", err)
	}

	// We can think the the following lines would be in one (or more) of our http.Handler
	digest, err := base64.StdEncoding.DecodeString(request.Header.Get("X-Twilio-Signature"))
	if err != nil {
		log.Fatalf("Error decoding provided HMAC value: %s", err)
	}

	payload := make(map[string]string)
	jd := json.NewDecoder(request.Body)
	defer closeBody(request)

	if err := jd.Decode(&payload); err != nil {
		log.Fatalf("Error decoding JSON: %s", err)
	}

	isValid := val(secret, request.URL.String(), payload, digest)
	fmt.Println(isValid)
	// Output: true
}

func Example_pusher() {
	secret := "7ad3773142a6692b25b8"
	// We create a Val configured to check HMAC digests as Twilio generates
	val := hmacval.NewVal(sha256.New, nil, nil, nil, "", "")

	// We create an request to simulate how Pusher sends a WebHook
	request, err := http.NewRequest("POST", "https://mycompany.com/myapp", bytes.NewBuffer([]byte(`{"time_ms":1327078148132,"events":[{"name":"event_name","some":"data"}]}`)))
	request.Header.Set("X-Pusher-Signature", "26537b0c36841dc4e940291893424d4fba6af2a7510701f113e720df5d4f2577")
	if err != nil {
		log.Fatalf("Error creating request: %s", err)
	}

	// We can think the the following lines would be in one (or more) of our http.Handler
	digest, err := hex.DecodeString(request.Header.Get("X-Pusher-Signature"))
	if err != nil {
		log.Fatalf("Error decoding provided HMAC value: %s", err)
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Fatalf("Error reading all the content in Request's body: %s", err)
	}
	defer closeBody(request)

	isValid := val(secret, string(body), nil, digest)
	fmt.Println(isValid)
	// Output: true
}

func closeBody(req *http.Request) {
	if err := req.Body.Close(); err != nil {
		log.Fatalf("Error closing Request Body reader: %s", err)
	}
}

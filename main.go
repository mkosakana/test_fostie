package main

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/ory/fosite"
	"log"
	"net/http"
	"time"

	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
)

var privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
var config = &fosite.Config{
	AccessTokenLifespan:  time.Hour,
	RefreshTokenLifespan: time.Hour,
}
var oauth2Provider = compose.ComposeAllEnabled(config, storage.NewExampleStore(), privateKey)

func main() {
	http.HandleFunc("/ping", func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("pong"))
	})
	http.HandleFunc("/oauth2/auth", AuthorizationEndpoint)
	http.HandleFunc("/oauth2/token", TokenEndpoint)
	http.HandleFunc("/oauth2/introspect", IntrospectionEndpoint)
	log.Fatal(http.ListenAndServe(":3846", nil))
}

func AuthorizationEndpoint(rw http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	ar, err := oauth2Provider.NewAuthorizeRequest(ctx, req)
	if err != nil {
		oauth2Provider.WriteAuthorizeError(ctx, rw, ar, err)
		return
	}

	if req.URL.Query().Get("username") == "" {
		rw.Write([]byte(`set username as query parameter.`))
		return
	}

	mySessionData := &fosite.DefaultSession{
		Username: req.Form.Get("username"),
	}

	response, err := oauth2Provider.NewAuthorizeResponse(ctx, ar, mySessionData)
	if err != nil {
		oauth2Provider.WriteAuthorizeError(ctx, rw, ar, err)
		return
	}

	oauth2Provider.WriteAuthorizeResponse(ctx, rw, ar, response)
}

func TokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	mySessionData := new(fosite.DefaultSession)
	accessRequest, err := oauth2Provider.NewAccessRequest(ctx, req, mySessionData)
	if err != nil {
		oauth2Provider.WriteAccessError(ctx, rw, accessRequest, err)
		return
	}
	response, err := oauth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		oauth2Provider.WriteAccessError(ctx, rw, accessRequest, err)
		return
	}

	oauth2Provider.WriteAccessResponse(ctx, rw, accessRequest, response)
}

func IntrospectionEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	ir, err := oauth2Provider.NewIntrospectionRequest(ctx, req, new(fosite.DefaultSession))
	if err != nil {
		log.Printf("Error occurred in NewIntrospectionRequest: %+v", err)
		oauth2Provider.WriteIntrospectionError(ctx, rw, err)
		return
	}
	oauth2Provider.WriteIntrospectionResponse(ctx, rw, ir)
}

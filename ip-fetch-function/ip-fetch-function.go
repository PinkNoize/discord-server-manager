package ip_fetch_function

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/pubsub"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

var projectID string = os.Getenv("PROJECT_ID")
var commandTopicID string = os.Getenv("COMMAND_TOPIC")
var keySecretID string = os.Getenv("KEY_SECRET_ID")

var firestoreClient *firestore.Client
var commandTopic *pubsub.Topic
var aesGCM cipher.AEAD

type ForwardPubSub struct {
	Command     string  `json:"command"`
	Interaction *[]byte `json:"interaction,omitempty"`
}

type Token struct {
	Expiration time.Time `json:"expiration" firestore:"expiration"`
	Id         string    `json:"id" firestore:"id"`
	User       string    `json:"user" firestore:"user"`
	ServerName string    `json:"name" firestore:"name"`
}

func init() {
	var err error
	ctx := context.Background()
	firestoreClient, err = firestore.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("Failed to create firestore client: %v", err)
	}
	pubsubClient, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("Failed to create pubsub client: %v", err)
	}
	commandTopic = pubsubClient.Topic(commandTopicID)
}

func init() {
	var err error
	ctx := context.TODO()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("Error: init: NewClient: %v", err)
	}
	defer client.Close()
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("%v/versions/latest", keySecretID),
	}
	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		log.Fatalf("Error: init: AccessSecretVersion: %v", err)
	}
	key := result.Payload.Data

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic("init: NewCipher: %v", err)
	}

	aesGCM, err = cipher.NewGCM(block)
	if err != nil {
		log.Panic("init: NewGCM: %v", err)
	}
}

// A client-side redirect should prevent Discord preview from triggering the link
func returnClientRedirect(w http.ResponseWriter, token string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	  <head>
		<meta charset="utf-8">
		<meta property="og:title" content="Connect to server">
		<meta property="og:description" content="">
		<title>Connecting...</title>
	  </head>
	  <body>
	  	<script>window.location.replace(window.location.pathname.concat("?tokenid=%v"));</script>
	  </body>
	</html>`, token)

}

// Entry function
func IPFetchEntry(w http.ResponseWriter, r *http.Request) {

	tokenParam, ok := r.URL.Query()["tokenid"]
	if !ok || len(tokenParam) < 1 {
		log.Printf("Token not supplied")
		http.Error(w, "Missing query parameter", http.StatusUnprocessableEntity)
		return
	}
	if _, preview := r.URL.Query()["preview"]; preview {
		returnClientRedirect(w, tokenParam[0])
		return
	}
	rawToken, err := base64.URLEncoding.DecodeString(tokenParam[0])
	if err != nil {
		log.Printf("Token not valid base64: %v", err)
		http.Error(w, "Invalid parameter: tokenid", http.StatusBadRequest)
		return
	}
	nonce := rawToken[:aesGCM.NonceSize()]
	ciphertext := rawToken[aesGCM.NonceSize():]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("Invalid plaintext: %v", err)
		http.Error(w, "Invalid tokenid", http.StatusBadRequest)
		return
	}
	var token Token
	err = json.Unmarshal(plaintext, &token)
	if err != nil {
		log.Printf("Invalid JSON: %v", err)
		http.Error(w, "Invalid tokenid", http.StatusBadRequest)
		return
	}

	// Check if token is still valid
	now := time.Now().UTC()
	if !now.After(token.Expiration) {
		log.Printf("Token still valid: %v", token.Id)
		err = handleValidToken(r.Context(), r.RemoteAddr, &token)
		if err != nil {
			log.Printf("handleValidToken: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		log.Printf("Token expired: %v %v", token.Id, token.Expiration)
		http.Error(w, "Invalid tokenid", http.StatusBadRequest)
		return
	}
}

func getTokenEntry(ctx context.Context, id string) (*Token, error) {
	tokenDocRef := firestoreClient.Collection("Tokens").Doc(id)
	token := Token{}
	var err error
	tokenDoc, err := tokenDocRef.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("get: %v", err)
	}
	if !tokenDoc.Exists() {
		return nil, fmt.Errorf("token %v does not exist", id)
	}
	err = tokenDoc.DataTo(&token)
	if err != nil {
		return nil, fmt.Errorf("DataTo: %v", err)
	}
	_, err = tokenDocRef.Delete(ctx)
	if err != nil {
		return nil, fmt.Errorf("delete: %v", err)
	}
	return &token, nil
}

func handleValidToken(ctx context.Context, remoteAddr string, token *Token) error {
	remoteToken, err := getTokenEntry(ctx, token.Id)
	if err != nil {
		return fmt.Errorf("getTokenEntry: %v", err)
	}
	log.Printf("Token: %+v", *token)
	log.Printf("RemoteToken: %+v", *remoteToken)
	if remoteToken.Id == token.Id &&
		remoteToken.ServerName == token.ServerName &&
		remoteToken.User == token.User &&
		remoteToken.Expiration.Round(time.Millisecond).Equal(token.Expiration.Round(time.Millisecond)) {
		return fmt.Errorf("passed token did not match server token")
	}
	remoteIP := strings.Split(remoteAddr, ":")[0]
	log.Printf("Adding %v to server %v", remoteIP, remoteToken.ServerName)
	pubSubData, err := json.Marshal(ForwardPubSub{
		Command:     "add-user-ip",
		Interaction: nil,
	})
	if err != nil {
		return fmt.Errorf("jsonMarshal: %v", err)
	}
	result := commandTopic.Publish(ctx, &pubsub.Message{
		Data: pubSubData,
		Attributes: map[string]string{
			"name": remoteToken.ServerName,
			"ip":   remoteIP,
			"user": remoteToken.User,
		},
	})
	_, err = result.Get(ctx)
	if err != nil {
		return fmt.Errorf("Pubsub.Publish: %v", err)
	}
	return nil
}

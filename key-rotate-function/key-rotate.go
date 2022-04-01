package key_rotate_function

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"google.golang.org/api/iterator"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

// PubSubMessage is the payload of a Pub/Sub event.
// See the documentation for more details:
// https://cloud.google.com/pubsub/docs/reference/rest/v1/PubsubMessage
type PubSubMessage struct {
	Data       []byte           `json:"data"`
	Attributes PubSubAttributes `json:"attributes"`
}

// PubSubAttributes are attributes from the Pub/Sub event.
type PubSubAttributes struct {
	SecretId  string `json:"secretId"`
	EventType string `json:"eventType"`
}

// Handles key rotation.
func KeyRotatePubSub(ctx context.Context, m PubSubMessage) error {
	eventType := m.Attributes.EventType
	secretID := m.Attributes.SecretId
	data := m.Data

	log.Printf("Received %s for %s. New metadata: %q.",
		eventType, secretID, data)

	switch eventType {
	case "SECRET_ROTATE":
		client, err := secretmanager.NewClient(ctx)
		if err != nil {
			return fmt.Errorf("NewClient: %v", err)
		}
		defer client.Close()

		oldSecrets := make([]string, 0, 10)
		listReq := &secretmanagerpb.ListSecretVersionsRequest{
			Parent: secretID,
		}
		iter := client.ListSecretVersions(ctx, listReq)
		for {
			resp, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return fmt.Errorf("iter.Next(): %v", err)
			}
			oldSecrets = append(oldSecrets, resp.Name)
		}
		log.Printf("%v old secrets in %v", len(oldSecrets), secretID)

		newKey := make([]byte, 16)

		_, err = rand.Read(newKey)
		if err != nil {
			return fmt.Errorf("rand.Read(): %v", err)
		}

		addReq := &secretmanagerpb.AddSecretVersionRequest{
			Parent: secretID,
			Payload: &secretmanagerpb.SecretPayload{
				Data: newKey,
			},
		}
		_, err = client.AddSecretVersion(ctx, addReq)
		if err != nil {
			return fmt.Errorf("AddSecretVersion: %v", err)
		}
		log.Printf("Created new secret version")
		for _, name := range oldSecrets {
			destroyReq := &secretmanagerpb.DestroySecretVersionRequest{
				Name: name,
			}
			_, err = client.DestroySecretVersion(ctx, destroyReq)
			if err != nil {
				return fmt.Errorf("DestroySecretVersion: %v", err)
			}
		}
		return nil
	default:
		return nil
	}
}

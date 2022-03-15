package discord_function

import (
	"context"
	"fmt"
	"log"
	"net/http"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/bwmarrin/discordgo"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

var (
	commands = []*discordgo.ApplicationCommand{
		{
			Name:        "server",
			Description: "View/Modify servers' states",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Name:        "create",
					Description: "Create a server",
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "name",
							Description: "Name of the server",
							Required:    true,
						},
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "subdomain",
							Description: "Subdomain of the server",
							Required:    true,
						},
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "MachineType",
							Description: "GCP Machine Type that the server will use",
							Required:    true,
						},
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "ports",
							Description: "Comma-seperated port numbers to be opened to users",
							Required:    true,
						},
					},
				},
				{
					Name:        "start",
					Description: "Start a server",
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "name",
							Description: "Name of the server",
							Required:    true,
						},
					},
				},
				{
					Name:        "delete",
					Description: "Delete a server",
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "name",
							Description: "Name of the server",
							Required:    true,
						},
					},
				},
			},
		},
	}
)

var discordSession *discordgo.Session

func init() {
	var err error
	ctx := context.TODO()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("Error: initDiscord: NewClient: %v", err)
	}
	defer client.Close()
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("%v/versions/latest", discordSecretID),
	}
	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		log.Fatalf("Error: initDiscord: AccessSecretVersion: %v", err)
	}
	discordAPIToken := string(result.Payload.Data)
	discordSession, err = discordgo.New(fmt.Sprintf("Bot %v", discordAPIToken))
	if err != nil {
		log.Fatalf("Invalid bot parameters: %v", err)
	}
}

func DiscordCommandDeploy(w http.ResponseWriter, r *http.Request) {
	for i := range commands {
		_, err := discordSession.ApplicationCommandCreate(discordAppID, "", commands[i])
		if err != nil {
			log.Fatalf("ApplicationCommandCreate: %v", err)
		}
	}
}

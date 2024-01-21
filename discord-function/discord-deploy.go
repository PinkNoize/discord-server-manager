package discord_function

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/bwmarrin/discordgo"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

var (
	minDiskSize = 10.0
	commands    = []*discordgo.ApplicationCommand{
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
							Name:        "machinetype",
							Description: "GCP Machine Type that the server will use",
							Required:    true,
						},
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "purpose",
							Description: "Purpose of the server",
							Required:    true,
							Choices: []*discordgo.ApplicationCommandOptionChoice{
								{
									Name:  "Game",
									Value: "Game",
								},
								{
									Name:  "Server",
									Value: "Server",
								},
							},
						},
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "os",
							Description: "OS Family (the latest version will be used)",
							Required:    true,
							Choices: []*discordgo.ApplicationCommandOptionChoice{
								{
									Name:  "Debian 12",
									Value: "debian-12",
								},
								{
									Name:  "Ubuntu 22.04",
									Value: "ubuntu-2204-lts",
								},
							},
						},
						{
							Type:        discordgo.ApplicationCommandOptionInteger,
							Name:        "disksize",
							Description: "Maximum disk size in GB",
							Required:    true,
							MaxValue:    100,
							MinValue:    &minDiskSize,
						},
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "ports",
							Description: "Space-seperated port numbers to be opened to users",
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
					Name:        "stop",
					Description: "Stop a server",
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
				{
					Name:        "status",
					Description: "Get all or a specific server's status",
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "name",
							Description: "Name of the server",
							Required:    false,
						},
					},
				},
				{
					Name:        "connect",
					Description: "Connect to a server",
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
		{
			Name:        "sshkey",
			Description: "Modify ssh keys",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Name:        "add",
					Description: "Adds an sshkey",
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
							Name:        "sshkey",
							Description: "ssh key",
							Required:    true,
						},
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "user",
							Description: "user (lowercase, no root)",
							Required:    true,
						},
					},
				},
				{
					Name:        "clear",
					Description: "Clears ssh keys for a server",
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
		{
			Name:        "user",
			Description: "View/Modify user permissions",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Name:        "add",
					Description: "Add a permission for user to start/stop a server",
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionUser,
							Name:        "user",
							Description: "Name of the user",
							Required:    true,
						},
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "name",
							Description: "Name of the server",
							Required:    true,
						},
					},
				},
				{
					Name:        "remove",
					Description: "Remove a permission for user to start/stop a server",
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionUser,
							Name:        "user",
							Description: "Name of the user",
							Required:    true,
						},
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "name",
							Description: "Name of the server",
							Required:    true,
						},
					},
				},
				{
					Name:        "perms",
					Description: "List a user's permissions",
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionUser,
							Name:        "user",
							Description: "Name of the user",
							Required:    true,
						},
					},
				},
			},
		},
	}
)

var discordDeploySession *discordgo.Session

var initDiscordCommandDeployOnce sync.Once

func initDiscordCommandDeploy() {
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
	discordDeploySession, err = discordgo.New(fmt.Sprintf("Bot %v", discordAPIToken))
	if err != nil {
		log.Fatalf("Invalid bot parameters: %v", err)
	}
}

func DiscordCommandDeploy(w http.ResponseWriter, r *http.Request) {
	initDiscordCommandDeployOnce.Do(initDiscordCommandDeploy)
	for i := range commands {
		_, err := discordDeploySession.ApplicationCommandCreate(discordAppID, "", commands[i])
		if err != nil {
			log.Fatalf("ApplicationCommandCreate: %v", err)
		}
	}
}

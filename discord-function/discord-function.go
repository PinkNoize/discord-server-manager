package discord_function

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/pubsub"
	"github.com/bwmarrin/discordgo"
)

// Globals
var projectID string = os.Getenv("PROJECT_ID")
var commandTopicID string = os.Getenv("COMMAND_TOPIC")
var rootUserID string = os.Getenv("ADMIN_DISCORD_ID")
var discordPubkey []byte
var discordAppID string = os.Getenv("DISCORD_APPID")
var discordSecretID string = os.Getenv("DISCORD_SECRET_ID")

var firestoreClient *firestore.Client
var permsChecker *PermissionManager
var commandTopic *pubsub.Topic

type ForwardPubSub struct {
	Command     string  `json:"command"`
	Interaction *[]byte `json:"interaction,omitempty"`
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
	discordPubkey, err = hex.DecodeString(os.Getenv("DISCORD_PUBKEY"))
	if err != nil {
		log.Fatalf("Failed to decode public key: %v", err)
	}
}

var initEnforcer sync.Once

func initalizeEnforcer() {
	var err error
	permsChecker, err = NewPermissionManager(os.Getenv("ADMIN_DISCORD_ID"), firestoreClient)
	if err != nil {
		log.Fatalf("NewPermissionManager(): %v", err)
	}
}

func optionsToMap(opts []*discordgo.ApplicationCommandInteractionDataOption) map[string]*discordgo.ApplicationCommandInteractionDataOption {
	mappedOpts := make(map[string]*discordgo.ApplicationCommandInteractionDataOption)

	for i := range opts {
		if opts[i] != nil {
			mappedOpts[opts[i].Name] = opts[i]
		}
	}
	return mappedOpts
}

// Check if all expected opts exist
func verifyOpts(opts map[string]*discordgo.ApplicationCommandInteractionDataOption, expected []string) (bool, string) {
	for _, v := range expected {
		if _, ok := opts[v]; !ok {
			return false, v
		}
	}
	return true, ""
}

// Cloud Function Entry
func DiscordFunctionEntry(w http.ResponseWriter, r *http.Request) {
	verified := discordgo.VerifyInteraction(r, ed25519.PublicKey(discordPubkey))
	if !verified {
		log.Printf("Failed signature verification: %v", r.RemoteAddr)
		http.Error(w, "signature mismatch", http.StatusUnauthorized)
		return
	}

	defer r.Body.Close()
	var interaction discordgo.Interaction
	rawInteraction, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error: handleApplicationCommand: ReadAll: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	err = interaction.UnmarshalJSON(rawInteraction)
	if err != nil {
		log.Printf("Error: handleApplicationCommand: jsonDecoder: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}

	switch interaction.Type {
	case discordgo.InteractionPing:
		handlePing(w)
	case discordgo.InteractionApplicationCommand:
		// Initialize permissions enforcer only once
		initEnforcer.Do(initalizeEnforcer)
		handleApplicationCommand(r.Context(), interaction, w, rawInteraction)
	default:
		log.Printf("Error: Unknown Interaction Type: %v", interaction.Type)
		http.Error(w, "Unknown Interaction Type", http.StatusNotImplemented)
	}
}

func handlePing(w http.ResponseWriter) {
	_, err := w.Write([]byte(`{"type":1}`))
	if err != nil {
		log.Printf("Error: Ping: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleApplicationCommand(ctx context.Context, interaction discordgo.Interaction, w http.ResponseWriter, rawInteraction []byte) {
	var response *discordgo.InteractionResponse
	var err error
	var userID string = ""
	var username string = ""
	if interaction.Member != nil {
		userID = interaction.Member.User.ID
		username = interaction.Member.User.Username
	} else if interaction.User != nil {
		userID = interaction.User.ID
		username = interaction.User.Username
	}
	commandData := interaction.ApplicationCommandData()
	command := commandData.Name
	log.Printf("User %v (%v) ran %v", username, userID, command)
	if userID != "" {
		switch command {
		case "server":
			response, err = handleServerGroupCommand(ctx, userID, commandData, rawInteraction)
			if err != nil {
				log.Printf("Error: handleApplicationCommand: handleServerGroupCommand: %v", err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
		case "user":
			response, err = handleUserGroupCommand(ctx, userID, commandData, rawInteraction)
			if err != nil {
				log.Printf("Error: handleApplicationCommand: handleServerGroupCommand: %v", err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
		default:
			response = &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Command `%v` not implemented. Contact an admin", command),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}
		}
	} else {
		response = &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("User not specified in command: %v. Probably my fault", command),
				Flags:   uint64(discordgo.MessageFlagsEphemeral),
			},
		}
	}

	// Return response to discord

	// MUST SET HEADER BEFORE CONTENT
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(*response)
	if err != nil {
		log.Printf("Error: handleApplicationCommand: jsonEncoder: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleServerGroupCommand(ctx context.Context, userID string, data discordgo.ApplicationCommandInteractionData, rawInteraction []byte) (*discordgo.InteractionResponse, error) {
	opts := data.Options
	subcmd := opts[0]
	log.Printf("Subcommand: %v", subcmd.Name)
	switch subcmd.Name {
	case "create":
		args := optionsToMap(subcmd.Options)
		if pass, missing := verifyOpts(args, []string{"name", "subdomain", "machinetype", "ports"}); !pass {
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Arg %v not specified", missing),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
		name := args["name"].StringValue()
		subdomain := args["subdomain"].StringValue()
		machineType := args["machinetype"].StringValue()
		ports := args["ports"].StringValue()
		log.Printf(
			"Server Name: %v\nSubdomain: %v\nMachineType: %v\nPorts: %v",
			name,
			subdomain,
			machineType,
			ports,
		)
		allowed, err := permsChecker.CheckServerOp(userID, name, "create")
		if err != nil {
			return nil, fmt.Errorf("enforce: %v", err)
		}
		if allowed {
			// TODO: validate name, subdomain, machineType, ports
			pubSubData, err := json.Marshal(ForwardPubSub{
				Command:     "create",
				Interaction: &rawInteraction,
			})
			if err != nil {
				return nil, fmt.Errorf("jsonMarshal: %v", err)
			}
			result := commandTopic.Publish(ctx, &pubsub.Message{
				Data: pubSubData,
				Attributes: map[string]string{
					"name":        name,
					"subdomain":   subdomain,
					"machinetype": machineType,
					"ports":       ports,
				},
			})
			_, err = result.Get(ctx)
			if err != nil {
				return nil, fmt.Errorf("Pubsub.Publish: %v", err)
			}
			log.Print("Deferred response")
			_, err = permsChecker.CreateServerPermissions(name)
			if err != nil {
				log.Printf("Failed to create server permissions. You may need to delete the server to clean up.")
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseDeferredChannelMessageWithSource, // Deferred response
					Data: &discordgo.InteractionResponseData{
						Content: "Failed to create server permissions. You may need to delete the server to clean up.",
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseDeferredChannelMessageWithSource, // Deferred response
				Data: &discordgo.InteractionResponseData{
					Content: "Creating server...",
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		} else {
			log.Print("Not authorized")
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Operation not authorized",
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
	case "start", "stop", "delete":
		args := optionsToMap(subcmd.Options)
		if pass, missing := verifyOpts(args, []string{"name"}); !pass {
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Arg %v not specified", missing),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
		name := args["name"].Value.(string)
		log.Printf("Server name: %v", name)
		allowed, err := permsChecker.CheckServerOp(userID, name, subcmd.Name)
		if err != nil {
			return nil, fmt.Errorf("enforce: %v", err)
		}
		if allowed {
			pubSubData, err := json.Marshal(ForwardPubSub{
				Command:     subcmd.Name,
				Interaction: &rawInteraction,
			})
			if err != nil {
				return nil, fmt.Errorf("jsonMarshal: %v", err)
			}
			result := commandTopic.Publish(ctx, &pubsub.Message{
				Data: pubSubData,
				Attributes: map[string]string{
					"name": name,
				},
			})
			_, err = result.Get(ctx)
			if err != nil {
				return nil, fmt.Errorf("Pubsub.Publish: %v", err)
			}
			log.Print("Deferred response")
			if subcmd.Name == "delete" {
				_, err = permsChecker.DeleteServerPermissions(name)
				if err != nil {
					log.Printf("Failed to delete server permissions.")
					return &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseDeferredChannelMessageWithSource, // Deferred response
						Data: &discordgo.InteractionResponseData{
							Content: "Failed to delete server permissions.",
							Flags:   uint64(discordgo.MessageFlagsEphemeral),
						},
					}, nil
				}
			}
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseDeferredChannelMessageWithSource, // Deferred response
				Data: &discordgo.InteractionResponseData{
					Content: "...",
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		} else {
			log.Print("Not authorized")
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content:         "Operation not authorized",
					Flags:           uint64(discordgo.MessageFlagsEphemeral),
					Embeds:          []*discordgo.MessageEmbed{},
					AllowedMentions: &discordgo.MessageAllowedMentions{},
				},
			}, nil
		}
	default:
		log.Printf("Command `%v` not implemented for server.", subcmd.Name)
		return &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("Command `%v` not implemented for server.", subcmd.Name),
				Flags:   uint64(discordgo.MessageFlagsEphemeral),
			},
		}, nil
	}
}

func handleUserGroupCommand(ctx context.Context, userID string, data discordgo.ApplicationCommandInteractionData, rawInteraction []byte) (*discordgo.InteractionResponse, error) {
	opts := data.Options
	subcmd := opts[0]
	log.Printf("Subcommand: %v", subcmd.Name)
	switch subcmd.Name {
	case "add":
		args := optionsToMap(subcmd.Options)
		if pass, missing := verifyOpts(args, []string{"user", "name"}); !pass {
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Arg %v not specified", missing),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
		targetUser := args["user"].UserValue(nil)
		name := args["name"].StringValue()
		if targetUser.ID == "" {
			log.Printf("Target User ID not specified: %v", *targetUser)
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Target User ID not specified"),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
		log.Printf("Add %v to server %v", targetUser, name)
		allowed, err := permsChecker.CheckUserOp(userID, targetUser.ID, "add")
		if err != nil {
			return nil, fmt.Errorf("enforce: %v", err)
		}
		if allowed {
			// TODO: Check existence of server
			success, err := permsChecker.AddUserToServer(targetUser.ID, name)
			if err != nil {
				log.Printf("AddUserToServer: %v", err)
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("Internal error. Oops"),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			if !success {
				log.Printf("User %v already has role for server: %v", targetUser.ID, name)
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("<@%v>, has already been added to server: %v", targetUser.ID, name),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
						AllowedMentions: &discordgo.MessageAllowedMentions{
							Parse: []discordgo.AllowedMentionType{discordgo.AllowedMentionTypeUsers},
							Users: []string{targetUser.ID},
						},
					},
				}, nil
			}
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("<@%v>, has been added to server: %v", targetUser.ID, name),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		} else {
			log.Print("Not authorized")
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content:         "Operation not authorized",
					Flags:           uint64(discordgo.MessageFlagsEphemeral),
					Embeds:          []*discordgo.MessageEmbed{},
					AllowedMentions: &discordgo.MessageAllowedMentions{},
				},
			}, nil
		}
	case "remove":
		args := optionsToMap(subcmd.Options)
		if pass, missing := verifyOpts(args, []string{"user", "name"}); !pass {
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Arg %v not specified", missing),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
		targetUser := args["user"].UserValue(nil)
		name := args["name"].StringValue()
		if targetUser.ID == "" {
			log.Printf("Target User ID not specified: %v", *targetUser)
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Target User ID not specified"),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
		log.Printf("Remove %v from server %v", targetUser, name)
		allowed, err := permsChecker.CheckUserOp(userID, targetUser.ID, "add")
		if err != nil {
			return nil, fmt.Errorf("enforce: %v", err)
		}
		if allowed {
			// TODO: Check existence of server
			success, err := permsChecker.RemoveUserFromServer(targetUser.ID, name)
			if err != nil {
				log.Printf("RemoveUserFromServer: %v", err)
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("Internal error. Oops"),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			if !success {
				log.Printf("User %v has no role for server: %v", targetUser.ID, name)
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("<@%v>, is not in server: %v", targetUser.ID, name),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
						AllowedMentions: &discordgo.MessageAllowedMentions{
							Parse: []discordgo.AllowedMentionType{discordgo.AllowedMentionTypeUsers},
							Users: []string{targetUser.ID},
						},
					},
				}, nil
			}
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("<@%v>, has been removed from server: %v", targetUser.ID, name),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		} else {
			log.Print("Not authorized")
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content:         "Operation not authorized",
					Flags:           uint64(discordgo.MessageFlagsEphemeral),
					Embeds:          []*discordgo.MessageEmbed{},
					AllowedMentions: &discordgo.MessageAllowedMentions{},
				},
			}, nil
		}
	case "perms":
		log.Printf("Command `%v` not implemented for user.", subcmd.Name)
		return &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("Command `%v` not implemented for user.", subcmd.Name),
				Flags:   uint64(discordgo.MessageFlagsEphemeral),
			},
		}, nil
	default:
		log.Printf("Command `%v` not implemented for user.", subcmd.Name)
		return &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("Command `%v` not implemented for user.", subcmd.Name),
				Flags:   uint64(discordgo.MessageFlagsEphemeral),
			},
		}, nil
	}
}

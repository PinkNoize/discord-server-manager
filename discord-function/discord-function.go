package discord_function

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/pubsub"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/bwmarrin/discordgo"
	"github.com/google/uuid"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const CONNECT_TOKEN_LIFE = 15

// Globals
var projectID string = os.Getenv("PROJECT_ID")
var commandTopicID string = os.Getenv("COMMAND_TOPIC")
var rootUserID string = os.Getenv("ADMIN_DISCORD_ID")
var discordPubkey []byte
var discordAppID string = os.Getenv("DISCORD_APPID")
var discordSecretID string = os.Getenv("DISCORD_SECRET_ID")
var keySecretID string = os.Getenv("KEY_SECRET_ID")
var ipFetchURL string = os.Getenv("IP_FETCH_URL")
var logWebhookURL string = os.Getenv("LOG_WEBHOOK_URL")
var logWebhookID string
var logWebhookToken string

var firestoreClient *firestore.Client
var permsChecker *PermissionManager
var commandTopic *pubsub.Topic

type ForwardPubSub struct {
	Command     string  `json:"command"`
	Interaction *[]byte `json:"interaction,omitempty"`
}

var isValidName = regexp.MustCompile(`^[a-zA-Z0-9\-]{2,14}$`).MatchString
var discordSession *discordgo.Session

type LogEntry struct {
	Message  string `json:"message"`
	Severity string `json:"severity,omitempty"`
}

// String renders an entry structure to the JSON format expected by Cloud Logging.
func (e LogEntry) String() string {
	if e.Severity == "" {
		e.Severity = "INFO"
	}
	out, err := json.Marshal(e)
	if err != nil {
		log.Printf("json.Marshal: %v", err)
	}
	return string(out)
}

type UserInfo struct {
	User   *discordgo.User
	Member *discordgo.Member
}

func (ui UserInfo) ID() string {
	if ui.Member != nil {
		return ui.Member.User.ID
	} else if ui.User != nil {
		return ui.User.ID
	} else {
		return ""
	}
}

func (ui UserInfo) DisplayName() string {
	if ui.Member != nil {
		return ui.Member.Nick
	} else if ui.User != nil {
		return fmt.Sprintf("%v%v", ui.User.ID, ui.User.Discriminator)
	} else {
		return ""
	}
}

func init() {
	var err error
	// Disable log prefixes such as the default timestamp.
	// Prefix text prevents the message from being parsed as JSON.
	// A timestamp is added when shipping logs to Cloud Logging.
	log.SetFlags(0)
	ctx := context.Background()
	firestoreClient, err = firestore.NewClient(ctx, projectID)
	if err != nil {
		log.Fatal(LogEntry{
			Message:  fmt.Sprintf("Failed to create firestore client: %v", err),
			Severity: "CRITICAL",
		})
	}
	pubsubClient, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		log.Fatal(LogEntry{
			Message:  fmt.Sprintf("Failed to create pubsub client: %v", err),
			Severity: "CRITICAL",
		})
	}
	commandTopic = pubsubClient.Topic(commandTopicID)
	discordPubkey, err = hex.DecodeString(os.Getenv("DISCORD_PUBKEY"))
	if err != nil {
		log.Fatal(LogEntry{
			Message:  fmt.Sprintf("Failed to decode public key: %v", err),
			Severity: "CRITICAL",
		})
	}
	discordSession, err = discordgo.New("")
	if err != nil {
		log.Fatal(LogEntry{
			Message:  fmt.Sprintf("Error: initDiscord: %v", err),
			Severity: "CRITICAL",
		})
	}
	if len(logWebhookURL) > 0 {
		u, err := url.Parse(logWebhookURL)
		if err != nil {
			log.Print(LogEntry{
				Message:  fmt.Sprintf("Failed to parse logWebhookURL: %v", err),
				Severity: "ERROR",
			})
		} else {
			dir, file := path.Split(u.Path)
			logWebhookToken = file
			dir, file = path.Split(path.Clean(dir))
			logWebhookID = file
		}
	}
}

var initEnforcer sync.Once

func initalizeEnforcer() {
	var err error
	permsChecker, err = NewPermissionManager(os.Getenv("ADMIN_DISCORD_ID"), firestoreClient)
	if err != nil {
		log.Fatal(LogEntry{
			Message:  fmt.Sprintf("NewPermissionManager(): %v", err),
			Severity: "CRITICAL",
		})
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

func logCommandToWebhook(username, command, subcmd string, args map[string]*discordgo.ApplicationCommandInteractionDataOption) error {
	if len(logWebhookURL) < 1 {
		return nil
	}
	log.Print(LogEntry{
		Message:  "Sending command to webhook",
		Severity: "INFO",
	})
	var fields []*discordgo.MessageEmbedField
	fields = append(fields, &discordgo.MessageEmbedField{
		Name:   "Command",
		Value:  command,
		Inline: true,
	})
	fields = append(fields, &discordgo.MessageEmbedField{
		Name:   "Subcommand",
		Value:  subcmd,
		Inline: true,
	})
	for arg, option := range args {
		v := "nil"
		if option != nil {
			v = fmt.Sprintf("%s", option.Value)
		}
		fields = append(fields, &discordgo.MessageEmbedField{
			Name:  arg,
			Value: v,
		})
	}
	data := &discordgo.WebhookParams{
		Embeds: []*discordgo.MessageEmbed{
			{
				Title:  username,
				Type:   discordgo.EmbedTypeRich,
				Fields: fields,
			},
		},
	}
	_, err := discordSession.WebhookExecute(logWebhookID, logWebhookToken, false, data)
	if err != nil {
		return fmt.Errorf("WebhookExecute %v", err)
	}
	return nil
}

// Cloud Function Entry
func DiscordFunctionEntry(w http.ResponseWriter, r *http.Request) {
	verified := discordgo.VerifyInteraction(r, ed25519.PublicKey(discordPubkey))
	if !verified {
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Failed signature verification: %v", r.RemoteAddr),
			Severity: "NOTICE",
		})
		http.Error(w, "signature mismatch", http.StatusUnauthorized)
		return
	}

	defer r.Body.Close()
	var interaction discordgo.Interaction
	rawInteraction, err := io.ReadAll(r.Body)
	if err != nil {
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Error: handleApplicationCommand: ReadAll: %v", err),
			Severity: "ERROR",
		})
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	err = interaction.UnmarshalJSON(rawInteraction)
	if err != nil {
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Error: handleApplicationCommand: jsonDecoder: %v", err),
			Severity: "ERROR",
		})
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
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Unknown Interaction Type: %v", interaction.Type),
			Severity: "ERROR",
		})
		http.Error(w, "Unknown Interaction Type", http.StatusNotImplemented)
	}
	log.Print(LogEntry{
		Message:  "Complete",
		Severity: "INFO",
	}) // maybe flushes logger
}

func handlePing(w http.ResponseWriter) {
	log.Print(LogEntry{
		Message:  "Ping received",
		Severity: "INFO",
	})
	_, err := w.Write([]byte(`{"type":1}`))
	if err != nil {
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Ping: %v", err),
			Severity: "ERROR",
		})
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleApplicationCommand(ctx context.Context, interaction discordgo.Interaction, w http.ResponseWriter, rawInteraction []byte) {
	var response *discordgo.InteractionResponse
	var err error
	var userInfo UserInfo = UserInfo{
		User:   interaction.User,
		Member: interaction.Member,
	}

	commandData := interaction.ApplicationCommandData()
	command := commandData.Name
	log.Print(LogEntry{
		Message:  fmt.Sprintf("User %v (%v) ran %v", userInfo.DisplayName(), userInfo.ID(), command),
		Severity: "INFO",
	})
	if userInfo.ID() != "" {
		switch command {
		case "server":
			response, err = handleServerGroupCommand(ctx, userInfo, commandData, rawInteraction)
			if err != nil {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("handleApplicationCommand: handleServerGroupCommand: %v", err),
					Severity: "ERROR",
				})
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
		case "user":
			response, err = handleUserGroupCommand(ctx, userInfo, commandData, rawInteraction)
			if err != nil {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("Error: handleApplicationCommand: handleUserGroupCommand: %v", err),
					Severity: "ERROR",
				})
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
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Error: handleApplicationCommand: jsonEncoder: %v", err),
			Severity: "ERROR",
		})
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleServerGroupCommand(ctx context.Context, userInfo UserInfo, data discordgo.ApplicationCommandInteractionData, rawInteraction []byte) (*discordgo.InteractionResponse, error) {
	opts := data.Options
	subcmd := opts[0]
	log.Print(LogEntry{
		Message:  fmt.Sprintf("Subcommand: %v", subcmd.Name),
		Severity: "INFO",
	})
	args := optionsToMap(subcmd.Options)
	logCommandToWebhook(fmt.Sprintf("%v (%v)", userInfo.DisplayName(), userInfo.ID()), "server", subcmd.Name, args)
	switch subcmd.Name {
	case "create":
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
		log.Print(LogEntry{
			Message: fmt.Sprintf(
				"Server Name: %v\nSubdomain: %v\nMachineType: %v\nPorts: %v",
				name,
				subdomain,
				machineType,
				ports),
			Severity: "INFO",
		})
		allowed, err := permsChecker.CheckServerOp(userInfo.ID(), name, "create")
		if err != nil {
			return nil, fmt.Errorf("enforce: %v", err)
		}
		if allowed {
			if !isValidName(name) {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("Invalid server name: %v", name),
					Severity: "INFO",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: "Invalid server name. Server names can only contain letters, numbers, and -",
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			if !isValidName(subdomain) {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("Invalid subdomain: %v", subdomain),
					Severity: "INFO",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: "Invalid subdomain. Subdomains can only contain letters, numbers, and -",
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
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
			log.Print(LogEntry{
				Message:  "Deferred response",
				Severity: "INFO",
			})
			_, err = permsChecker.CreateServerPermissions(name)
			if err != nil {
				log.Print(LogEntry{
					Message:  "Failed to create server permissions. You may need to delete the server to clean up.",
					Severity: "ERROR",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseDeferredChannelMessageWithSource, // Deferred response
					Data: &discordgo.InteractionResponseData{
						Content: "Failed to create server permissions. You may need to delete the server to clean up.",
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			// TODO: remove existing role mappings
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseDeferredChannelMessageWithSource, // Deferred response
				Data: &discordgo.InteractionResponseData{
					Content: "Creating server...",
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		} else {
			log.Print(LogEntry{
				Message:  "Not authorized",
				Severity: "INFO",
			})
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Operation not authorized",
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
	case "start", "stop", "delete":
		if pass, missing := verifyOpts(args, []string{"name"}); !pass {
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Arg %v not specified", missing),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
		name := args["name"].StringValue()
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Server name: %v", name),
			Severity: "INFO",
		})
		allowed, err := permsChecker.CheckServerOp(userInfo.ID(), name, subcmd.Name)
		if err != nil {
			return nil, fmt.Errorf("enforce: %v", err)
		}
		if allowed {
			if !serverExists(ctx, name) {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("Server %v does not exist", err),
					Severity: "INFO",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("Server %v does not exist", name),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
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
			log.Print(LogEntry{
				Message:  "Deferred response",
				Severity: "INFO",
			})
			if subcmd.Name == "delete" {
				log.Print(LogEntry{
					Message:  "Deleting permissions",
					Severity: "INFO",
				})
				_, err = permsChecker.DeleteServerPermissions(name)
				if err != nil {
					log.Print(LogEntry{
						Message:  fmt.Sprintf("Failed to delete server permissions: %v", err),
						Severity: "ERROR",
					})
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
			log.Print(LogEntry{
				Message:  "Not authorized",
				Severity: "INFO",
			})
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
	case "connect":
		if pass, missing := verifyOpts(args, []string{"name"}); !pass {
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Arg %v not specified", missing),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
		name := args["name"].StringValue()
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Server name: %v", name),
			Severity: "INFO",
		})
		// Can connect if have start permissions
		allowed, err := permsChecker.CheckServerOp(userInfo.ID(), name, "start")
		if err != nil {
			return nil, fmt.Errorf("enforce: %v", err)
		}
		if allowed {
			if !serverExists(ctx, name) {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("Server %v does not exist", err),
					Severity: "INFO",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("Server %v does not exist", name),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			connectUrl, err := generateConnectUrl(ctx, userInfo.ID(), name)
			if err != nil {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("generateConnectUrl: %v", err),
					Severity: "ERROR",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: "Internal Server Error",
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Embeds: []*discordgo.MessageEmbed{
						{
							URL:   connectUrl,
							Title: fmt.Sprintf("Connect to %v", name),
						},
					},
					Flags: uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		} else {
			log.Print(LogEntry{
				Message:  "Not authorized",
				Severity: "INFO",
			})
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
	case "status":
		nameIface, ok := args["name"]
		var servers []string
		if !ok {
			log.Print(LogEntry{
				Message:  "User requested the status for all servers",
				Severity: "INFO",
			})
			// Return results for all valid servers
			servers = permsChecker.GetServersForUser(userInfo.ID())
			if len(servers) < 1 {
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Embeds: []*discordgo.MessageEmbed{
							{
								Type:        discordgo.EmbedTypeImage,
								Description: "You do not have access to any servers.",
								Image: &discordgo.MessageEmbedImage{
									URL: "https://cdn.discordapp.com/attachments/561082316689244162/964590315501666374/unknown.png",
								},
							},
						},
						Flags: uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
		} else {
			// Check if user has permission to access the server
			log.Print(LogEntry{
				Message:  fmt.Sprintf("%v requested the status for %v", userInfo.ID(), nameIface.StringValue()),
				Severity: "INFO",
			})
			allowed, err := permsChecker.CheckServerOp(userInfo.ID(), nameIface.StringValue(), "start")
			if err != nil {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("CheckServerOp: %v", err),
					Severity: "ERROR",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: "Internal Server Error",
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			if !allowed {
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Embeds: []*discordgo.MessageEmbed{
							{
								Type:        discordgo.EmbedTypeImage,
								Description: fmt.Sprintf("You do not have access to `%v` or it does not exist", nameIface.StringValue()),
								Image: &discordgo.MessageEmbedImage{
									URL: "https://cdn.discordapp.com/attachments/561082316689244162/964590315501666374/unknown.png",
								},
							},
						},
						Flags: uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			} else {
				servers = append(servers, nameIface.StringValue())
			}
		}
		// Forward to command lambda
		pubSubData, err := json.Marshal(ForwardPubSub{
			Command:     "status",
			Interaction: &rawInteraction,
		})
		if err != nil {
			return nil, fmt.Errorf("jsonMarshal: %v", err)
		}
		serverCSV := strings.Join(servers, ",")
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Requesting status for %v", serverCSV),
			Severity: "INFO",
		})
		result := commandTopic.Publish(ctx, &pubsub.Message{
			Data: pubSubData,
			Attributes: map[string]string{
				"servers": serverCSV,
			},
		})
		_, err = result.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("Pubsub.Publish: %v", err)
		}
		log.Print(LogEntry{
			Message:  "Deferred response",
			Severity: "INFO",
		})
		return &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseDeferredChannelMessageWithSource, // Deferred response
			Data: &discordgo.InteractionResponseData{
				Content: "...",
				Flags:   uint64(discordgo.MessageFlagsEphemeral),
			},
		}, nil
	default:
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Command `%v` not implemented for server.", subcmd.Name),
			Severity: "WARNING",
		})
		return &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("Command `%v` not implemented for server.", subcmd.Name),
				Flags:   uint64(discordgo.MessageFlagsEphemeral),
			},
		}, nil
	}
}

func handleUserGroupCommand(ctx context.Context, userInfo UserInfo, data discordgo.ApplicationCommandInteractionData, rawInteraction []byte) (*discordgo.InteractionResponse, error) {
	opts := data.Options
	subcmd := opts[0]
	log.Print(LogEntry{
		Message:  fmt.Sprintf("Subcommand: %v", subcmd.Name),
		Severity: "INFO",
	})
	args := optionsToMap(subcmd.Options)
	logCommandToWebhook(fmt.Sprintf("%v (%v)", userInfo.DisplayName(), userInfo.ID()), "user", subcmd.Name, args)
	switch subcmd.Name {
	case "add":
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
			log.Print(LogEntry{
				Message:  fmt.Sprintf("Target User ID not specified: %v", *targetUser),
				Severity: "INFO",
			})
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Target User ID not specified"),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Add %v to server %v", targetUser, name),
			Severity: "INFO",
		})
		allowed, err := permsChecker.CheckUserOp(userInfo.ID(), targetUser.ID, "add")
		if err != nil {
			return nil, fmt.Errorf("enforce: %v", err)
		}
		if allowed {
			if !serverExists(ctx, name) {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("Server %v does not exist", name),
					Severity: "INFO",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("Server %v does not exist", name),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			success, err := permsChecker.AddUserToServer(targetUser.ID, name)
			if err != nil {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("AddUserToServer: %v", err),
					Severity: "ERROR",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("Internal error. Oops"),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			if !success {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("User %v already has role for server: %v", targetUser.ID, name),
					Severity: "INFO",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("<@%v>, has already been added to server: %v", targetUser.ID, name),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
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
			log.Print(LogEntry{
				Message:  "Not authorized",
				Severity: "INFO",
			})
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Operation not authorized",
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
					Embeds:  []*discordgo.MessageEmbed{},
				},
			}, nil
		}
	case "remove":
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
			log.Print(LogEntry{
				Message:  fmt.Sprintf("Target User ID not specified: %v", *targetUser),
				Severity: "INFO",
			})
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Target User ID not specified"),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Remove %v from server %v", targetUser, name),
			Severity: "INFO",
		})
		allowed, err := permsChecker.CheckUserOp(userInfo.ID(), targetUser.ID, "add")
		if err != nil {
			return nil, fmt.Errorf("enforce: %v", err)
		}
		if allowed {
			if !serverExists(ctx, name) {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("Server %v does not exist", name),
					Severity: "INFO",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("Server %v does not exist", name),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			success, err := permsChecker.RemoveUserFromServer(targetUser.ID, name)
			if err != nil {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("RemoveUserFromServer: %v", err),
					Severity: "ERROR",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("Internal error. Oops"),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			if !success {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("User %v has no role for server: %v", targetUser.ID, name),
					Severity: "WARNING",
				})
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("<@%v>, is not in server: %v", targetUser.ID, name),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
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
			log.Print(LogEntry{
				Message:  "Not authorized",
				Severity: "INFO",
			})
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
		if pass, missing := verifyOpts(args, []string{"user"}); !pass {
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Arg %v not specified", missing),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
		targetUser := args["user"].UserValue(nil)
		if targetUser.ID == "" {
			log.Print(LogEntry{
				Message:  fmt.Sprintf("Target User ID not specified: %v", *targetUser),
				Severity: "INFO",
			})
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Target User ID not specified"),
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		}
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Get perms for %v", targetUser),
			Severity: "INFO",
		})
		allowed, err := permsChecker.CheckUserOp(userInfo.ID(), targetUser.ID, "perms")
		if err != nil {
			return nil, fmt.Errorf("enforce: %v", err)
		}
		if allowed {
			// TODO
			serverRoles := permsChecker.GetServersForUser(targetUser.ID)
			if len(serverRoles) < 1 {
				return &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("<@%v> has no servers", targetUser.ID),
						Flags:   uint64(discordgo.MessageFlagsEphemeral),
					},
				}, nil
			}
			serverString := strings.Join(serverRoles, "\n")
			var embeds []*discordgo.MessageEmbed
			embeds = append(embeds, &discordgo.MessageEmbed{
				Title: fmt.Sprintf("%v%v", targetUser.Username, targetUser.Discriminator),
				Type:  discordgo.EmbedTypeRich,
				Fields: []*discordgo.MessageEmbedField{
					{
						Name:  "Servers",
						Value: serverString,
					},
				},
			})
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Embeds: embeds,
					Flags:  uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		} else {
			log.Print(LogEntry{
				Message:  "Not authorized",
				Severity: "INFO",
			})
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
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Command `%v` not implemented for user.", subcmd.Name),
			Severity: "INFO",
		})
		return &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("Command `%v` not implemented for user.", subcmd.Name),
				Flags:   uint64(discordgo.MessageFlagsEphemeral),
			},
		}, nil
	}
}

func serverExists(ctx context.Context, name string) bool {
	serverDoc, err := firestoreClient.Collection("Servers").Doc(name).Get(ctx)
	if err != nil {
		if status.Code(err) != codes.NotFound {
			log.Print(LogEntry{
				Message:  fmt.Sprintf("serverExists: Get: %v", err),
				Severity: "ERROR",
			})
		}
		return false
	}
	return serverDoc.Exists()
}

type Token struct {
	Expiration time.Time `json:"expiration" firestore:"expiration"`
	Id         string    `json:"id" firestore:"id"`
	User       string    `json:"user" firestore:"user"`
	ServerName string    `json:"name" firestore:"name"`
}

var initAESKeyOnce sync.Once
var aesGCM cipher.AEAD

func initAESKey() {
	var err error
	ctx := context.TODO()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatal(LogEntry{
			Message:  fmt.Sprintf("init: NewClient: %v", err),
			Severity: "ERROR",
		})
	}
	defer client.Close()
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("%v/versions/latest", keySecretID),
	}
	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		log.Fatal(LogEntry{
			Message:  fmt.Sprintf("init: AccessSecretVersion: %v", err),
			Severity: "ERROR",
		})
	}
	key := result.Payload.Data

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(LogEntry{
			Message:  fmt.Sprintf("init: NewCipher: %v", err),
			Severity: "CRITICAL",
		})
	}

	aesGCM, err = cipher.NewGCM(block)
	if err != nil {
		log.Panic(LogEntry{
			Message:  fmt.Sprintf("init: NewGCM: %v", err),
			Severity: "CRITICAL",
		})
	}
}

func generateConnectUrl(ctx context.Context, user, name string) (string, error) {
	// Get key first as this can fail
	initAESKeyOnce.Do(initAESKey)
	// Generate Token
	newToken := Token{
		Expiration: time.Now().UTC().Add(15 * time.Minute),
		Id:         uuid.New().String(),
		User:       user,
		ServerName: name,
	}
	// Submit into database
	tokenDoc := firestoreClient.Collection("Tokens").Doc(newToken.Id)
	_, err := tokenDoc.Create(
		ctx,
		newToken,
	)
	if err != nil {
		return "", err
	}
	// Use to delete in case of error
	tokenDocUndo := func() {
		log.Print(LogEntry{
			Message:  fmt.Sprintf("Undo doc creation of %v", newToken.Id),
			Severity: "NOTICE",
		})
		if _, err = tokenDoc.Delete(ctx); err != nil {
			log.Print(LogEntry{
				Message:  fmt.Sprintf("Failed to delete document %v in Tokens", newToken.Id),
				Severity: "ERROR",
			})
		}
	}
	log.Print(LogEntry{
		Message:  fmt.Sprintf("Inserted token %v into Collection Tokens", newToken.Id),
		Severity: "INFO",
	})
	// Encrypt Token
	rawToken, err := json.Marshal(newToken)
	if err != nil {
		defer tokenDocUndo()
		return "", fmt.Errorf("Marshal: %v", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		defer tokenDocUndo()
		return "", fmt.Errorf("ReadFull(rand.Reader): %v", err)
	}
	ciphertext := aesGCM.Seal(nil, nonce, rawToken, nil)
	token := base64.URLEncoding.EncodeToString(append(nonce, ciphertext...))
	// Create URL
	url := fmt.Sprintf("%v?preview=true&tokenid=%v", ipFetchURL, url.QueryEscape(token))
	return url, nil
}

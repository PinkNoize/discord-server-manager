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
	"strings"
	"sync"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/pubsub"
	"github.com/bwmarrin/discordgo"
	casbin "github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	casfs "github.com/reedom/casbin-firestore-adapter"
)

// Globals
var projectID string = os.Getenv("PROJECT_ID")
var commandTopicID string = os.Getenv("COMMAND_TOPIC")
var rootUserID string = os.Getenv("ADMIN_DISCORD_ID")
var discordPubkey []byte
var discordAppID string = os.Getenv("DISCORD_APPID")
var discordSecretID string = os.Getenv("DISCORD_SECRET_ID")

var firestoreClient *firestore.Client
var enforcer *casbin.CachedEnforcer
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
	modelString := `[request_definition]
r = sub, dom, act

[policy_definition]
p = sub, dom, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.act == p.act`
	if rootUserID == "" {
		modelString = fmt.Sprintf(`[request_definition]
r = sub, dom, act

[policy_definition]
p = sub, dom, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.act == p.act || r.sub == "%v"`, rootUserID)
	}

	model, err := model.NewModelFromString(modelString)
	if err != nil {
		log.Fatalf("Error: NewModelFromString: %v", err)
	}
	adapter := casfs.NewAdapter(firestoreClient)
	enf, err := casbin.NewCachedEnforcer()
	if err != nil {
		log.Fatalf("Error: NewEnforcer: %v", err)
	}
	err = enf.InitWithModelAndAdapter(model, adapter)
	if err != nil {
		log.Fatalf("Error: NewEnforcer: %v", err)
	}
	enforcer = enf
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

func checkUserAllowed(user string, obj string, action string) (bool, error) {
	if strings.HasSuffix(user, "_role") {
		return false, fmt.Errorf("checkUserAllowed: Invalid User name: %v", user)
	}
	allowed, err := enforcer.Enforce(user, obj, action)
	if err != nil {
		return false, fmt.Errorf("checkUserAllowed: %v", err)
	}
	return allowed, err
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

	w.Header().Set("Content-Type", "application/json")
	resp, err := json.Marshal(*response)
	//err = json.NewEncoder(w).Encode(*response)
	if err != nil {
		log.Printf("Error: handleApplicationCommand: jsonEncoder: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	//DEBUG
	resp = []byte(`{"type": 4, "data": {"tts": false, "content": "Congrats on sending your command!", "embeds": [], "allowed_mentions": { "parse": [] }}}`)
	log.Printf("Response: %v", string(resp))
	_, err = w.Write(resp)
	if err != nil {
		log.Fatalf("Error: handleApplicationCommand: Write: %v", err)
	}
	log.Printf("Content Type: %v", w.Header().Get("Content-Type"))
}

func handleServerGroupCommand(ctx context.Context, userID string, data discordgo.ApplicationCommandInteractionData, rawInteraction []byte) (*discordgo.InteractionResponse, error) {
	opts := data.Options
	subcmd := opts[0]
	log.Printf("Subcommand: %v", subcmd.Name)
	switch subcmd.Name {
	case "create":
		args := optionsToMap(subcmd.Options)
		if pass, missing := verifyOpts(args, []string{"name", "subdomain", "machineType", "ports"}); !pass {
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
		machineType := args["machineType"].StringValue()
		ports := args["ports"].StringValue()
		allowed, err := checkUserAllowed(userID, name, "create")
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
					"machineType": machineType,
					"ports":       ports,
				},
			})
			_, err = result.Get(ctx)
			if err != nil {
				return nil, fmt.Errorf("Pubsub.Publish: %v", err)
			}
			return &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseDeferredChannelMessageWithSource, // Deferred response
				Data: &discordgo.InteractionResponseData{
					Content: "Creating server...",
					Flags:   uint64(discordgo.MessageFlagsEphemeral),
				},
			}, nil
		} else {
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
		allowed, err := checkUserAllowed(userID, name, subcmd.Name)
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
			log.Printf("Deferred response")
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

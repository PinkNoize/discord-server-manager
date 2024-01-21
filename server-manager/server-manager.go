package server_manager

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/bwmarrin/discordgo"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	iam "google.golang.org/api/iam/v1"
)

type LogEntry struct {
	Message  string `json:"message"`
	Severity string `json:"severity,omitempty"`
}

// Globals
var projectID string = os.Getenv("PROJECT_ID")
var projectRegion string = os.Getenv("PROJECT_REGION")
var projectZone string = os.Getenv("PROJECT_ZONE")
var dnsProjectID string = os.Getenv("DNS_PROJECT_ID")
var dnsZone string = os.Getenv("DNS_MANAGED_ZONE")
var baseDomain string = os.Getenv("BASE_DOMAIN")
var snapshotTopicID string = os.Getenv("SNAPSHOT_TOPIC")
var discordAppID string = os.Getenv("DISCORD_APPID")
var discordSecretID string = os.Getenv("DISCORD_SECRET_ID")
var discordAPIToken string

var firestoreClient *firestore.Client
var storageClient *storage.Client
var iamService *iam.Service
var cloudresourcemanagerService *cloudresourcemanager.Service
var computeClient *compute.Service
var dnsClient *dns.Service
var rrClient *dns.ResourceRecordSetsService
var discordSession *discordgo.Session
var httpClient http.Client = http.Client{Timeout: time.Second * 5}
var snapshotTopic *pubsub.Topic

var initDiscordSession sync.Once

func init() {
	var err error
	ctx := context.Background()
	computeClient, err = compute.NewService(ctx)
	if err != nil {
		log.Fatalf("Failed to create compute client: %v", err)
	}
	firestoreClient, err = firestore.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("Failed to create firestore client: %v", err)
	}
	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create storage client: %v", err)
	}
	iamService, err = iam.NewService(ctx)
	if err != nil {
		log.Fatalf("Failed to create iam service: %v", err)
	}
	cloudresourcemanagerService, err = cloudresourcemanager.NewService(ctx)
	if err != nil {
		log.Fatalf("cloudresourcemanager.NewService: %v", err)
	}
	dnsClient, err = dns.NewService(ctx)
	if err != nil {
		log.Fatalf("Failed to create dns client: %v", err)
	}
	rrClient = dns.NewResourceRecordSetsService(dnsClient)

	pubsubClient, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		log.Fatal(LogEntry{
			Message:  fmt.Sprintf("Failed to create pubsub client: %v", err),
			Severity: "CRITICAL",
		})
	}
	snapshotTopic = pubsubClient.Topic(snapshotTopicID)
}

func initDiscord(ctx context.Context) {
	var err error
	// client, err := secretmanager.NewClient(ctx)
	// if err != nil {
	// 	log.Fatalf("Error: initDiscord: NewClient: %v", err)
	// }
	// defer client.Close()
	// req := &secretmanagerpb.AccessSecretVersionRequest{
	// 	Name: fmt.Sprintf("%v/versions/latest", discordSecretID),
	// }
	// result, err := client.AccessSecretVersion(ctx, req)
	// if err != nil {
	// 	log.Fatalf("Error: initDiscord: AccessSecretVersion: %v", err)
	// }
	// discordAPIToken = string(result.Payload.Data)
	discordSession, err = discordgo.New("")
	if err != nil {
		log.Fatalf("Error: initDiscord: %v", err)
	}
}

// Cloud Function Code

// PubSubMessage is the payload of a Pub/Sub event.
// See the documentation for more details:
// https://cloud.google.com/pubsub/docs/reference/rest/v1/PubsubMessage
type PubSubMessage struct {
	Data       []byte          `json:"data"`
	Attributes json.RawMessage `json:"attributes"`
}

type ForwardPubSub struct {
	Command     string  `json:"command"`
	Interaction *[]byte `json:"interaction,omitempty"`
}

type createServerArgs struct {
	Name        *string `json:"name"`
	Subdomain   *string `json:"subdomain"`
	MachineType *string `json:"machinetype"`
	Purpose     *string `json:"purpose"`
	Ports       *string `json:"ports"`
	OS          *string `json:"os"`
	DiskSize    *string `json:"disksize"`
}
type deleteServerArgs struct {
	Name *string `json:"name"`
}
type startServerArgs struct {
	Name *string `json:"name"`
}
type stopServerArgs struct {
	Name *string `json:"name"`
}
type addUserIPArgs struct {
	Name *string `json:"name"`
	IP   *string `json:"ip"`
	User *string `json:"user"`
}
type statusArgs struct {
	Servers *string `json:"servers"`
}

type addSSHKeyArgs struct {
	Name   *string `json:"name"`
	User   *string `json:"user"`
	SSHKey *string `json:"sshkey"`
}

type clearSSHKeyArgs struct {
	Name *string `json:"name"`
}

func SendDiscordInteractionResponse(token string, response *discordgo.WebhookParams) error {
	log.Print("Sending Interaction response")
	_, err := discordSession.FollowupMessageCreate(
		discordAppID,
		&discordgo.Interaction{
			Token: token,
		},
		true,
		response,
	)
	if err != nil {
		return fmt.Errorf("SendDiscordInteractionResponse: FollowupMessageCreate %v", err)
	}
	return nil
}

// Handles server commands.
func CommandPubSub(ctx context.Context, m PubSubMessage) error {
	var forwardedData ForwardPubSub
	if err := json.Unmarshal([]byte(m.Data), &forwardedData); err != nil {
		log.Fatalf("Failed to unmarshal forwardedData: %v", err)
	}
	command := forwardedData.Command
	originalInteraction := forwardedData.Interaction
	response := discordgo.WebhookParams{
		Content: "Internal Error",
		Flags:   uint64(discordgo.MessageFlagsEphemeral),
	}
	defer func() {
		if originalInteraction != nil {
			initDiscordSession.Do(func() { initDiscord(ctx) })
			interaction := discordgo.Interaction{}
			err := interaction.UnmarshalJSON(*originalInteraction)
			if err != nil {
				log.Printf("Error: InteractionUnmarshal: %v", err)
				return
			}
			err = SendDiscordInteractionResponse(interaction.Token, &response)
			if err != nil {
				log.Printf("Error: InteractionRespond: %v", err)
				return
			}
		}
	}()
	log.Printf("Command: %v", command)
	switch command {
	case "create":
		args := createServerArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Invalid args to command: %v",
				command,
			)
			return fmt.Errorf("error parsing CreateServerArgs: %v", err)
		}
		server, err := commandCreateServer(ctx, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Failed to create server: %v",
				err,
			)
			return fmt.Errorf("CreateServer failed: %v", err)
		}
		response.Content = fmt.Sprintf(
			"Created %v (%v). The server will need a restart to use the domain name.",
			server.Name,
			server.DnsName(),
		)
	case "delete":
		args := deleteServerArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Invalid args to command: %v",
				command,
			)
			return fmt.Errorf("error parsing DeleteServerArgs: %v", err)
		}
		err = commandDeleteServer(ctx, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Failed to delete server: %v",
				err,
			)
			return fmt.Errorf("DeleteServer failed: %v", err)
		}
		response.Content = fmt.Sprintf(
			"Server %v deleted.",
			*args.Name,
		)
	case "start":
		args := startServerArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Invalid args to command: %v",
				command,
			)
			return fmt.Errorf("error parsing startServerArgs: %v", err)
		}
		err = commandStartServer(ctx, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Failed to start server: %v",
				err,
			)
			return fmt.Errorf("start Server failed: %v", err)
		}
		response.Content = fmt.Sprintf(
			"Server %v started.",
			*args.Name,
		)
	case "stop":
		args := stopServerArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Invalid args to command: %v",
				command,
			)
			return fmt.Errorf("error parsing stopServerArgs: %v", err)
		}
		err = commandStopServer(ctx, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Failed to stop server: %v",
				err,
			)
			return fmt.Errorf("stop Server failed: %v", err)
		}
		response.Content = fmt.Sprintf(
			"Server %v stopped.",
			*args.Name,
		)
	case "add-user-ip":
		args := addUserIPArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Invalid args to command: %v",
				command,
			)
			return fmt.Errorf("error parsing addUserIPArgs: %v", err)
		}
		err = commandAddUserIP(ctx, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Failed to add IP: %v",
				err,
			)
			return fmt.Errorf("AddUserIP failed: %v", err)
		}
		response.Content = fmt.Sprintf(
			"Added %v to %v.",
			args.IP,
			args.Name,
		)
	case "status":
		args := statusArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Invalid args to command: %v",
				command,
			)
			return fmt.Errorf("error parsing statusArgs: %v", err)
		}
		embeds, err := commandStatus(ctx, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Failed to get status: %v",
				err,
			)
			return fmt.Errorf("status failed: %v", err)
		}
		response.Content = ""
		response.Embeds = embeds
	case "addsshkey":
		args := addSSHKeyArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Invalid args to command: %v",
				command,
			)
			return fmt.Errorf("error parsing addSSHKeyArgs: %v", err)
		}
		err = commandAddSSHKeyIP(ctx, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Failed to add SSH key: %v",
				err,
			)
			return fmt.Errorf("AddSSHKey failed: %v", err)
		}
		response.Content = fmt.Sprintf(
			"Added sshkey %v to %v.",
			args.SSHKey,
			args.Name,
		)
	case "clearsshkeys":
		args := clearSSHKeyArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Invalid args to command: %v",
				command,
			)
			return fmt.Errorf("error parsing clearSSHKeyArgs: %v", err)
		}
		err = commandClearSSHKey(ctx, &args)
		if err != nil {
			response.Content = fmt.Sprintf(
				"Failed to clear sshkey: %v",
				err,
			)
			return fmt.Errorf("clearsshkey failed: %v", err)
		}
		response.Content = fmt.Sprintf(
			"SSH keys cleared for server %v",
			*args.Name,
		)
	default:
		response.Content = fmt.Sprintf(
			"Command not recognized: %v",
			command,
		)
		return fmt.Errorf("command %v not recognized", command)
	}
	return nil
}

func commandCreateServer(ctx context.Context, args *createServerArgs) (*server, error) {
	if args.Name == nil {
		return nil, fmt.Errorf("name not specified")
	}
	if args.Subdomain == nil {
		return nil, fmt.Errorf("subdomain not specified")
	}
	if args.MachineType == nil {
		return nil, fmt.Errorf("machineType not specified")
	}
	if args.Purpose == nil {
		return nil, fmt.Errorf("purpose not specified")
	}
	if args.Ports == nil {
		return nil, fmt.Errorf("ports not specified")
	}
	ports := []uint16{}
	for _, port := range strings.Fields(*args.Ports) {
		tmp, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parse port failed: %v", err)
		}
		ports = append(ports, uint16(tmp))
	}
	disksize, err := strconv.ParseInt(*args.DiskSize, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parseuint: %v", err)
	}
	log.Printf("Creating %v (%v) - %v", *args.Name, *args.MachineType, *args.Subdomain)
	return CreateServer(
		ctx,
		*args.Name,
		*args.Subdomain,
		*args.MachineType,
		*args.Purpose,
		*args.OS,
		ports,
		disksize,
	)
}

func commandDeleteServer(ctx context.Context, args *deleteServerArgs) error {
	if args.Name == nil {
		return fmt.Errorf("name not specified")
	}
	server, err := ServerFromName(ctx, *args.Name)
	if err != nil {
		return fmt.Errorf("serverFromName failed: %v", err)
	}
	// Check if the server has been stopped to make sure DNS record is gone
	stopped, err := server.IsStopped(ctx)
	if err != nil {
		return err
	} else if !stopped {
		return fmt.Errorf("server %v must be stopped first", *args.Name)
	}
	return server.Delete(ctx)
}

func commandStartServer(ctx context.Context, args *startServerArgs) error {
	if args.Name == nil {
		return fmt.Errorf("name not specified")
	}
	server, err := ServerFromName(ctx, *args.Name)
	if err != nil {
		return fmt.Errorf("serverFromName failed: %v", err)
	}
	// Check if the server is already running
	running, err := server.IsRunning(ctx)
	if err != nil {
		return fmt.Errorf("failed to get %v status: %v", *args.Name, err)
	}
	if running {
		return fmt.Errorf("server %v already running", *args.Name)
	}
	err = server.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start server %v: %v", *args.Name, err)
	}
	// Wait for server to have an IP
	for i := 0; i < 20; i++ {
		_, err := server.ServerIP(ctx)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	err = server.CreateDNSRecord(ctx)
	if err != nil {
		return fmt.Errorf("failed to create DNS record: %v", err)
	}
	return err
}

func commandStopServer(ctx context.Context, args *stopServerArgs) error {
	if args.Name == nil {
		return fmt.Errorf("name not specified")
	}
	server, err := ServerFromName(ctx, *args.Name)
	if err != nil {
		return fmt.Errorf("serverFromName failed: %v", err)
	}
	// Check if the server is already stopped
	running, err := server.IsStopped(ctx)
	if err != nil {
		return fmt.Errorf("failed to get %v status: %v", *args.Name, err)
	}
	if running {
		return fmt.Errorf("server %v already stopped", *args.Name)
	}
	// Delete DNS Record
	err = server.DeleteDNSRecord(ctx)
	if err != nil {
		fmt.Printf("Failed to delete DNS record %v: %v", server.DnsName(), err)
	}
	// Stop Server
	return server.Stop(ctx)
}

func commandAddUserIP(ctx context.Context, args *addUserIPArgs) error {
	if args.Name == nil {
		return fmt.Errorf("name not specified")
	}
	if args.IP == nil {
		return fmt.Errorf("ip not specified")
	}
	if args.User == nil {
		return fmt.Errorf("user not specified")
	}
	server, err := ServerFromName(ctx, *args.Name)
	if err != nil {
		return fmt.Errorf("serverFromName failed: %v", err)
	}
	log.Printf("Adding %s to %s as %s", *args.IP, *args.Name, *args.User)
	err = server.AddUserIP(ctx, *args.User, *args.IP)
	if err != nil {
		return fmt.Errorf("failed AddUserIP: %v", err)
	}
	return nil
}

func commandStatus(ctx context.Context, args *statusArgs) ([]*discordgo.MessageEmbed, error) {
	if args.Servers == nil {
		return nil, fmt.Errorf("server not specified")
	}
	serversList := strings.Split(*args.Servers, ",")
	if len(serversList) < 1 {
		return nil, fmt.Errorf("no servers specified")
	}
	sort.Strings(serversList)
	servers := make(map[string]*server)
	for i := range serversList {
		s, err := ServerFromName(ctx, serversList[i])
		if err != nil {
			log.Printf("error: commandStatus: ServerFromName: %v", err)
			servers[serversList[i]] = nil
		} else {
			servers[serversList[i]] = s
		}
	}
	var embeds []*discordgo.MessageEmbed
	for _, key := range serversList {
		serverInfo := servers[key]
		if serverInfo == nil {
			embeds = append(embeds, &discordgo.MessageEmbed{
				Title:       key,
				Type:        discordgo.EmbedTypeRich,
				Description: "Unable to get status",
			})
		} else {
			var statusString string
			var domainString string

			status, err := serverInfo.GetStatus(ctx)
			if err != nil {
				log.Printf("error: commandStatus: Status: %v", err)
				statusString = "Unable to get status"
			} else {
				statusString = status.String()
			}
			domainString = serverInfo.DnsName()

			embeds = append(embeds, &discordgo.MessageEmbed{
				Title: key,
				Type:  discordgo.EmbedTypeRich,
				Fields: []*discordgo.MessageEmbedField{
					{
						Name:  "Status",
						Value: statusString,
					},
					{
						Name:  "Domain",
						Value: domainString,
					},
				},
			})
		}
	}
	return embeds, nil
}

func commandAddSSHKeyIP(ctx context.Context, args *addSSHKeyArgs) error {
	if args.Name == nil {
		return fmt.Errorf("name not specified")
	}
	if args.SSHKey == nil {
		return fmt.Errorf("sshkey not specified")
	}
	if args.User == nil {
		return fmt.Errorf("user not specified")
	}
	server, err := ServerFromName(ctx, *args.Name)
	if err != nil {
		return fmt.Errorf("serverFromName failed: %v", err)
	}
	log.Print(LogEntry{
		Message: fmt.Sprintf("Adding sshkey %s to %s as %s", *args.SSHKey, *args.Name, *args.User),
	})
	err = server.AddSSHKey(ctx, *args.User, *args.SSHKey)
	if err != nil {
		return fmt.Errorf("failed AddSSHkey: %v", err)
	}
	return nil
}

func commandClearSSHKey(ctx context.Context, args *clearSSHKeyArgs) error {
	if args.Name == nil {
		return fmt.Errorf("name not specified")
	}
	server, err := ServerFromName(ctx, *args.Name)
	if err != nil {
		return fmt.Errorf("serverFromName failed: %v", err)
	}
	err = server.ClearSSHKeys(ctx)
	if err != nil {
		return fmt.Errorf("clearSSHKeys: %v", err)
	}
	return nil
}

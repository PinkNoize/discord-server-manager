package server_manager

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
)

// Globals
var projectID string = os.Getenv("PROJECT_ID")
var projectZone string = os.Getenv("PROJECT_ZONE")
var dnsProjectID string = os.Getenv("DNS_PROJECT_ID")
var dnsZone string = os.Getenv("DNS_MANAGED_ZONE")
var baseDomain string = os.Getenv("BASE_DOMAIN")

var firestoreClient *firestore.Client
var computeClient *compute.Service
var dnsClient *dns.Service
var rrClient *dns.ResourceRecordSetsService

func init() {
	// My linter won't fuck off so I have to declare err
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
	dnsClient, err = dns.NewService(ctx)
	if err != nil {
		log.Fatalf("Failed to create dns client: %v", err)
	}
	rrClient = dns.NewResourceRecordSetsService(dnsClient)
}

// Cloud Function Code

// PubSubMessage is the payload of a Pub/Sub event.
// See the documentation for more details:
// https://cloud.google.com/pubsub/docs/reference/rest/v1/PubsubMessage
type PubSubMessage struct {
	Data       []byte          `json:"data"`
	Attributes json.RawMessage `json:"attributes"`
}

type createServerArgs struct {
	Name        *string `json:"name"`
	Subdomain   *string `json:"subdomain"`
	MachineType *string `json:"machineType"`
	Ports       *string `json:"ports"`
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

// Handles server commands.
func CommandPubSub(ctx context.Context, m PubSubMessage) error {
	command := string(m.Data) // Automatically decoded from base64.
	log.Println(command)
	switch command {
	case "create":
		args := createServerArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			return fmt.Errorf("error parsing CreateServerArgs: %v", err)
		}
		_, err = commandCreateServer(ctx, &args)
		if err != nil {
			return fmt.Errorf("CreateServer failed: %v", err)
		}
	case "delete":
		args := deleteServerArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			return fmt.Errorf("error parsing DeleteServerArgs: %v", err)
		}
		err = commandDeleteServer(ctx, &args)
		if err != nil {
			return fmt.Errorf("DeleteServer failed: %v", err)
		}
	case "start":
		args := startServerArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			return fmt.Errorf("error parsing startServerArgs: %v", err)
		}
		err = commandStartServer(ctx, &args)
		if err != nil {
			return fmt.Errorf("start Server failed: %v", err)
		}
	case "stop":
		args := stopServerArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			return fmt.Errorf("error parsing stopServerArgs: %v", err)
		}
		err = commandStopServer(ctx, &args)
		if err != nil {
			return fmt.Errorf("stop Server failed: %v", err)
		}
	case "add-user-ip":
		args := addUserIPArgs{}
		err := json.Unmarshal(m.Attributes, &args)
		if err != nil {
			return fmt.Errorf("error parsing addUserIPArgs: %v", err)
		}
		err = commandAddUserIP(ctx, &args)
		if err != nil {
			return fmt.Errorf("AddUserIP failed: %v", err)
		}
	default:
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
	return CreateServer(
		ctx,
		*args.Name,
		*args.Subdomain,
		*args.MachineType,
		ports,
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
		return fmt.Errorf("server %v must be stopped first", args.Name)
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
		return fmt.Errorf("failed to get %v status: %v", args.Name, err)
	}
	if running {
		return fmt.Errorf("server %v already running", args.Name)
	}
	err = server.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start server %v: %v", args.Name, err)
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
	err = server.AddUserIP(ctx, *args.User, *args.IP)
	if err != nil {
		return fmt.Errorf("failed AddUserIP: %v", err)
	}
	return nil
}

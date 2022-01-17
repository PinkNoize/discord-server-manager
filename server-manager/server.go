package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/google/uuid"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ServerStatus uint

const (
	DEPROVISIONING = iota
	PROVISIONING
	REPAIRING
	RUNNING
	STAGING
	STOPPED
	STOPPING
	SUSPENDED
	TERMINATED
	UNKNOWN
)
const publicInterfaceName string = "External NAT"

type server struct {
	name        string
	subdomain   string   `firestore:"subdomain"`
	machineType string   `firestore:"machineType"`
	ports       []uint16 `firestore:"ports"`
}

func CreateServer(ctx context.Context, name, subdomain, machineType string, ports []uint16) (*server, error) {
	_, err := firestoreClient.Collection("Servers").Doc(name).Get(ctx)
	if err == nil || status.Code(err) != codes.NotFound {
		return nil, fmt.Errorf("server %v already exists", name)
	}

	server := server{
		name:        name,
		subdomain:   subdomain,
		machineType: machineType,
		ports:       ports,
	}

	// Create database item
	serverDoc, _, err := firestoreClient.Collection("Servers").Add(
		ctx,
		server,
	)
	if err != nil {
		return nil, err
	}
	// Use to delete in case of error
	serverDocUndo := func() {
		if _, err = serverDoc.Delete(ctx); err != nil {
			log.Printf("ERROR: Failed to delete document %v in Servers", name)
		}
	}
	log.Printf("Inserted Doc %v into Collection Servers", name)

	// Get compute instance image
	imageResponse, err := computeClient.Images.GetFromFamily(
		"debian-cloud",
		"debian-11",
	).Context(ctx).Do()
	if err != nil {
		defer serverDocUndo()
		return nil, err
	}
	sourceImage := imageResponse.SelfLink
	log.Printf("Found source image: %v", sourceImage)

	// Generate compute instance config
	machineTypePath := fmt.Sprintf("zones/%s/machineTypes/%s", projectZone, machineType)

	startupScript := "#!/bin/bash\n/startup.sh"
	shutdownScript := "#!/bin/bash\n/shutdown.sh"
	instanceConfig := compute.Instance{
		Name:        name,
		MachineType: machineTypePath,
		Disks: []*compute.AttachedDisk{
			{
				Boot:       true,
				AutoDelete: true,
				InitializeParams: &compute.AttachedDiskInitializeParams{
					SourceImage: sourceImage,
					DiskType:    "pd-standard",
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{
				Network: "global/networks/default",
				AccessConfigs: []*compute.AccessConfig{
					{
						Name:        publicInterfaceName,
						Type:        "ONE_TO_ONE_NAT",
						NetworkTier: "STANDARD",
					},
				},
			},
		},
		Metadata: &compute.Metadata{
			Items: []*compute.MetadataItems{
				{
					Key:   "startup-script",
					Value: &startupScript,
				},
				{
					Key:   "shutdown-script",
					Value: &shutdownScript,
				},
			},
		},
		Tags: &compute.Tags{
			Items: []string{generateServerTag(name)},
		},
	}
	// Create Compute instance
	_, err = computeClient.Instances.Insert(
		projectID,
		projectZone,
		&instanceConfig,
	).Context(ctx).Do()
	if err != nil {
		defer serverDocUndo()
		return nil, err
	}
	log.Printf("Created instance %v", name)

	return &server, nil
}

func ServerFromName(ctx context.Context, name string) (*server, error) {
	serverDoc, err := firestoreClient.Collection("Servers").Doc(name).Get(ctx)
	if err != nil || serverDoc.Exists() {
		return nil, fmt.Errorf("server %v does not exist", name)
	}
	server := server{name: name}
	err = serverDoc.DataTo(server)
	if err != nil {
		return nil, err
	}
	return &server, nil
}

func (s *server) Start(ctx context.Context) error {
	_, err := computeClient.Instances.Start(
		projectID,
		projectZone,
		s.name,
	).Context(ctx).Do()
	if err != nil {
		return err
	}
	log.Printf("Server %v started", s.name)
	return nil
}

func (s *server) Stop(ctx context.Context) error {
	_, err := computeClient.Instances.Stop(
		projectID,
		projectZone,
		s.name,
	).Context(ctx).Do()
	if err != nil {
		return err
	}
	log.Printf("Server %v stopped", s.name)
	return nil
}

func (s *server) Delete(ctx context.Context) error {
	// Delete compute instance
	_, err := computeClient.Instances.Delete(
		projectID,
		projectZone,
		s.name,
	).Context(ctx).Do()
	if err != nil {
		return err
	}
	log.Printf("Instance %v deleted", s.name)

	// Delete database entry
	_, err = firestoreClient.Collection("Servers").Doc(s.name).Delete(ctx)
	if err != nil {
		return err
	}
	log.Printf("Doc %v deleted in Collection Servers", s.name)

	return nil
}

func (s *server) Status(ctx context.Context) (ServerStatus, error) {
	instance, err := computeClient.Instances.Get(
		projectID,
		projectZone,
		s.name,
	).Context(ctx).Do()
	if err != nil {
		return UNKNOWN, err
	}
	status := instance.Status
	switch status {
	case "DEPROVISIONING":
		return DEPROVISIONING, nil
	case "PROVISIONING":
		return PROVISIONING, nil
	case "REPAIRING":
		return REPAIRING, nil
	case "RUNNING":
		return RUNNING, nil
	case "STAGING":
		return STAGING, nil
	case "STOPPED":
		return STOPPED, nil
	case "STOPPING":
		return STOPPING, nil
	case "SUSPENDED":
		return SUSPENDED, nil
	case "TERMINATED":
		return TERMINATED, nil
	}
	return UNKNOWN, nil
}

func generateServerTag(name string) string {
	return fmt.Sprintf("server-%v", name)
}

func (s *server) AddUserIP(ctx context.Context, user string, ip net.IP) error {
	fwname := fmt.Sprintf("%v-%v-%v", s.name, user, uuid.NewString())
	serverTag := generateServerTag(s.name)

	var allowedPorts []string
	for _, p := range s.ports {
		allowedPorts = append(allowedPorts, fmt.Sprintf("%v", p))
	}
	_, err := computeClient.Firewalls.Insert(
		projectID,
		&compute.Firewall{
			Allowed: []*compute.FirewallAllowed{
				{
					IPProtocol: "tcp",
					Ports:      allowedPorts,
				},
				{
					IPProtocol: "udp",
					Ports:      allowedPorts,
				},
			},
			Name:         fwname,
			SourceRanges: []string{fmt.Sprintf("%v/32", ip.String())},
			TargetTags:   []string{serverTag},
		},
	).Do()
	if err != nil {
		return err
	}
	log.Printf("Opened firewall to %v:%v from %v", serverTag, allowedPorts, ip)
	return nil
}

func (s *server) ServerIP(ctx context.Context) (*string, error) {
	// Get server IP
	instance, err := computeClient.Instances.Get(
		projectID,
		projectZone,
		s.name,
	).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	if instance.Status != "RUNNING" {
		return nil, fmt.Errorf("%v not running", s.name)
	}

	var extIP *string = nil
ifaceLoop:
	for _, iface := range instance.NetworkInterfaces {
		for _, cfg := range iface.AccessConfigs {
			if cfg.Name == publicInterfaceName {
				extIP = &iface.NetworkIP
				break ifaceLoop
			}
		}
	}
	if extIP == nil {
		return nil, fmt.Errorf("%v has not external interface", s.name)
	}
	return extIP, nil
}

func (s *server) CreateDNSRecord(ctx context.Context, ip string) error {
	// Set DNS record
	_, err := rrClient.Create(
		dnsProjectID,
		dnsZone,
		&dns.ResourceRecordSet{
			Name: s.DnsName(),
			Type: "A",
			Ttl:  300,
			Rrdatas: []string{
				ip,
			},
		},
	).Do()
	return err
}

func (s *server) DeleteDNSRecord(ctx context.Context, ip string) error {
	// Set DNS record
	_, err := rrClient.Delete(
		dnsProjectID,
		dnsZone,
		s.DnsName(),
		"A",
	).Do()
	return err
}

func (s *server) DnsName() string {
	return fmt.Sprintf("%v.%v", s.subdomain, baseDomain)
}

func (s *server) IsStopped(ctx context.Context) (bool, error) {
	status, err := s.Status(ctx)
	if err != nil {
		return false, err
	}
	return status != STOPPED &&
		status != STOPPING, nil
}

func (s *server) IsRunning(ctx context.Context) (bool, error) {
	status, err := s.Status(ctx)
	if err != nil {
		return false, err
	}
	return status != PROVISIONING &&
		status != RUNNING &&
		status != STAGING, nil
}

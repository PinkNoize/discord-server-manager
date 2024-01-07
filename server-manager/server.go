package server_manager

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"strings"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/storage"
	"github.com/sony/sonyflake"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/googleapi"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ServerStatus uint

// Editing these between deployments can cause confusion
const (
	// Internal statuses
	NEW = iota
	READY
	STARTINGUP
	SAVING
	// GCP statuses
	DEPROVISIONING
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

func (ss ServerStatus) String() string {
	switch ss {
	case NEW:
		return "NEW"
	case READY:
		return "READY"
	case SAVING:
		return "SAVING"
	case DEPROVISIONING:
		return "DEPROVISIONING"
	case PROVISIONING:
		return "PROVISIONING"
	case REPAIRING:
		return "REPAIRING"
	case RUNNING:
		return "RUNNING"
	case STAGING:
		return "STAGING"
	case STOPPED:
		return "STOPPED"
	case STOPPING:
		return "STOPPING"
	case SUSPENDED:
		return "SUSPENDED"
	case TERMINATED:
		return "TERMINATED"
	default:
		return "UNKNOWN"
	}
}

const publicInterfaceName string = "External NAT"

type server struct {
	// User configurable
	Name        string
	Subdomain   string   `firestore:"subdomain"`
	MachineType string   `firestore:"machineType"`
	Purpose     string   `firestore:"purpose"`
	OSFamily    string   `firestore:"osFamily"`
	Ports       []uint16 `firestore:"ports"`
	DiskSizeGB  int64    `firestore:"diskSizeGB"`
	// Backend
	instanceAccount *string      `firestore:"instanceAccount"`
	bucket          *string      `firestore:"bucket"`
	status          ServerStatus `firestore:"status"`
}

func CreateServer(ctx context.Context, name, subdomain, machineType, purpose, osFamily string, ports []uint16, diskSize int64) (*server, error) {
	// Create database item
	server := server{
		Name:            name,
		Subdomain:       subdomain,
		MachineType:     machineType,
		Purpose:         purpose,
		OSFamily:        osFamily,
		Ports:           ports,
		DiskSizeGB:      diskSize,
		instanceAccount: nil,
		bucket:          nil,
		status:          NEW,
	}
	// TODO: Add validation for input fields
	if diskSize > 100 && diskSize >= 1 {
		return nil, fmt.Errorf("disk space must be less than 101 GB: %v GB", diskSize)
	}
	serverDoc := firestoreClient.Collection("Servers").Doc(name)
	_, err := serverDoc.Create(
		ctx,
		server,
	)
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			return nil, fmt.Errorf("server %v already exists", name)
		}
		return nil, fmt.Errorf("serverDoc.create: %v", err)
	}
	return &server, nil
}

func ServerFromName(ctx context.Context, name string) (*server, error) {
	serverDoc, err := firestoreClient.Collection("Servers").Doc(name).Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Doc %v: %v", name, err)
	}
	if !serverDoc.Exists() {
		return nil, fmt.Errorf("server %v does not exist", name)
	}
	server := server{}
	err = serverDoc.DataTo(&server)
	server.Name = name
	if err != nil {
		return nil, err
	}
	return &server, nil
}

func (s *server) getDocRef() *firestore.DocumentRef {
	return firestoreClient.Collection("Servers").Doc(s.Name)
}

func (s *server) syncFromDB(ctx context.Context) error {
	if newServer, err := ServerFromName(ctx, s.Name); err != nil {
		return fmt.Errorf("serverFromName: %v", err)
	} else {
		*s = *newServer
		return nil
	}
}

// Setters
func (s *server) updateDBfield(ctx context.Context, field string, value interface{}) error {
	update := []firestore.Update{
		{
			Path:  field,
			Value: value,
		},
	}
	_, err := s.getDocRef().Update(ctx, update)
	if err != nil {
		return fmt.Errorf("update: %v", err)
	}
	return nil
}

func (s *server) setBucketName(ctx context.Context, bucket *string) error {
	err := s.updateDBfield(ctx, "bucket", *bucket)
	if err != nil {
		return fmt.Errorf("updateDBfield: %v", err)
	}
	s.bucket = bucket
	return nil
}

func (s *server) setInstanceAccount(ctx context.Context, account *string) error {
	err := s.updateDBfield(ctx, "instanceAccount", *account)
	if err != nil {
		return fmt.Errorf("updateDBfield: %v", err)
	}
	s.instanceAccount = account
	return nil
}

func (s *server) setStatus(ctx context.Context, status ServerStatus) error {
	err := s.updateDBfield(ctx, "status", status)
	if err != nil {
		return fmt.Errorf("updateDBfield: %v", err)
	}
	s.status = status
	return nil
}

func (s *server) isSetup() bool {
	return s.bucket != nil && s.instanceAccount != nil
}

func (s *server) setup(ctx context.Context) error {
	if s.bucket == nil {
		// Create bucket
		flake := sonyflake.NewSonyflake(sonyflake.Settings{
			MachineID: func() (uint16, error) { return 0x6969, nil },
		})
		flakeID, err := flake.NextID()
		if err != nil {
			return fmt.Errorf("flake.NextID: %v", err)
		}
		flakeIDbyte := make([]byte, 8)
		binary.BigEndian.PutUint64(flakeIDbyte, flakeID)
		id := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(flakeIDbyte))
		bucketName := fmt.Sprintf("%v-storage-%v", s.Name, id)
		bucket := storageClient.Bucket(bucketName)
		attrs := storage.BucketAttrs{
			Location:     projectZone,
			LocationType: "region",
			Labels: map[string]string{
				"server": generateServerTag(s.Name),
			},
		}
		if err := bucket.Create(ctx, projectID, &attrs); err != nil {
			return fmt.Errorf("bucket.Create: %v", err)
		}
		log.Printf("Bucket created successfully: %v", bucketName)
		err = s.setBucketName(ctx, &bucketName)
		if err != nil {
			return fmt.Errorf("setBucketName: %v", err)
		}
	}
	if s.instanceAccount == nil {
		// Create service account
		createRequest := &iam.CreateServiceAccountRequest{
			AccountId: fmt.Sprintf("%s-server-compute", s.Name),
			ServiceAccount: &iam.ServiceAccount{
				DisplayName: fmt.Sprintf("%v Compute Service Account", s.Name),
			},
		}
		sAccount, err := iamService.Projects.ServiceAccounts.Create("projects/"+projectID, createRequest).Do()
		if err != nil {
			return fmt.Errorf("Projects.ServiceAccounts.Create: %v", err)
		}
		log.Printf("Created service account %v", sAccount.Email)
		err = s.setInstanceAccount(ctx, &sAccount.Email)
		if err != nil {
			return fmt.Errorf("setInstanceAccount: %v", err)
		}

		// Set IAM Policy
		policy, err := cloudresourcemanagerService.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
		if err != nil {
			return fmt.Errorf("Projects.ServiceAccounts.GetIamPolicy: %v", err)
		}

		addBinding(cloudresourcemanagerService, projectID, fmt.Sprintf("serviceAccount:%s", sAccount.Email), "roles/monitoring.metricWriter", policy, nil)
		addBinding(cloudresourcemanagerService, projectID, fmt.Sprintf("serviceAccount:%s", sAccount.Email), "roles/logging.logWriter", policy, nil)

		setIamPolicyRequest := &cloudresourcemanager.SetIamPolicyRequest{
			Policy: policy,
		}
		_, err = cloudresourcemanagerService.Projects.SetIamPolicy(projectID, setIamPolicyRequest).Do()
		if err != nil {
			return fmt.Errorf("Projects.ServiceAccounts.SetIamPolicy: %v", err)
		}
		log.Printf("Binded service account %v to policy", s.instanceAccount)
	}
	// Update Status
	if err := s.setStatus(ctx, READY); err != nil {
		return fmt.Errorf("setStatus: %v", err)
	}
	return nil
}

func (s *server) unsetup(ctx context.Context) error {
	if s.bucket != nil {
		bucketName := s.bucket
		bucket := storageClient.Bucket(*bucketName)
		if err := bucket.Delete(ctx); err != nil {
			return fmt.Errorf("bucket.Delete: %v", err)
		}
		log.Printf("Bucket deleted successfully: %v", bucketName)
		if err := s.setBucketName(ctx, nil); err != nil {
			return fmt.Errorf("setBucketName: %v", err)
		}
	}
	if s.instanceAccount != nil {
		sAccount := *s.instanceAccount
		// Remove policy bindings for SA
		policy, err := cloudresourcemanagerService.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
		if err != nil {
			return fmt.Errorf("Projects.ServiceAccounts.GetIamPolicy: %v", err)
		}
		removeBindingsForSA(cloudresourcemanagerService, projectID, fmt.Sprintf("serviceAccount:%s", sAccount), policy)

		setIamPolicyRequest := &cloudresourcemanager.SetIamPolicyRequest{
			Policy: policy,
		}
		_, err = cloudresourcemanagerService.Projects.SetIamPolicy(projectID, setIamPolicyRequest).Do()
		if err != nil {
			return fmt.Errorf("Projects.ServiceAccounts.SetIamPolicy: %v", err)
		}
		// Delete service account
		_, err = iamService.Projects.ServiceAccounts.Delete(fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, sAccount)).Do()
		if err != nil {
			return fmt.Errorf("Projects.ServiceAccounts.Delete: %v", err)
		}
		log.Printf("Deleted service account %v", sAccount)
		err = s.setInstanceAccount(ctx, nil)
		if err != nil {
			return fmt.Errorf("setInstanceAccount: %v", err)
		}
	}
	if err := s.setStatus(ctx, NEW); err != nil {
		return fmt.Errorf("setStatus: %v", err)
	}
	return nil
}

func (s *server) getInstanceBaseImage(ctx context.Context) (string, error) {
	project := ""
	switch {
	case strings.HasPrefix(s.OSFamily, "debian"):
		project = "debian-cloud"
	default:
		return "", fmt.Errorf("OS family unknown: %v", s.OSFamily)
	}
	// Get compute instance image
	imageResponse, err := computeClient.Images.GetFromFamily(
		project,
		s.OSFamily,
	).Context(ctx).Do()
	if err != nil {
		return "", err
	}
	sourceImage := imageResponse.SelfLink
	log.Printf("Found source image: %v", sourceImage)
	return sourceImage, nil
}

func (s *server) Start(ctx context.Context) error {
	if !s.isSetup() {
		err := s.setup(ctx)
		if err != nil {
			return fmt.Errorf("setup: %v", err)
		}
	}
	// Check that instance is in a startable state
	status, err := s.Status(ctx)
	if err != nil {
		return fmt.Errorf("GetStatus: %v", err)
	}
	switch status {
	case READY:
	default:
		return fmt.Errorf("server not in a startable state: %v", status)
	}

	// Get instance config
	sourceImage, err := s.getInstanceBaseImage(ctx)
	if err != nil {
		return fmt.Errorf("getInstanceBaseImage: %v", err)
	}

	startupScript := "#!/bin/bash\n/startup.sh"
	shutdownScript := "#!/bin/bash\n/shutdown.sh"
	instanceConfig := compute.Instance{
		Name:        s.Name,
		MachineType: fmt.Sprintf("zones/%s/machineTypes/%s", projectZone, s.MachineType),
		Disks: []*compute.AttachedDisk{
			{
				Boot:       true,
				AutoDelete: true,
				InitializeParams: &compute.AttachedDiskInitializeParams{
					SourceImage: sourceImage,
					DiskType:    fmt.Sprintf("zones/%v/diskTypes/pd-standard", projectZone),
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
		Scheduling: &compute.Scheduling{
			ProvisioningModel:         "SPOT",
			InstanceTerminationAction: "DELETE",
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
		ServiceAccounts: []*compute.ServiceAccount{
			{
				Email:  *s.instanceAccount,
				Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
			},
		},
		Labels: map[string]string{
			"server": generateServerTag(s.Name),
		},
		Tags: &compute.Tags{
			Items: []string{generateServerTag(s.Name)},
		},
	}
	instance, err := computeClient.Instances.Insert(
		projectID,
		projectZone,
		&instanceConfig,
	).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("instances.insert: %v", err)
	}
	log.Printf("Created instance %v for %v", instance.Id, s.Name)
	if err := s.setStatus(ctx, STARTINGUP); err != nil {
		return fmt.Errorf("setStatus: %v", err)
	}
	// TODO: Create volume and attach it
	// Update server status
	if err := s.setStatus(ctx, RUNNING); err != nil {
		return fmt.Errorf("setStatus: %v", err)
	}
	return nil
}

func (s *server) Stop(ctx context.Context) error {
	_, err := computeClient.Instances.Stop(
		projectID,
		projectZone,
		s.Name,
	).Context(ctx).Do()
	if err != nil {
		return err
	}
	log.Printf("Server %v stopped", s.Name)
	return nil
}

func (s *server) Delete(ctx context.Context) error {
	// Check status is in a deletable state
	status, err := s.Status(ctx)
	if err != nil {
		return fmt.Errorf("GetStatus: %v", err)
	}
	switch status {
	case NEW, READY:
	default:
		return fmt.Errorf("server not in a deletable state: %v", status)
	}
	if err := s.unsetup(ctx); err != nil {
		return fmt.Errorf("unsetup: %v", err)
	}
	// Get instance info
	instance, err := computeClient.Instances.Get(
		projectID,
		projectZone,
		s.Name,
	).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("error: Instances.get: %v", err)
	}

	// Delete compute instance
	_, err = computeClient.Instances.Delete(
		projectID,
		projectZone,
		s.Name,
	).Context(ctx).Do()
	if err != nil {
		return err
	}
	log.Printf("Instance %v deleted", s.Name)

	// Remove policy bindings for SA
	policy, err := cloudresourcemanagerService.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return fmt.Errorf("Projects.ServiceAccounts.GetIamPolicy: %v", err)
	}
	for _, sAcc := range instance.ServiceAccounts {
		removeBindingsForSA(cloudresourcemanagerService, projectID, fmt.Sprintf("serviceAccount:%s", sAcc.Email), policy)
	}

	setIamPolicyRequest := &cloudresourcemanager.SetIamPolicyRequest{
		Policy: policy,
	}
	_, err = cloudresourcemanagerService.Projects.SetIamPolicy(projectID, setIamPolicyRequest).Do()
	if err != nil {
		return fmt.Errorf("Projects.ServiceAccounts.SetIamPolicy: %v", err)
	}

	// Delete service account
	for _, sAcc := range instance.ServiceAccounts {
		_, err = iamService.Projects.ServiceAccounts.Delete(fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, sAcc.Email)).Do()
		if err != nil {
			log.Printf("error: Unable to delete %v. Manually delete the account", sAcc.Email)
		} else {
			log.Printf("Deleted service account %v", sAcc.Email)
		}

	}

	// Delete database entry
	_, err = firestoreClient.Collection("Servers").Doc(s.Name).Delete(ctx)
	if err != nil {
		return err
	}
	log.Printf("Doc %v deleted in Collection Servers", s.Name)

	return nil
}

func (s *server) Status(ctx context.Context) (ServerStatus, error) {
	instance, err := computeClient.Instances.Get(
		projectID,
		projectZone,
		s.Name,
	).Context(ctx).Do()
	if err != nil {
		if gerr, ok := err.(*googleapi.Error); ok && gerr.Code == http.StatusNotFound {
			// Instance not found
			if err := s.syncFromDB(ctx); err != nil {
				return UNKNOWN, fmt.Errorf("syncFromDB: %v", err)
			}
			return s.status, nil
		}
		return UNKNOWN, err
	}
	status := instance.Status
	log.Printf("server %v status: %v", s.Name, status)
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

func (s *server) AddUserIP(ctx context.Context, user string, ip string) error {
	flake := sonyflake.NewSonyflake(sonyflake.Settings{
		MachineID: func() (uint16, error) { return 0x6969, nil },
	})
	flakeID, err := flake.NextID()
	if err != nil {
		return fmt.Errorf("flake.NextID: %v", err)
	}
	flakeIDbyte := make([]byte, 8)
	binary.BigEndian.PutUint64(flakeIDbyte, flakeID)
	id := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(flakeIDbyte))
	// Must start with letter
	fwname := fmt.Sprintf("fw-%v-%v", user, id)
	serverTag := generateServerTag(s.Name)

	var allowedPorts []string
	for _, p := range s.Ports {
		allowedPorts = append(allowedPorts, fmt.Sprintf("%v", p))
	}
	_, err = computeClient.Firewalls.Insert(
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
			SourceRanges: []string{fmt.Sprintf("%v/32", ip)},
			TargetTags:   []string{serverTag},
		},
	).Do()
	if err != nil {
		return err
	}
	log.Printf("Opened firewall to %v:%v from %v", serverTag, allowedPorts, ip)
	return nil
}

func (s *server) ServerIP(ctx context.Context) (string, error) {
	// Get server IP
	instance, err := computeClient.Instances.Get(
		projectID,
		projectZone,
		s.Name,
	).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("failed to get instance IP %v: %v", s.Name, err)
	}

	if instance.Status != "RUNNING" {
		return "", fmt.Errorf("%v not running", s.Name)
	}

	var extIP string = ""
ifaceLoop:
	for i := range instance.NetworkInterfaces {
		for _, cfg := range instance.NetworkInterfaces[i].AccessConfigs {
			if cfg.Name == publicInterfaceName {
				log.Printf("Network %v: %v", cfg.Name, instance.NetworkInterfaces[i].NetworkIP)
				extIP = cfg.NatIP
				break ifaceLoop
			}
		}
	}
	if extIP == "" {
		return "", fmt.Errorf("%v has no external interface", s.Name)
	}
	return extIP, nil
}

func (s *server) CreateDNSRecord(ctx context.Context) error {
	// Get server IP
	ip, err := s.ServerIP(ctx)
	if err != nil {
		return fmt.Errorf("CreateDNSRecord: %v", err)
	}

	log.Printf("Creating record: %v -> %v", s.DnsName(), ip)
	// Set DNS record
	_, err = rrClient.Create(
		dnsProjectID,
		dnsZone,
		&dns.ResourceRecordSet{
			Name: s.DnsName(),
			Kind: "dns#resourceRecordSet",
			Type: "A",
			Ttl:  300,
			Rrdatas: []string{
				ip,
			},
		},
	).Do()
	if err != nil {
		log.Printf("Headers: %+v", *(err.(*googleapi.Error)))
	}
	return err
}

func (s *server) DeleteDNSRecord(ctx context.Context) error {
	log.Printf("Deleting record %v", s.DnsName())
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
	return fmt.Sprintf("%v.%v.", s.Subdomain, baseDomain)
}

func (s *server) IsStopped(ctx context.Context) (bool, error) {
	status, err := s.Status(ctx)
	if err != nil {
		return false, err
	}
	return status == STOPPED ||
		status == STOPPING || status == TERMINATED || status == NEW || status == READY, nil
}

func (s *server) IsRunning(ctx context.Context) (bool, error) {
	status, err := s.Status(ctx)
	if err != nil {
		return false, err
	}
	return status == PROVISIONING ||
		status == RUNNING ||
		status == STAGING, nil
}

// https://github.com/GoogleCloudPlatform/golang-samples/blob/cc8d05b8732769e07f5da46094a848bde655240d/iam/quickstart/quickstart.go#L69
func addBinding(crmService *cloudresourcemanager.Service, projectID, member, role string, policy *cloudresourcemanager.Policy, cond *cloudresourcemanager.Expr) {

	// Find the policy binding for role. Only one binding can have the role.
	var binding *cloudresourcemanager.Binding
	for _, b := range policy.Bindings {
		if b.Role == role && b.Condition == cond {
			binding = b
			break
		}
	}

	if binding != nil {
		// If the binding exists, adds the member to the binding
		binding.Members = append(binding.Members, member)
	} else {
		// If the binding does not exist, adds a new binding to the policy
		binding = &cloudresourcemanager.Binding{
			Role:      role,
			Members:   []string{member},
			Condition: cond,
		}
		policy.Bindings = append(policy.Bindings, binding)
	}
}

func removeBindingsForSA(crmService *cloudresourcemanager.Service, projectID, member string, policy *cloudresourcemanager.Policy) {
	newBindings := policy.Bindings[:0]
	for _, b := range policy.Bindings {
		newMembers := b.Members[:0]
		for _, m := range b.Members {
			if m != member {
				newMembers = append(newMembers, m)
			}
		}
		b.Members = newMembers
		if len(b.Members) > 0 {
			newBindings = append(newBindings, b)
		}
	}
	policy.Bindings = newBindings
}

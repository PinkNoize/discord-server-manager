package snapshotfunction

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/compute/v1"
)

// Globals
var projectID string = os.Getenv("PROJECT_ID")
var projectRegion string = os.Getenv("PROJECT_REGION")
var projectZone string = os.Getenv("PROJECT_ZONE")

var computeClient *compute.Service
var firestoreClient *firestore.Client

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
}

type PubSubMessage struct {
	Data []byte `json:"data"`
}

type SnapshotInfoPubSub struct {
	Name string `json:"name"`
	Disk string `json:"disk"`
}

type ServerStatus string

const (
	// Internal statuses
	NEW        = "NEW"
	READY      = "READY"
	STARTINGUP = "STARTINGUP"
	SAVING     = "SAVING"
	// GCP statuses
	DEPROVISIONING = "DEPROVISIONING"
	PROVISIONING   = "PROVISIONING"
	REPAIRING      = "REPAIRING"
	RUNNING        = "RUNNING"
	STAGING        = "STAGING"
	STOPPED        = "STOPPED"
	STOPPING       = "STOPPING"
	SUSPENDED      = "SUSPENDED"
	TERMINATED     = "TERMINATED"
	UNKNOWN        = "UNKNOWN"
)

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

type server struct {
	// User configurable
	Name string
	// Backend
	Status ServerStatus `firestore:"status"`
}

func generateServerTag(name string) string {
	return fmt.Sprintf("server-%v", name)
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

// Entry
func SnapshotPubSub(ctx context.Context, m PubSubMessage) error {
	var snapshotInfo SnapshotInfoPubSub
	if err := json.Unmarshal([]byte(m.Data), &snapshotInfo); err != nil {
		log.Fatalf("Failed to unmarshal snapshotInfo: %v", err)
	}
	serverName := snapshotInfo.Name
	disk := snapshotInfo.Disk
	_, diskName := filepath.Split(disk)
	serverDocRef := firestoreClient.Collection("Servers").Doc(serverName)

	diskInfo, err := computeClient.Disks.Get(projectID, projectZone, diskName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to find disk: %v", err)
	}
	if len(diskInfo.Users) != 0 {
		return fmt.Errorf("disk %v still has attachments: %v", diskName, diskInfo.Users)
	}

	server, err := ServerFromName(ctx, serverName)
	if err != nil {
		return fmt.Errorf("serverFromName: %v", err)
	}
	log.Print(LogEntry{
		Message: fmt.Sprintf("Server %v has status %v", serverName, server.Status),
	})

	if server.Status == SAVING {
		// Snapshot disk
		snapshot, err := computeClient.Snapshots.Insert(projectID, &compute.Snapshot{
			Name:        fmt.Sprintf("%v-%x", serverName, diskInfo.Id),
			Description: fmt.Sprintf("Snapshot of %x", diskInfo.Id),
			SourceDisk:  disk,
			StorageLocations: []string{
				projectZone,
			},
			Labels: map[string]string{
				"server": generateServerTag(serverName),
			},
		}).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to create snapshot for %v %x", serverName, diskInfo.Id)
		}
		log.Println("Snapshot creation operation started. Waiting for completion...")

		snapshot, err = waitForOperation(ctx, snapshot)
		if err != nil {
			return fmt.Errorf("waitForOperation: %v", err)
		}

		log.Println("Snapshot creation successful!")

		snapshot_path := fmt.Sprintf("global/snapshots/%s", snapshot.Name)
		log.Print(LogEntry{
			Message: fmt.Sprintf("Created snapshot %v", snapshot_path),
		})
		// Delete disk
		_, err = computeClient.Disks.Delete(projectID, projectZone, diskInfo.Name).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("disks.Delete: %v", err)
		}
		// Update status
		_, err = serverDocRef.Update(ctx, []firestore.Update{
			{
				Path:  "status",
				Value: READY,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to update server status: %v", err)
		}
		oldSnapshots, err := server.getOldServerSnapshots(ctx)
		if err != nil {
			return fmt.Errorf("getOldServerSnapshots: %v", err)
		}
		log.Print(LogEntry{
			Message: "Old snapshots found:",
		})
		for _, snap := range oldSnapshots {
			log.Print(LogEntry{
				Message: fmt.Sprintf("Deleting %v", snap.Name),
			})
			if err = deleteSnapshot(ctx, snap); err != nil {
				log.Print(LogEntry{
					Message:  fmt.Sprintf("deleteSnapshot: %v", err),
					Severity: "ERROR",
				})
			}
		}
		return nil
	} else if server.Status == READY {
		return nil
	} else {
		return fmt.Errorf("server not in processable status: %v", server.Status)
	}
}

func waitForOperation(ctx context.Context, op *compute.Operation) (*compute.Operation, error) {
	globalOperationsService := compute.NewGlobalOperationsService(computeClient)

	for {
		status, err := globalOperationsService.Wait(projectID, op.Name).Do()
		if err != nil {
			return nil, fmt.Errorf("error checking operation status: %w", err)
		}

		switch status.Status {
		case "DONE":
			if status.Error != nil {
				return nil, fmt.Errorf("operation completed with error: %v", status.Error)
			}
			return status, nil // Operation completed successfully
		case "PENDING", "RUNNING":
			log.Print(LogEntry{
				Message: fmt.Sprintf("Operation still in progress: %v", status.StatusMessage),
			})
			continue
		default:
			return nil, fmt.Errorf("unexpected operation status: %s", status.Status)
		}
	}
}

func (s *server) getOldServerSnapshots(ctx context.Context) ([]*compute.Snapshot, error) {
	snapshotRes, err := computeClient.Snapshots.List(projectID).Filter(fmt.Sprintf("labels.server=%s", generateServerTag(s.Name))).Do()
	if err != nil {
		return nil, fmt.Errorf("snapshots.List: %v", err)
	}
	snapshots := snapshotRes.Items
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].CreationTimestamp > snapshots[j].CreationTimestamp
	})
	if len(snapshots) >= 1 {
		return snapshots[1:], nil
	} else {
		return []*compute.Snapshot{}, nil
	}
}

func deleteSnapshot(ctx context.Context, snapshot *compute.Snapshot) error {
	_, err := computeClient.Snapshots.Delete(projectID, snapshot.Name).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("snapshots.Delete: %v", err)
	}
	return nil
}

# Resources for IP Fetching cloud function

# Encryption key
resource "google_secret_manager_secret" "ip-fetch-key" {
  secret_id = "ip-fetch-key"

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
  rotation {
    rotation_period = "7889238s" # 3 months
    next_rotation_time = timeadd(time_static.create_time.rfc3339, "15m")
  }
  topics {
    # For publication to succeed, the Secret Manager Service Agent service account must have pubsub.publisher permissions on the topic.
    name = google_pubsub_topic.key_rotate_topic.id
  }
  depends_on  =[
    google_pubsub_topic_iam_member.key-rotate-secret-pubsub-member # service account and mapping must be created first
  ]
  lifecycle {
    ignore_changes = [
      rotation[0].next_rotation_time,    
    ]  
  }
}

resource "time_static" "create_time" {}

# Command deployer Cloud Function
resource "google_service_account" "ip_fetch_service_account" {
  account_id   = "ip-fetch-service-acc"
  display_name = "IP Fetch Function Account"
}

resource "google_secret_manager_secret_iam_member" "ip-fetch-member" {
  project = var.project
  secret_id = google_secret_manager_secret.ip-fetch-key.id
  role = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.ip_fetch_service_account.email}"
}

resource "google_project_iam_member" "ip-fetch-firestore-iam" {
  project = var.project
  role    = "roles/datastore.user"
  member = "serviceAccount:${google_service_account.discord_service_account.email}"
}

resource "google_pubsub_topic_iam_member" "ip-fetch-pubsub-member" {
  project = google_pubsub_topic.command_topic.project
  topic = google_pubsub_topic.command_topic.name
  role = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.ip_fetch_service_account.email}"
}

module "ip_fetch_function" {
  source                = "./modules/function"
  project               = var.project
  region                = var.region
  function_name         = "ip-fetch-function"
  function_entry_point  = "IPFetchEntry"
  environment_variables = {
    "PROJECT_ID"    = var.project
    "COMMAND_TOPIC" = google_pubsub_topic.command_topic.name
    "KEY_SECRET_ID" = google_secret_manager_secret.ip-fetch-key.id
  }
  source_dir            = "./ip-fetch-function"
  service_account_email = google_service_account.ip_fetch_service_account.email
  trigger_http          = true
  ingress_settings      = "ALLOW_ALL"
}

# Key Rotation Function REsources
resource "google_pubsub_topic" "key_rotate_topic" {
  name = "key-rotate-topic"
}

resource "google_service_account" "key_rotate_service_account" {
  account_id   = "key-rotate-service-acc"
  display_name = "Key Rotation Function Account"
}

resource "google_secret_manager_secret_iam_member" "key-rotate-member" {
  project = var.project
  secret_id = google_secret_manager_secret.ip-fetch-key.id
  role = "roles/secretmanager.admin"
  member = "serviceAccount:${google_service_account.key_rotate_service_account.email}"
}

module "key_rotate_function" {
  source                = "./modules/function"
  project               = var.project
  region                = var.region
  function_name         = "key-rotate-function"
  function_entry_point  = "KeyRotatePubSub"
  environment_variables = {
    "PROJECT_ID"    = var.project
    "KEY_SECRET_ID" = google_secret_manager_secret.ip-fetch-key.id
  }
  source_dir            = "./key-rotate-function"
  service_account_email = google_service_account.key_rotate_service_account.email
  event_type            = "google.pubsub.topic.publish"
  event_resource        = "${google_pubsub_topic.key_rotate_topic.id}"
}

resource "google_project_service_identity" "sc_sa" {
  provider = google-beta

  project = data.google_project.project.project_id
  service = "secretmanager.googleapis.com"
}

resource "google_pubsub_topic_iam_member" "key-rotate-secret-pubsub-member" {
  project = google_pubsub_topic.key_rotate_topic.project
  topic = google_pubsub_topic.key_rotate_topic.name
  role = "roles/pubsub.publisher"
  member = "serviceAccount:${google_project_service_identity.sc_sa.email}"
}
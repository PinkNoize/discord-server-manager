terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.5.0"
    }
    random = {
      source = "hashicorp/random"
      version = "3.1.0"
    }
  }
}

provider "random" {
  # Configuration options
}


provider "google" {
  project = var.project
  region  = var.region
}

provider "google" {
  alias = "dns"
  project = var.dns_project_id
}

resource "google_pubsub_topic" "command_topic" {
  name = "command-topic"
}

# Cloud Function Resources

resource "random_id" "id" {
	  byte_length = 8
}

resource "google_project_iam_custom_role" "command_func_role" {
  role_id     = "cmdfunc_role_${random_id.id.hex}"
  title       = "Command Func Role"
  description = ""
  permissions = ["datastore.databases.get"]
}

resource "google_service_account" "service_account" {
  account_id   = "command-func-service-acc"
  display_name = "Command Function Account"
}

resource "google_service_account_iam_binding" "custom-role-iam" {
  role    = google_project_iam_custom_role.command_func_role.id
  members = ["serviceAccount:${google_service_account.service_account.email}"]
}

resource "google_service_account_iam_binding" "firestore-iam" {
  role    = "roles/datastore.user"
  members = ["serviceAccount:${google_service_account.service_account.email}"]
}

resource "google_service_account_iam_binding" "compute-iam" {
  role    = "roles/compute.admin"
  members = ["serviceAccount:${google_service_account.service_account.email}"]
}

# Add permissions to access DNS project
resource "google_service_account_iam_binding" "dns-iam" {
  provider = google.dns
  role    = "roles/server_manager_dns_role"
  members = ["serviceAccount:${google_service_account.service_account.email}"]
}

module "command_function" {
  source                = "./modules/function"
  project               = var.project
  region                = var.region
  function_name         = "command-function"
  function_entry_point  = "CommandPubSub"
  environment_variables = {
    "PROJECT_ID"       = var.project
    "PROJECT_ZONE"     = var.zone
    "DNS_PROJECT_ID"   = var.dns_project_id
    "DNS_MANAGED_ZONE" = var.dns_managed_zone
    "BASE_DOMAIN"      = var.base_domain
  }
  source_dir            = "./server-manager"
  service_account_email = google_service_account.service_account.email
  event_type            = "google.pubsub.topic.publish"
  event_resource        = "${google_pubsub_topic.command_topic.id}"
}

# Enable Firestore
resource "google_app_engine_application" "app" {
  project       = var.project
  location_id   = var.region
  database_type = "CLOUD_FIRESTORE"
}
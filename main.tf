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

data "google_project" "project" {}

resource "google_pubsub_topic" "command_topic" {
  name = "command-topic"
}

#Enable Compute API
resource "google_project_service" "comp" {
  project = var.project
  service = "compute.googleapis.com"

  disable_dependent_services = true
  disable_on_destroy         = false
}

# Give cloudbuild access to cloud functions
resource "google_project_service_identity" "cb_sa" {
  provider = google-beta

  project = var.project
  service = "cloudbuild.googleapis.com"
}

resource "google_project_iam_member" "cloudbuild-cf-member" {
  project = google_project_service_identity.cb_sa.project
  role = "roles/cloudfunctions.developer"
  member = "serviceAccount:${google_project_service_identity.cb_sa.email}"
}

resource "google_project_iam_member" "cloudbuild-sa-member" {
  project = google_project_service_identity.cb_sa.project
  role = "roles/iam.serviceAccountUser"
  member = "serviceAccount:${google_project_service_identity.cb_sa.email}"
}

# Discord API secret
resource "google_secret_manager_secret" "secret-basic" {
  secret_id = "discord-api-secret"

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

# Cloud Function Resources

resource "random_id" "id" {
	  byte_length = 8
}

resource "google_project_iam_custom_role" "command_func_svc_create_role" {
  role_id     = "cmdfunc_svc_create_${random_id.id.hex}"
  title       = "Command Func Role"
  description = ""
  permissions = ["iam.serviceAccounts.get",
                 "iam.serviceAccounts.create",
                 "iam.serviceAccounts.delete"]
}

resource "google_service_account" "service_account" {
  account_id   = "command-func-service-acc"
  display_name = "Command Function Account"
}

resource "google_project_iam_member" "custom-role-iam" {
  project = var.project
  role    = google_project_iam_custom_role.command_func_svc_create_role.id
  member = "serviceAccount:${google_service_account.service_account.email}"

  condition {
    title      = "limit_to_server_accs"
    expression = "resource.name.extract('/serviceAccounts/{acc_name}').endsWith('-server-compute')"
  }
}

resource "google_project_iam_member" "cmd-policy-role-iam" {
  project = var.project
  role    = "roles/resourcemanager.projectIamAdmin"
  member  = "serviceAccount:${google_service_account.service_account.email}"

  condition {
    title      = "limit_to_server_accs"
    expression = "resource.name.extract('/serviceAccounts/{acc_name}').endsWith('-server-compute')"
  }
}

resource "google_project_iam_member" "firestore-iam" {
  project = var.project
  role    = "roles/datastore.user"
  member = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_project_iam_member" "compute-iam" {
  project = var.project
  role    = "roles/compute.admin"
  member  = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_secret_manager_secret_iam_member" "command-member" {
  project = var.project
  secret_id = google_secret_manager_secret.secret-basic.id
  role = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.service_account.email}"
}

# Add permissions to access DNS project
resource "google_project_iam_binding" "dns-iam" {
  provider = google.dns
  project  = var.dns_project_id
  role     = "projects/${var.dns_project_id}/roles/server_manager_dns_role"
  members  = ["serviceAccount:${google_service_account.service_account.email}"]
}

module "command_function" {
  source                = "./modules/function"
  project               = var.project
  region                = var.region
  function_name         = "command-function"
  function_entry_point  = "CommandPubSub"
  environment_variables = {
    "PROJECT_ID"        = var.project
    "PROJECT_ZONE"      = var.zone
    "DNS_PROJECT_ID"    = var.dns_project_id
    "DNS_MANAGED_ZONE"  = var.dns_managed_zone
    "BASE_DOMAIN"       = var.base_domain
    "DISCORD_APPID"     = var.discord_app_id
    "DISCORD_SECRET_ID" = google_secret_manager_secret.secret-basic.id
  }
  repository            = var.repository
  branch                = "main"
  source_dir            = "server-manager"
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

# Discord Bot Cloud Function

resource "google_project_iam_custom_role" "discord_func_role" {
  role_id     = "discord_role_${random_id.id.hex}"
  title       = "Discord Func Role"
  description = ""
  permissions = ["datastore.databases.get"]
}

resource "google_service_account" "discord_service_account" {
  account_id   = "discord-func-service-acc"
  display_name = "Discord Function Account"
}

resource "google_project_iam_member" "discord-custom-role-iam" {
  project = var.project
  role    = google_project_iam_custom_role.discord_func_role.id
  member = "serviceAccount:${google_service_account.discord_service_account.email}"
}

resource "google_project_iam_member" "discord-firestore-iam" {
  project = var.project
  role    = "roles/datastore.user"
  member = "serviceAccount:${google_service_account.discord_service_account.email}"
}

resource "google_pubsub_topic_iam_member" "member" {
  project = google_pubsub_topic.command_topic.project
  topic = google_pubsub_topic.command_topic.name
  role = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.discord_service_account.email}"
}

resource "google_secret_manager_secret_iam_member" "discord-function-member" {
  project = var.project
  secret_id = google_secret_manager_secret.ip-fetch-key.id
  role = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.discord_service_account.email}"
}

module "discord_function" {
  source                = "./modules/function"
  project               = var.project
  region                = var.region
  function_name         = "discord-function"
  function_entry_point  = "DiscordFunctionEntry"
  environment_variables = {
    "PROJECT_ID"       = var.project
    "COMMAND_TOPIC"    = google_pubsub_topic.command_topic.name
    "ADMIN_DISCORD_ID" = var.admin_discord_id
    "DISCORD_PUBKEY"   = var.discord_pubkey
    "IP_FETCH_URL"     = module.ip_fetch_function.function.https_trigger_url
    "KEY_SECRET_ID"    = google_secret_manager_secret.ip-fetch-key.id
    "LOG_WEBHOOK_URL"  = var.webhook_log
  }
  repository            = var.repository
  branch                = "main"
  source_dir            = "discord-function"
  service_account_email = google_service_account.discord_service_account.email
  trigger_http          = true
  ingress_settings      = "ALLOW_ALL"
}

# IAM entry for all users to invoke the function
resource "google_cloudfunctions_function_iam_member" "invoker" {
  project        = module.discord_function.function.project
  region         = module.discord_function.function.region
  cloud_function = module.discord_function.function.name

  role   = "roles/cloudfunctions.invoker"
  member = "allUsers"
}

# Command deployer Cloud Function
resource "google_service_account" "discord_deploy_service_account" {
  account_id   = "discord-deploy-service-acc"
  display_name = "Discord Function Account"
}

resource "google_secret_manager_secret_iam_member" "discord-deploy-member" {
  project = var.project
  secret_id = google_secret_manager_secret.secret-basic.id
  role = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.discord_deploy_service_account.email}"
}

module "discord_deploy_function" {
  source                = "./modules/function"
  project               = var.project
  region                = var.region
  function_name         = "discord-deploy-function"
  function_entry_point  = "DiscordCommandDeploy"
  environment_variables = {
    "PROJECT_ID"       = var.project
    "DISCORD_APPID"    = var.discord_app_id
    "DISCORD_SECRET_ID" = google_secret_manager_secret.secret-basic.id
  }
  repository            = var.repository
  branch                = "main"
  source_dir            = "discord-function"
  service_account_email = google_service_account.discord_deploy_service_account.email
  trigger_http          = true
  ingress_settings      = "ALLOW_INTERNAL_ONLY"
}
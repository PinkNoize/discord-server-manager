# Enable Cloud Functions API
resource "google_project_service" "cf" {
  project = var.project
  service = "cloudfunctions.googleapis.com"

  disable_dependent_services = true
  disable_on_destroy         = false
}

# Enable Cloud Build API
resource "google_project_service" "cb" {
  project = var.project
  service = "cloudbuild.googleapis.com"

  disable_dependent_services = true
  disable_on_destroy         = false
}

locals {
  repo_url = "https://source.developers.google.com/projects/${var.project}/repos/${var.repository}/moveable-aliases/${var.branch}/paths/${var.source_dir}"
}

# Create Cloud Function
resource "google_cloudfunctions_function" "function" {
  name    = var.function_name
  region  = var.region
  runtime = "go121"
  docker_registry = "ARTIFACT_REGISTRY"
  timeout = var.timeout

  available_memory_mb   = 128
  source_repository {
    url = local.repo_url
  }
  trigger_http          = var.trigger_http
  ingress_settings      = var.ingress_settings
  entry_point           = var.function_entry_point
  environment_variables = var.environment_variables
  service_account_email = var.service_account_email
  dynamic "event_trigger" {
    
     for_each = var.trigger_http == true ? toset([]) : toset([1])
    
    content {
      event_type = var.event_type
      resource   = var.event_resource
      failure_policy {
        retry = var.retry_on_failure
      }
    }
  }
  lifecycle {
    ignore_changes = [
      labels,    
    ]  
  }
}

# Cloudbuild trigger for function
resource "google_cloudbuild_trigger" "build-trigger" {
  name = "${google_cloudfunctions_function.function.name}-trigger"
  trigger_template {
    project_id  = var.project
    branch_name = "^${var.branch}$"
    repo_name   = var.repository
    dir         = var.source_dir
  }
  included_files = [ "${var.source_dir}/**" ]
  build {
    step {
      name = "gcr.io/google.com/cloudsdktool/cloud-sdk"
      args = ["gcloud", "functions", "deploy", "${google_cloudfunctions_function.function.name}", "--region=${google_cloudfunctions_function.function.region}", "--source=${local.repo_url}"]
      dir  = var.source_dir
      timeout = "600s"
    }

    source {
      repo_source {
        project_id  = var.project
        branch_name = "^${var.branch}$"
        repo_name   = var.repository
        dir         = var.source_dir
      }
    }
  }
}

output "function" {
  value = google_cloudfunctions_function.function
}
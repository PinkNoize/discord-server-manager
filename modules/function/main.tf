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
resource "google_cloudfunctions2_function" "function" {
  name     = var.function_name
  location = var.region

  build_config {
    runtime     = "go121"
    entry_point = var.function_entry_point
    source {
      repo_source {
        project_id  = var.project
        repo_name   = var.repository
        branch_name = var.branch
        dir         = var.source_dir
      }
    }
  }

  service_config {
    timeout_seconds       = var.timeout
    available_memory      = "128M"
    environment_variables = var.environment_variables
    service_account_email = var.service_account_email
    ingress_settings      = var.ingress_settings
  }
  dynamic "event_trigger" {

    for_each = var.trigger_http == true ? toset([]) : toset([1])

    content {
      event_type   = var.event_type
      pubsub_topic = var.pubsub_topic
      retry_policy = var.retry_policy
    }
  }
  # idk if I still need this
  #lifecycle {
  #  ignore_changes = [ labels ]
  #}
}

# Cloudbuild trigger for function
resource "google_cloudbuild_trigger" "build-trigger" {
  name = "${google_cloudfunctions2_function.function.name}-trigger"
  trigger_template {
    project_id  = var.project
    branch_name = "^${var.branch}$"
    repo_name   = var.repository
    dir         = var.source_dir
  }
  included_files = ["${var.source_dir}/**"]
  build {
    step {
      name    = "gcr.io/google.com/cloudsdktool/cloud-sdk"
      args    = ["gcloud", "functions", "deploy", "--gen2", "${google_cloudfunctions2_function.function.name}", "--region=${google_cloudfunctions2_function.function.location}", "--source=${local.repo_url}"]
      dir     = var.source_dir
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
  value = google_cloudfunctions2_function.function
}

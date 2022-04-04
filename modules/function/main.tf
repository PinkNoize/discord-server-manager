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

# Create Cloud Function
resource "google_cloudfunctions_function" "function" {
  name    = var.function_name
  region  = var.region
  runtime = "go116"

  available_memory_mb   = 128
  source_repository {
    url = "https://source.cloud.google.com/projects/${var.project}/repos/${var.repository}/moveable-aliases/${var.branch}/paths/${var.source_dir}"
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
    }
  }
}

output "function" {
  value = google_cloudfunctions_function.function
}
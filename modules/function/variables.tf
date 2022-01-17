variable "project" {}
variable "region" {}
variable "function_name" {}
variable "function_entry_point" {}
variable "source_dir" {}
variable "environment_variables" {}
variable "service_account_email" {
    default = null
}
variable "trigger_http" {
    default = null
}
variable "event_trigger" {
    default = null
}
variable "event_type" {
    default = null
}
variable "event_resource" {
    default = null
}
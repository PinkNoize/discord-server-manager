variable "project" {}
variable "region" {}
variable "function_name" {}
variable "function_entry_point" {}
variable "enviroment_variables" {}
variable "service_account_email" {
    default = null
}
variable "trigger_http" {
    default = null
}
variable "event_trigger" {
    default = null
}
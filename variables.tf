variable "project" {}
variable "region" {
  default = "us-west2"
}
variable "zone" {
  default = "us-west2-c"
}
variable "dns_project_id" {}
variable "dns_managed_zone" {}
variable "base_domain" {}
variable "discord_app_id" {}
variable "discord_pubkey" {}
variable "admin_discord_id" {
  default = ""
}
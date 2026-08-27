terraform {
  backend "local" {
  }
}

provider "google" {
  credentials = file("myCredentials.json")
  project = "gcp-study-340519"
}

resource "google_iap_brand" "project_brand" {
  support_email     = "acc.gcp.forstudy@gmail.com"
  application_title = " Search Ads 360 API"
  project           = "GCP-study"
}

resource "google_iap_client" "project_client" {
  display_name = "Test"
  brand        =  google_iap_brand.project_brand.name
}
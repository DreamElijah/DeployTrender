terraform {
  backend "s3" {
    bucket  = "trandrader-tf-backend-s3"
    key     = "terraform.tfstate"
    region  = "ap-southeast-1"
    encrypt = true
  }
}

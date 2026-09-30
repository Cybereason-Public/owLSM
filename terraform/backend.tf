# =============================================================================
# Terraform Backend Configuration - OCI Object Storage
# Uses native OCI backend (requires Terraform >= 1.12.0).
# Auth via local ~/.oci/config (pre-baked in runner images).
# =============================================================================

terraform {
  backend "oci" {
    bucket    = "terraform-state-owlsm"
    namespace = "id9uy08ld7kh"
    
    # Linux CI: terraform init (this key).
    # K8s CI:   terraform init -backend-config=k8s-backend.hcl -reconfigure
    key                 = "runners/terraform.tfstate"
    config_file_profile = "DEFAULT"
  }
}

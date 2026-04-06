# =============================================================================
# Terraform Backend Configuration - OCI Object Storage
# Uses native OCI backend (requires Terraform >= 1.12.0).
# Auth via local ~/.oci/config (pre-baked in runner images).
#
# The "key" is intentionally omitted here and must be supplied at init time
# via -backend-config="key=..." to isolate state per workflow run.
# =============================================================================

terraform {
  backend "oci" {
    bucket              = "terraform-state-owlsm"
    namespace           = "id9uy08ld7kh"
    config_file_profile = "DEFAULT"
  }
}

# Partial backend override. Linux CI keeps backend.tf key runners/terraform.tfstate.
# K8s CI: terraform init -backend-config=k8s-backend.hcl -reconfigure
#         terraform plan/apply -var-file=k8s-runners.tfvars.json
key = "k8s-runners/terraform.tfstate"

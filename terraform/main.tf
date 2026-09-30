# =============================================================================
# OCI GitHub Actions Runner Module
# Creates OCI compute instances and registers them as GitHub Actions runners.
# =============================================================================

locals {
  # Drop ARM (A1) shapes when enable_arm is false
  active_runners = var.enable_arm ? var.runners : {
    for key, runner in var.runners : key => runner
    if length(regexall("A1", runner.shape)) == 0
  }

  runner_display_names = {
    for key, runner in local.active_runners : key => "automation-owlsm-${runner.display_name}-${var.run_id}"
  }

  cloud_init_scripts = {
    for key, runner in local.active_runners : key => templatefile(
      "${path.module}/templates/cloud-init.sh",
      {
        runner_user      = var.runner_user
        runner_version   = var.runner_version
        github_repo_url  = var.github_repo_url
        github_pat       = var.github_pat
        runner_name      = local.runner_display_names[key]
        runner_labels    = join(",", concat(runner.runner_labels, var.runner_shared_labels, ["run-${var.run_id}"]))
        runner_group     = var.runner_group
        ephemeral_runner = var.ephemeral_runner
      }
    )
  }

  runners_with_reserved_ip = {
    for key, runner in local.active_runners : key => runner
    if can(regex("^ocid1\\.publicip\\.", try(runner.reserved_public_ip_id, "")))
  }
}

# =============================================================================
# Compute Instances
# =============================================================================

resource "oci_core_instance" "gh_runner" {
  for_each = local.active_runners

  compartment_id      = var.compartment_id
  availability_domain = var.availability_domain
  display_name        = local.runner_display_names[each.key]
  shape               = each.value.shape

  # Disable legacy IMDSv1 metadata endpoint
  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }

  # PARAVIRTUALIZED launch mode. A1 (ARM) custom images reject overriding
  # PvEncryptionInTransitEnabled — omit it there (null) and use the image default.
  launch_options {
    boot_volume_type                    = "PARAVIRTUALIZED"
    network_type                        = "PARAVIRTUALIZED"
    is_pv_encryption_in_transit_enabled = length(regexall("A1", each.value.shape)) > 0 ? null : each.value.pv_encryption_in_transit
  }

  # Flex shape configuration (CPU / memory)
  dynamic "shape_config" {
    for_each = can(regex("Flex$", each.value.shape)) ? [1] : []
    content {
      ocpus         = each.value.ocpus
      memory_in_gbs = each.value.memory_in_gbs
    }
  }

  source_details {
    source_type             = "image"
    source_id               = each.value.image_id
    boot_volume_size_in_gbs = each.value.boot_volume_gb
  }

  create_vnic_details {
    subnet_id        = var.subnet_id
    assign_public_ip = !contains(keys(local.runners_with_reserved_ip), each.key)
    display_name     = "${local.runner_display_names[each.key]}-vnic"
    nsg_ids          = var.network_security_group_ids
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data           = base64encode(local.cloud_init_scripts[each.key])
  }

  freeform_tags = merge(
    var.instance_tags,
    {
      runner-name   = local.runner_display_names[each.key]
      runner-labels = join(",", each.value.runner_labels)
      runner-key    = each.key
    }
  )

  # Prevent destroy from removing active runners accidentally
  lifecycle {
    precondition {
      condition     = length(each.value.image_id) > 0
      error_message = "image_id must not be empty for runner '${each.key}'."
    }
  }
}

data "oci_core_private_ips" "reserved" {
  for_each   = local.runners_with_reserved_ip
  ip_address = oci_core_instance.gh_runner[each.key].private_ip
  subnet_id  = var.subnet_id
}

# Attach a console-created reserved public IP. Do not create/destroy the IP
# in this state — K8s terraform destroy must only unassign it.
resource "terraform_data" "attach_reserved_public_ip" {
  for_each = local.runners_with_reserved_ip

  input = {
    public_ip_id  = each.value.reserved_public_ip_id
    private_ip_id = data.oci_core_private_ips.reserved[each.key].private_ips[0].id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      export OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True
      oci network public-ip update --force \
        --public-ip-id "${self.input.public_ip_id}" \
        --private-ip-id "${self.input.private_ip_id}"
    EOT
  }

  provisioner "local-exec" {
    when        = destroy
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      export OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True
      oci network public-ip update --force \
        --public-ip-id "${self.input.public_ip_id}" \
        --private-ip-id ""
    EOT
  }
}

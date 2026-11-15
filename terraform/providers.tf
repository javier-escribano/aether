terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.53"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.116"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    # AP05: archive_file packages the DSC configuration zip.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.6"
    }
    # AP07 (leak_mode="sas"): time_static/time_offset set the expiry
    # (start + sas_expiry_years years) of the leaked SAS -> idempotent/reset-safe.
    # Declared UNCONDITIONALLY (providers cannot be conditional);
    # only the time_* resources are gated. In leak_mode="account_key" it stays
    # declared-but-unused (zero cost). Precedent: AP05 added hashicorp/archive.
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }

  # Optional remote state (recommended for shared / multi-machine use): the local
  # tfstate holds cleartext credentials. Uncomment and fill in for an encrypted,
  # access-controlled azurerm backend. [SECURITY.md H-5]
  # backend "azurerm" {
  #   resource_group_name  = "my-tfstate-rg"
  #   storage_account_name = "mytfstatesa"
  #   container_name       = "tfstate"
  #   key                  = "aether.tfstate"
  #   use_azuread_auth     = true
  # }
}

# Pinned to the TEST tenant/subscription (see variables.tf). Terraform refuses to
# run against any other tenant; aether.ps1 also cross-checks the active az context.
provider "azuread" {
  tenant_id = var.expected_tenant_id
}

provider "azurerm" {
  tenant_id       = var.expected_tenant_id
  subscription_id = var.expected_subscription_id # null -> active az subscription (identity-only use)

  features {
    # Disposable lab RGs: let destroy/reset delete the RG even if a student created
    # extra resources in it at runtime (otherwise teardown fails and the leftovers
    # keep billing). [SECURITY.md H-7]
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
    # Purge the AP02 Key Vault on destroy so its SP secret does not linger in
    # soft-delete for 7 days. [SECURITY.md L-7]
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = false
    }
  }
}

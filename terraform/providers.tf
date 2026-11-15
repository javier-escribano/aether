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
}

# Reuses the context from `az login --tenant <test>` (see docs/00-setup.md).
provider "azuread" {}

provider "azurerm" {
  features {}
}

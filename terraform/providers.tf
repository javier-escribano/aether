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
    # AP05: archive_file empaqueta el zip de la configuracion DSC.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.6"
    }
    # AP07 (leak_mode="sas"): time_static/time_offset fijan el expiry
    # (start + sas_expiry_years anios) del SAS filtrado -> idempotencia/reset-safe.
    # Declarado INCONDICIONALMENTE (los providers no pueden ser condicionales);
    # solo los recursos time_* van gateados. En leak_mode="account_key" queda
    # declarado-pero-sin-uso (coste nulo). Precedente: AP05 anadio hashicorp/archive.
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }
}

# Reutiliza el contexto de `az login --tenant <test>` (ver docs/00-setup.md).
provider "azuread" {}

provider "azurerm" {
  features {}
}

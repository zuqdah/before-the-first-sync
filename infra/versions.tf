terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.6"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
  }
}

provider "azurerm" {
  # The other labs in this series registered providers per subscription
  # already, and a lab should not quietly change subscription-wide state.
  resource_provider_registrations = "none"

  features {
    virtual_machine {
      # The drill is torn down in the same job, so leaving disks behind would
      # bill for resources no state file remembers.
      delete_os_disk_on_deletion = true
    }
  }
}

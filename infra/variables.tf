variable "location" {
  description = "Where the forest runs. eastus2 has quota for the DASv4 family on this subscription; Bsv2 has a limit of 0, which fails at apply time rather than at plan time."
  type        = string
  default     = "eastus2"
}

variable "prefix" {
  description = "Name prefix, so a stray resource is obviously from this lab."
  type        = string
  default     = "presync"
}

variable "vm_size" {
  description = <<-EOT
    Standard_D2als_v7, because it is the size this subscription has actually
    been able to place. Quota is not the test: the v3 and v4 families have a
    quota of 10 in every region checked and were refused for "Capacity
    Restrictions" in all of them, while az vm list-skus reported no
    restriction on either. Published restrictions are subscription-level;
    whether a cluster can take the VM right now is neither published nor
    stable, so the workflow walks candidates rather than trusting one.
  EOT
  type        = string
  default     = "Standard_D2als_v7"
}

variable "admin_username" {
  description = "Local administrator account on the domain controller."
  type        = string
  default     = "forestadmin"
}

variable "domain_name" {
  description = "The on-premises forest root. Deliberately a .local name nobody can verify in a tenant, because that is the situation a real assessment finds and has to report."
  type        = string
  default     = "corp.local"
}

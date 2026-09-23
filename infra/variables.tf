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
    Standard_D2as_v4: 2 vCPU and 8 GB, which is enough to promote a domain
    controller. Checked against both `az vm list-skus` and `az vm list-usage`
    before choosing, because a SKU can be offered in a region while the
    subscription has a quota of zero for its family -- Azure reports that as
    "Capacity Restrictions", which reads like a transient shortage rather than
    a limit on the account. Bsv2 and DASv5 are both at zero here.
  EOT
  type        = string
  default     = "Standard_D2as_v4"
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

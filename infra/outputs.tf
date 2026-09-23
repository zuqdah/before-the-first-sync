output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "vm_name" {
  value = azurerm_windows_virtual_machine.dc.name
}

output "domain_name" {
  value = var.domain_name
}

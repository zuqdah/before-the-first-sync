resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false

  keepers = {
    location = var.location
  }
}

resource "random_password" "admin" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${var.prefix}-${random_string.suffix.result}"
  location = var.location
}

resource "azurerm_virtual_network" "lab" {
  name                = "vnet-${var.prefix}"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  address_space       = ["10.50.0.0/16"]
}

resource "azurerm_subnet" "dc" {
  name                 = "snet-dc"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.50.1.0/24"]
}

# Deny everything inbound. The assessment reaches the machine through the Azure
# guest agent via Run Command, which needs no inbound rule and no public
# address, so a domain controller in this lab is never reachable from the
# internet at all. Opening RDP "just for troubleshooting" is how a lab
# domain controller ends up in somebody's botnet.
resource "azurerm_network_security_group" "dc" {
  name                = "nsg-${var.prefix}-dc"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location

  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "dc" {
  subnet_id                 = azurerm_subnet.dc.id
  network_security_group_id = azurerm_network_security_group.dc.id
}

resource "azurerm_network_interface" "dc" {
  name                = "nic-${var.prefix}-dc"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.dc.id
    private_ip_address_allocation = "Static"
    # Fixed, because a domain controller answers DNS for the forest and its own
    # resolver has to point at itself once it is promoted.
    private_ip_address = "10.50.1.10"
  }
}

resource "azurerm_windows_virtual_machine" "dc" {
  name                = "vm-${var.prefix}-dc"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  size                = var.vm_size
  admin_username      = var.admin_username
  admin_password      = random_password.admin.result

  network_interface_ids = [azurerm_network_interface.dc.id]

  # StandardSSD rather than Premium. The forest lives for twenty minutes and
  # holds thirty objects; paying for provisioned IOPS would be paying for a
  # benchmark nobody is running.
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }

  # No boot diagnostics storage account. Run Command returns what the scripts
  # print, and a serial console nobody reads is another resource to tear down.
  patch_mode = "Manual"

  tags = {
    lab = var.prefix
  }
}

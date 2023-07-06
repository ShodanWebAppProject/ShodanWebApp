variable "resource_group_location" {
  type        = string
  default     = "northeurope"
  description = "Location of the resource group."
}

variable "node_count" {
  type        = number
  description = "The initial quantity of nodes for the node pool."
  default     = 3
}

variable "msi_id" {
  type        = string
  description = "The Managed Service Identity ID. Set this value if you're running this example using Managed Identity as the authentication method."
  default     = null
}

variable "azurerm_resource_group_name"{
  type        = string
  default     = "srs2023-stu-g8"
  description = "Name of the resource group."
}

variable azurerm_kubernetes_cluster_name{
  type        = string
  default     = "cluster-elegant-crow"
  description = "Name of the k8s cluster."
}
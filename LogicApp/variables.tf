variable "location" {
    type        = string
    description = "Location of all resources"
}

variable "resourceGroupName" {
    type = string
}

variable "storageAccountName" {
    type = string
}

variable "serviceBusName" {
    type = string
}

variable "stage" {
    type = string
}

variable "tags" {
    type = map(string)
    default = {}
}
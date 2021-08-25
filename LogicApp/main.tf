resource "azurerm_resource_group_template_deployment" "LogicApp" {
    name                = "LogicAppDeployment"
    resource_group_name = var.resourceGroupName
    deployment_mode     = "Incremental"

    template_content = file("${path.module}/logicapp.json")
    parameters_content = jsonencode(
        {
            "workflow_name": {
                "value": "${join("-",["mailservice",var.stage,"la"])}",
            },
            "azureblob_accountName": {
                "value": "${var.storageAccountName}",
            },
            "servicebus_name": {
                "value": "${var.serviceBusName}",
            },
            "connections_azureblob_name": {
                "value": "azureblob",
            },
            "connections_office365_name": {
                "value": "office365",
            },
            "connections_servicebus_name": {
                "value": "servicebus",
            }
        }
    )
}
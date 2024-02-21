#!/bin/sh

$YQ -i '.version = strenv(VERSION), .appVersion = strenv(VERSION)' chart/Chart.yaml
$YQ -i '.name = "dns-resolution-operator", .description = "An operator to generate egress NetworkPolicies with resolved IP addresses"' chart/Chart.yaml
$YQ -i '.controllerManager.manager.image.tag = "v"+strenv(VERSION)' chart/values.yaml
$YQ -i '.controllerManager.manager.env = {}' chart/values.yaml
$YQ -i '(.controllerManager.manager.env | key) head_comment="Additional environment variables of the controller as key-value pairs\nFor example:\nIP_EXPIRATION: 30s"' chart/values.yaml

patch chart/templates/deployment.yaml env.patch

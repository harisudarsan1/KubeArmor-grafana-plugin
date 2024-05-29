package models

import (
	"github.com/grafana/grafana-plugin-sdk-go/data"
)

var EdgeframeFields = []FrameFieldType{
	{
		Name: "id",
		Type: data.FieldTypeString,
	},
	{
		Name: "source",
		Type: data.FieldTypeString,
	},
	{
		Name: "target",
		Type: data.FieldTypeString,
	},

	{
		Name: "mainstat",
		Type: data.FieldTypeString,
	},

	{
		Name:        "detail__Count",
		Type:        data.FieldTypeString,
		DisplayName: "Request Count",
	},
}

// Define the equivalent Go representation of NodeframeFields
var NetworkNodeframeFields = []FrameFieldType{
	{
		Name: "id",
		Type: data.FieldTypeString,
	},
	{
		Name: "title",
		Type: data.FieldTypeString,
	},
	{
		Name: "mainstat",
		Type: data.FieldTypeString,
	},
	{
		Name: "color",
		Type: data.FieldTypeString,
	},

	{
		Name:        "detail__ResourceName",
		Type:        data.FieldTypeString,
		DisplayName: "ResourceName",
	},

	{
		Name:        "detail__NamespaceName",
		Type:        data.FieldTypeString,
		DisplayName: "Namespace",
	},
}

var NodeframeFields = []FrameFieldType{
	{
		Name: "id",
		Type: data.FieldTypeString,
	},
	{
		Name: "title",
		Type: data.FieldTypeString,
	},
	{
		Name: "mainstat",
		Type: data.FieldTypeString,
	},
	{
		Name: "color",
		Type: data.FieldTypeString,
	},
	// {
	// 	Name: "nodeRadius",
	// 	Type: data.FieldTypeString,
	// },
	// {
	// 	Name: "highlighted",
	// 	Type: data.FieldTypeBool,
	// },
	// {
	// 	Name:        "detail__Timestamp",
	// 	Type:        data.FieldTypeInt64,
	// 	DisplayName: "Timestamp",
	// },
	// {
	// 	Name:        "detail__ChildNode",
	// 	Type:        data.FieldTypeString,
	// 	DisplayName: "Updated Time",
	// },
	{
		Name:        "detail__ClusterName",
		Type:        data.FieldTypeString,
		DisplayName: "Cluster Name",
	},
	{
		Name:        "detail__HostName",
		Type:        data.FieldTypeString,
		DisplayName: "Host Name",
	},
	{
		Name:        "detail__NamespaceName",
		Type:        data.FieldTypeString,
		DisplayName: "Namespace Name",
	},
	{
		Name:        "detail__PodName",
		Type:        data.FieldTypeString,
		DisplayName: "Pod Name",
	},
	{
		Name:        "detail__Labels",
		Type:        data.FieldTypeString,
		DisplayName: "Labels",
	},
	{
		Name:        "detail__ContainerID",
		Type:        data.FieldTypeString,
		DisplayName: "Container ID",
	},
	{
		Name:        "detail__ContainerName",
		Type:        data.FieldTypeString,
		DisplayName: "Container Name",
	},
	{
		Name:        "detail__ContainerImage",
		Type:        data.FieldTypeString,
		DisplayName: "Container Image",
	},
	{
		Name:        "detail__ParentProcessName",
		Type:        data.FieldTypeString,
		DisplayName: "Parent Process Name",
	},
	{
		Name:        "detail__ProcessName",
		Type:        data.FieldTypeString,
		DisplayName: "Process Name",
	},
	{
		Name:        "detail__HostPPID",
		Type:        data.FieldTypeInt64,
		DisplayName: "Host PPID",
	},
	{
		Name:        "detail__HostPID",
		Type:        data.FieldTypeInt64,
		DisplayName: "Host PID",
	},
	{
		Name:        "detail__PPID",
		Type:        data.FieldTypeInt64,
		DisplayName: "PPID",
	},
	{
		Name:        "detail__PID",
		Type:        data.FieldTypeInt64,
		DisplayName: "PID",
	},
	{
		Name:        "detail__UID",
		Type:        data.FieldTypeInt64,
		DisplayName: "UID",
	},
	{
		Name:        "detail__Type",
		Type:        data.FieldTypeString,
		DisplayName: "Type",
	},
	{
		Name:        "detail__Source",
		Type:        data.FieldTypeString,
		DisplayName: "Source",
	},
	{
		Name:        "detail__Operation",
		Type:        data.FieldTypeString,
		DisplayName: "Operation",
	},
	{
		Name:        "detail__Resource",
		Type:        data.FieldTypeString,
		DisplayName: "Resource",
	},
	{
		Name:        "detail__Data",
		Type:        data.FieldTypeString,
		DisplayName: "Data",
	},
	{
		Name:        "detail__Result",
		Type:        data.FieldTypeString,
		DisplayName: "Result",
	},
	{
		Name:        "detail__Cwd",
		Type:        data.FieldTypeString,
		DisplayName: "Cwd",
	},
	{
		Name:        "detail__TTY",
		Type:        data.FieldTypeString,
		DisplayName: "TTY",
	},
}

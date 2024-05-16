package models

import (
// "github.com/grafana/grafana-plugin-sdk-go/data"
)

// Define the equivalent Go representation of NodeframeFields
var NodeframeFields = []FrameFieldType{
	{
		Name:   "id",
		Type:   "string",
		Config: make(map[string]string),
	},
	{
		Name:   "title",
		Type:   "string",
		Config: make(map[string]string),
	},
	{
		Name:   "mainStat",
		Type:   "string",
		Config: make(map[string]string),
	},
	{
		Name:   "color",
		Type:   "string",
		Config: make(map[string]string),
	},
	{
		Name:   "nodeRadius",
		Type:   "string",
		Config: make(map[string]string),
	},
	{
		Name:   "highlighted",
		Type:   "boolean",
		Config: make(map[string]string),
	},
	{
		Name: "detail__Timestamp",
		Type: "number",
		Config: map[string]string{
			"displayName": "Timestamp",
		},
	},
	{
		Name: "detail__UpdatedTime",
		Type: "string",
		Config: map[string]string{
			"displayName": "Updated Time",
		},
	},
	{
		Name: "detail__ClusterName",
		Type: "string",
		Config: map[string]string{
			"displayName": "Cluster Name",
		},
	},
	{
		Name: "detail__HostName",
		Type: "string",
		Config: map[string]string{
			"displayName": "Host Name",
		},
	},
	{
		Name: "detail__NamespaceName",
		Type: "string",
		Config: map[string]string{
			"displayName": "Namespace Name",
		},
	},
	{
		Name: "detail__PodName",
		Type: "string",
		Config: map[string]string{
			"displayName": "Pod Name",
		},
	},
	{
		Name: "detail__Labels",
		Type: "string",
		Config: map[string]string{
			"displayName": "Labels",
		},
	},
	{
		Name: "detail__ContainerID",
		Type: "string",
		Config: map[string]string{
			"displayName": "Container ID",
		},
	},
	{
		Name: "detail__ContainerName",
		Type: "string",
		Config: map[string]string{
			"displayName": "Container Name",
		},
	},
	{
		Name: "detail__ContainerImage",
		Type: "string",
		Config: map[string]string{
			"displayName": "Container Image",
		},
	},
	{
		Name: "detail__ParentProcessName",
		Type: "string",
		Config: map[string]string{
			"displayName": "Parent Process Name",
		},
	},
	{
		Name: "detail__ProcessName",
		Type: "string",
		Config: map[string]string{
			"displayName": "Process Name",
		},
	},
	{
		Name: "detail__HostPPID",
		Type: "number",
		Config: map[string]string{
			"displayName": "Host PPID",
		},
	},
	{
		Name: "detail__HostPID",
		Type: "number",
		Config: map[string]string{
			"displayName": "Host PID",
		},
	},
	{
		Name: "detail__PPID",
		Type: "number",
		Config: map[string]string{
			"displayName": "PPID",
		},
	},
	{
		Name: "detail__PID",
		Type: "number",
		Config: map[string]string{
			"displayName": "PID",
		},
	},
	{
		Name: "detail__UID",
		Type: "number",
		Config: map[string]string{
			"displayName": "UID",
		},
	},
	{
		Name: "detail__Type",
		Type: "string",
		Config: map[string]string{
			"displayName": "Type",
		},
	},
	{
		Name: "detail__Source",
		Type: "string",
		Config: map[string]string{
			"displayName": "Source",
		},
	},
	{
		Name: "detail__Operation",
		Type: "string",
		Config: map[string]string{
			"displayName": "Operation",
		},
	},
	{
		Name: "detail__Resource",
		Type: "string",
		Config: map[string]string{
			"displayName": "Resource",
		},
	},
	{
		Name: "detail__Data",
		Type: "string",
		Config: map[string]string{
			"displayName": "Data",
		},
	},
	{
		Name: "detail__Result",
		Type: "string",
		Config: map[string]string{
			"displayName": "Result",
		},
	},
	{
		Name: "detail__Cwd",
		Type: "string",
		Config: map[string]string{
			"displayName": "Cwd",
		},
	},
	{
		Name: "detail__TTY",
		Type: "string",
		Config: map[string]string{
			"displayName": "TTY",
		},
	},
}

// Print the converted Go structure

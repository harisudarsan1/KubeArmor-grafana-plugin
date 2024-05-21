package models

import (
	"github.com/grafana/grafana-plugin-sdk-go/data"
)

var EdgeframeFields = []FrameFieldType{
	{
		Name:   "id",
		Type:   data.FieldTypeString,
		Config: make(map[string]string),
	},
	{
		Name:   "source",
		Type:   data.FieldTypeString,
		Config: make(map[string]string),
	},
	{
		Name:   "target",
		Type:   data.FieldTypeString,
		Config: make(map[string]string),
	},
}

// Define the equivalent Go representation of NodeframeFields
var NetworkNodeframeFields = []FrameFieldType{

	{
		Name:   "id",
		Type:   data.FieldTypeString,
		Config: make(map[string]string),
	},
	{
		Name:   "title",
		Type:   data.FieldTypeString,
		Config: make(map[string]string),
	},
	{
		Name:   "mainStat",
		Type:   data.FieldTypeString,
		Config: make(map[string]string),
	},
	{
		Name:   "color",
		Type:   data.FieldTypeString,
		Config: make(map[string]string),
	},
}

var NodeframeFields = []FrameFieldType{
	{
		Name:   "id",
		Type:   data.FieldTypeString,
		Config: make(map[string]string),
	},
	{
		Name:   "title",
		Type:   data.FieldTypeString,
		Config: make(map[string]string),
	},
	{
		Name:   "mainStat",
		Type:   data.FieldTypeString,
		Config: make(map[string]string),
	},
	{
		Name:   "color",
		Type:   data.FieldTypeString,
		Config: make(map[string]string),
	},
	// {
	// 	Name:   "nodeRadius",
	// 	Type:   data.FieldTypeString,
	// 	Config: make(map[string]string),
	// },
	// {
	// 	Name:   "highlighted",
	// 	Type:   data.FieldTypeBool,
	// 	Config: make(map[string]string),
	// },
	// {
	// 	Name: "detail__Timestamp",
	// 	Type: data.FieldTypeInt64,
	// 	Config: map[string]string{
	// 		"displayName": "Timestamp",
	// 	},
	// },
	// {
	// 	Name: "detail__ChildNode",
	// 	Type: data.FieldTypeString,
	// 	Config: map[string]string{
	// 		"displayName": "Updated Time",
	// 	},
	// },
	{
		Name: "detail__ClusterName",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Cluster Name",
		},
	},
	{
		Name: "detail__HostName",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Host Name",
		},
	},
	{
		Name: "detail__NamespaceName",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Namespace Name",
		},
	},
	{
		Name: "detail__PodName",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Pod Name",
		},
	},
	{
		Name: "detail__Labels",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Labels",
		},
	},
	{
		Name: "detail__ContainerID",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Container ID",
		},
	},
	{
		Name: "detail__ContainerName",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Container Name",
		},
	},
	{
		Name: "detail__ContainerImage",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Container Image",
		},
	},
	{
		Name: "detail__ParentProcessName",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Parent Process Name",
		},
	},
	{
		Name: "detail__ProcessName",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Process Name",
		},
	},
	{
		Name: "detail__HostPPID",
		Type: data.FieldTypeInt64,
		Config: map[string]string{
			"displayName": "Host PPID",
		},
	},
	{
		Name: "detail__HostPID",
		Type: data.FieldTypeInt64,
		Config: map[string]string{
			"displayName": "Host PID",
		},
	},
	{
		Name: "detail__PPID",
		Type: data.FieldTypeInt64,
		Config: map[string]string{
			"displayName": "PPID",
		},
	},
	{
		Name: "detail__PID",
		Type: data.FieldTypeInt64,
		Config: map[string]string{
			"displayName": "PID",
		},
	},
	{
		Name: "detail__UID",
		Type: data.FieldTypeInt64,
		Config: map[string]string{
			"displayName": "UID",
		},
	},
	{
		Name: "detail__Type",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Type",
		},
	},
	{
		Name: "detail__Source",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Source",
		},
	},
	{
		Name: "detail__Operation",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Operation",
		},
	},
	{
		Name: "detail__Resource",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Resource",
		},
	},
	{
		Name: "detail__Data",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Data",
		},
	},
	{
		Name: "detail__Result",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Result",
		},
	},
	{
		Name: "detail__Cwd",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "Cwd",
		},
	},
	{
		Name: "detail__TTY",
		Type: data.FieldTypeString,
		Config: map[string]string{
			"displayName": "TTY",
		},
	},
}

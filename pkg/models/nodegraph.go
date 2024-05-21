package models

import "github.com/grafana/grafana-plugin-sdk-go/data"

type NodeGraph struct {
	Nodes []NodeFields
	Edges []EdgeFields
}

type FrameFieldType struct {
	Name   string            `json:"name"`
	Type   data.FieldType    `json:"type"`
	Config map[string]string `json:"config"`
}

type NodeFields struct {
	ID        string `json:"id"`
	Title     string `json:"title,omitempty"`
	MainStat  string `json:"mainStat,omitempty"`
	Color     string `json:"color,omitempty"`
	ChildNode string `json:"childNode,omitempty"`
	// NodeRadius  string `json:"nodeRadius,omitempty"`
	// Highlighted bool   `json:"highlighted,omitempty"`

	DetailClusterName       string `json:"detail__ClusterName,omitempty"`
	DetailHostName          string `json:"detail__HostName,omitempty"`
	DetailNamespaceName     string `json:"detail__NamespaceName,omitempty"`
	DetailPodName           string `json:"detail__PodName,omitempty"`
	DetailLabels            string `json:"detail__Labels,omitempty"`
	DetailContainerID       string `json:"detail__ContainerID,omitempty"`
	DetailContainerName     string `json:"detail__ContainerName,omitempty"`
	DetailContainerImage    string `json:"detail__ContainerImage,omitempty"`
	DetailParentProcessName string `json:"detail__ParentProcessName,omitempty"`
	DetailProcessName       string `json:"detail__ProcessName,omitempty"`
	DetailHostPPID          int64  `json:"detail__HostPPID,omitempty"`
	DetailHostPID           int64  `json:"detail__HostPID,omitempty"`
	DetailPPID              int64  `json:"detail__PPID,omitempty"`
	DetailPID               int64  `json:"detail__PID,omitempty"`
	DetailUID               int64  `json:"detail__UID,omitempty"`
	DetailType              string `json:"detail__Type,omitempty"`
	DetailSource            string `json:"detail__Source,omitempty"`
	DetailOperation         string `json:"detail__Operation,omitempty"`
	DetailResource          string `json:"detail__Resource,omitempty"`
	DetailData              string `json:"detail__Data,omitempty"`
	DetailResult            string `json:"detail__Result,omitempty"`
	DetailCwd               string `json:"detail__Cwd,omitempty"`
	DetailTTY               string `json:"detail__TTY,omitempty"`
}

// type KubeArmorLogs struct {
// 	DetailTimestamp         int    `json:"detail__Timestamp,omitempty"`
// 	DetailClusterName       string `json:"detail__ClusterName,omitempty"`
// 	DetailHostName          string `json:"detail__HostName,omitempty"`
// 	DetailNamespaceName     string `json:"detail__NamespaceName,omitempty"`
// 	DetailPodName           string `json:"detail__PodName,omitempty"`
// 	DetailLabels            string `json:"detail__Labels,omitempty"`
// 	DetailContainerID       string `json:"detail__ContainerID,omitempty"`
// 	DetailContainerName     string `json:"detail__ContainerName,omitempty"`
// 	DetailContainerImage    string `json:"detail__ContainerImage,omitempty"`
// 	DetailParentProcessName string `json:"detail__ParentProcessName,omitempty"`
// 	DetailProcessName       string `json:"detail__ProcessName,omitempty"`
// 	DetailHostPPID          int    `json:"detail__HostPPID,omitempty"`
// 	DetailHostPID           int    `json:"detail__HostPID,omitempty"`
// 	DetailPPID              int    `json:"detail__PPID,omitempty"`
// 	DetailPID               int    `json:"detail__PID,omitempty"`
// 	DetailUID               int    `json:"detail__UID,omitempty"`
// 	DetailType              string `json:"detail__Type,omitempty"`
// 	DetailSource            string `json:"detail__Source,omitempty"`
// 	DetailOperation         string `json:"detail__Operation,omitempty"`
// 	DetailResource          string `json:"detail__Resource,omitempty"`
// 	DetailData              string `json:"detail__Data,omitempty"`
// 	DetailResult            string `json:"detail__Result,omitempty"`
// 	DetailCwd               string `json:"detail__Cwd,omitempty"`
// 	DetailTTY               string `json:"detail__TTY,omitempty"`
// }

type Podowner struct {
	Ref       string `json:"ref"`
	Name      string `json:"Name"`
	Namespace string `json:"Namespace"`
}

type EdgeFields struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
}

type Hits struct {
	Index  string `json:"_index"`
	Type   string `json:"_type"`
	ID     string `json:"_id"`
	Score  int    `json:"_score"`
	Source Log    `json:"_source"`
}

type Shards struct {
	Total      int `json:"total"`
	Successful int `json:"successful"`
	Skipped    int `json:"skipped"`
	Failed     int `json:"failed"`
}

type Total struct {
	Value    int    `json:"value"`
	Relation string `json:"relation"`
}

type ElasticsearchResponse struct {
	Took     int    `json:"took"`
	TimedOut bool   `json:"timed_out"`
	Shards   Shards `json:"_shards"`
	Hits     struct {
		Total    Total  `json:"total"`
		MaxScore int    `json:"max_score"`
		Hits     []Hits `json:"hits"`
	} `json:"hits"`
}

type LokiSearchResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string        `json:"resultType"`
		Result     []LokiResults `json:"result"`
		Stats      interface{}   `json:"stats"`
	} `json:"Data"`
}

type LokiResults struct {
	Stream Stream      `json:"stream"`
	Values interface{} `json:"values"`
}

type Stream struct {
	BodyClusterName       string `json:"body_ClusterName"`
	BodyContainerID       string `json:"body_ContainerID"`
	BodyContainerImage    string `json:"body_ContainerImage"`
	BodyContainerName     string `json:"body_ContainerName"`
	BodyCwd               string `json:"body_Cwd"`
	BodyData              string `json:"body_Data"`
	BodyHostName          string `json:"body_HostName"`
	BodyHostPID           string `json:"body_HostPID"`
	BodyHostPPID          string `json:"body_HostPPID"`
	BodyLabels            string `json:"body_Labels"`
	BodyNamespaceName     string `json:"body_NamespaceName"`
	BodyOperation         string `json:"body_Operation"`
	BodyOwnerName         string `json:"body_Owner_Name"`
	BodyOwnerNamespace    string `json:"body_Owner_Namespace"`
	BodyOwnerRef          string `json:"body_Owner_Ref"`
	BodyPID               string `json:"body_PID"`
	BodyPPID              string `json:"body_PPID"`
	BodyParentProcessName string `json:"body_ParentProcessName"`
	BodyPodName           string `json:"body_PodName"`
	BodyProcessName       string `json:"body_ProcessName"`
	BodyResource          string `json:"body_Resource"`
	BodyResult            string `json:"body_Result"`
	BodySource            string `json:"body_Source"`
	BodyType              string `json:"body_Type"`
	BodyUID               string `json:"body_UID"`
	BodyUpdatedTime       string `json:"body_UpdatedTime"`
	BodyTTY               string `json:"body_TTY,omitempty"`
	Exporter              string `json:"exporter,omitempty"`
}

type Log struct {
	Timestamp         int      `json:"Timestamp,omitempty"`
	UpdatedTime       string   `json:"UpdatedTime"`
	ClusterName       string   `json:"ClusterName"`
	HostName          string   `json:"HostName"`
	NamespaceName     string   `json:"NamespaceName"`
	Owner             Podowner `json:"Owner"`
	PodName           string   `json:"PodName"`
	Labels            string   `json:"Labels"`
	ContainerID       string   `json:"ContainerID"`
	ContainerName     string   `json:"ContainerName"`
	ContainerImage    string   `json:"ContainerImage"`
	ParentProcessName string   `json:"ParentProcessName"`
	ProcessName       string   `json:"ProcessName"`
	HostPPID          int      `json:"HostPPID"`
	HostPID           int      `json:"HostPID"`
	PPID              int      `json:"PPID"`
	PID               int      `json:"PID"`
	UID               int      `json:"UID"`
	Type              string   `json:"Type"`
	Source            string   `json:"Source"`
	Operation         string   `json:"Operation"`
	Resource          string   `json:"Resource"`
	Data              string   `json:"Data"`
	Result            string   `json:"Result"`
	Cwd               string   `json:"Cwd"`
	TTY               string   `json:"TTY,omitempty"`
}

type HealthResponse struct {
	ClusterName string `json:"cluster_name"`
	Status      string `json:"status"`
	TimedOut    bool
}

type NetworkData struct {
	NetworkType string `json:"networkType"`
	SockType    string `json:"socktype"`

	Kprobe   string `json:"kprobe,omitempty"`
	Domain   string `json:"domain,omitempty"`
	RemoteIP string `json:"remoteIP,omitempty"`
	Port     string `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

type NetworkGraph struct {
	NData  NetworkData `json:"ndata,omitempty"`
	ID     string      `json:"id,omitempty"`
	Source NodeFields  `json:"source,omitempty"`
	Target NodeFields  `json:"target,omitempty"`
}

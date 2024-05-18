package plugin

import (
	"context"
	"encoding/json"
	"fmt"

	// "io"
	"net/http"
	// "time"

	"github.com/accuknox/kubearmor-plugin/pkg/models"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana-plugin-sdk-go/backend/instancemgmt"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"github.com/grafana/grafana-plugin-sdk-go/data"
)

// Make sure Datasource implements required interfaces. This is important to do
// since otherwise we will only get a not implemented error response from plugin in
// runtime. In this example datasource instance implements backend.QueryDataHandler,
// backend.CheckHealthHandler interfaces. Plugin should not implement all these
// interfaces - only those which are required for a particular task.
var (
	_ backend.QueryDataHandler      = (*Datasource)(nil)
	_ backend.CheckHealthHandler    = (*Datasource)(nil)
	_ instancemgmt.InstanceDisposer = (*Datasource)(nil)
)
var Backend string = ""
var NodeRows int = 1
var EdgeRows int = 1

const (
	pts0   = "pts0"
	denied = "Permission denied"
)

// NewDatasource creates a new datasource instance.
func NewDatasource(ctx context.Context, settings backend.DataSourceInstanceSettings) (instancemgmt.Instance, error) {

	opts, err := settings.HTTPClientOptions(ctx)
	if err != nil {
		return nil, fmt.Errorf("http client options: %w", err)
	}
	PluginSettings, err := models.LoadPluginSettings(settings)

	if err != nil {
		return nil, fmt.Errorf("Error in plugin settings: %w", err)
	}

	Backend = PluginSettings.Backend

	cl, err := httpclient.New(opts)
	if err != nil {
		return nil, fmt.Errorf("httpclient new: %w", err)
	}
	return &Datasource{
		settings:   settings,
		httpClient: cl,
	}, nil
}

// Datasource is an example datasource which can respond to data queries, reports
// its health and has streaming skills.
type Datasource struct {
	settings backend.DataSourceInstanceSettings

	httpClient *http.Client
}

// Dispose here tells plugin SDK that plugin wants to clean up resources when a new instance
// created. As soon as datasource settings change detected by SDK old datasource instance will
// be disposed and a new one will be created using NewSampleDatasource factory function.
func (d *Datasource) Dispose() {
	// Clean up datasource instance resources.
	d.httpClient.CloseIdleConnections()
}

// QueryData handles multiple queries and returns multiple responses.
// req contains the queries []DataQuery (where each query contains RefID as a unique identifier).
// The QueryDataResponse contains a map of RefID to the response for each query, and each response
// contains Frames ([]*Frame).

func (d *Datasource) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	// create response struct
	response := backend.NewQueryDataResponse()

	// loop over queries and execute them individually.
	for _, q := range req.Queries {
		res := d.query(ctx, req.PluginContext, q)

		// save the response in a hashmap
		// based on with RefID as identifier
		response.Responses[q.RefID] = res

	}

	return response, nil
}

type queryModel struct {
	NamespaceQuery string `json:"NamespaceQuery,omitempty"`
	LabelQuery     string `json:"LabelQuery,omitempty"`
	Operation      string `json:"Operation"`
}

func (d *Datasource) query(ctx context.Context, _ backend.PluginContext, q backend.DataQuery) backend.DataResponse {
	var response backend.DataResponse

	// Unmarshal the JSON into our queryModel.
	var qm queryModel

	ctxLogger := log.DefaultLogger.FromContext(ctx)

	err := json.Unmarshal(q.JSON, &qm)
	if err != nil {
		ctxLogger.Error("Error while marshalling the query json")
		return backend.ErrDataResponse(backend.StatusBadRequest, fmt.Sprintf("json unmarshal: %v", err.Error()))
	} else {
		ctxLogger.Info("Query json is sucessfully marshalled operation: ")
	}

	Nodegraph, tot, tty := getGraphData(ctx, d, qm)
	NodeRows = len(Nodegraph.Nodes)
	EdgeRows = len(Nodegraph.Edges)

	Nodefields := getNodeFields(qm)
	EdgeFields := getEdgeFields()

	Nodeframe := data.NewFrame("Nodes")
	Nodeframe.Fields = Nodefields
	EdgeFrame := data.NewFrame("Edges")
	EdgeFrame.Fields = EdgeFields

	edgetest := models.EdgeFields{
		ID:     "id",
		Source: qm.NamespaceQuery,
		Target: qm.Operation,
	}
	EdgeFrame.AppendRow(tty, string(qm.NamespaceQuery), fmt.Sprintf("%d", tot))
	EdgeFrame.AppendRow(edgetest.ID, edgetest.Source, edgetest.Target)

	var frameMeta = data.FrameMeta{
		PreferredVisualization: data.VisTypeNodeGraph,
	}
	Nodeframe.SetMeta(&frameMeta)
	EdgeFrame.SetMeta(&frameMeta)
	// EdgeFrame := data.NewFrame("Edges")
	// add the frames to the response.

	for _, node := range Nodegraph.Nodes {
		if qm.Operation == "Process" {

			Nodeframe.AppendRow(
				node.ID,
				node.Title,
				node.MainStat,
				node.Color,
				node.ChildNode,
				// node.NodeRadius,
				// node.Highlighted,
				// int64(node.DetailTimestamp),
				node.DetailClusterName,
				node.DetailHostName,
				node.DetailNamespaceName,
				node.DetailPodName,
				node.DetailLabels,
				node.DetailContainerID,
				node.DetailContainerName,
				node.DetailContainerImage,
				node.DetailParentProcessName,
				node.DetailProcessName,
				int64(node.DetailHostPPID),
				int64(node.DetailHostPID),
				int64(node.DetailPPID),
				int64(node.DetailPID),
				int64(node.DetailUID),
				node.DetailType,
				node.DetailSource,
				node.DetailOperation,
				node.DetailResource,
				node.DetailData,
				node.DetailResult,
				node.DetailCwd,
				node.DetailTTY,
			)
		} else if qm.Operation == "Network" {

			Nodeframe.AppendRow(
				node.ID,
				node.Title,
				node.MainStat,
				node.Color,
				node.ChildNode,
				// node.NodeRadius,
				// node.Highlighted,
				// node.DetailTimestamp,
				node.DetailClusterName,
				node.DetailHostName,
				node.DetailNamespaceName,
				node.DetailPodName,
				node.DetailLabels,
				node.DetailContainerID,
				node.DetailContainerName,
				node.DetailContainerImage,
				node.DetailParentProcessName,
				node.DetailProcessName,
				int64(node.DetailHostPPID),
				int64(node.DetailHostPID),
				int64(node.DetailPPID),
				int64(node.DetailPID),
				int64(node.DetailUID),
				node.DetailType,
				node.DetailSource,
				node.DetailOperation,
				node.DetailResource,
				node.DetailData,
				node.DetailResult,
				node.DetailCwd,
			)
		}
	}

	for _, edge := range Nodegraph.Edges {
		EdgeFrame.AppendRow(edge.ID, edge.Source, edge.Target)
	}

	response.Frames = append(response.Frames, Nodeframe)
	response.Frames = append(response.Frames, EdgeFrame)

	return response
}

func getNodeFields(_ queryModel) []*data.Field {

	fields := make([]*data.Field, len(models.NodeframeFields))
	for i, field := range models.NodeframeFields {
		// if qm.Operation == "Network" && field.Name == "detail__TTY" {
		// 	continue
		// }
		f := data.NewFieldFromFieldType(field.Type, 0)
		f.Name = field.Name
		fields[i] = f

	}

	return fields
}

func getEdgeFields() []*data.Field {

	fields := make([]*data.Field, len(models.EdgeframeFields))
	for i, field := range models.EdgeframeFields {
		f := data.NewFieldFromFieldType(field.Type, 0)
		f.Name = field.Name

		fields[i] = f

	}

	return fields
}

func getGraphData(ctx context.Context, datasource *Datasource, MyQuery queryModel) (models.NodeGraph, int, string) {

	ctxLogger := log.DefaultLogger.FromContext(ctx)
	var endpoint = ""
	var logs = []models.Log{}
	var total = 0

	var TTY = ""
	switch Backend {
	case "ELASTICSEARCH":
		endpoint = "/_search?size=1000&pretty"
		// if MyQuery.Operation == "Process" {
		// 	endpoint = endpoint + "&q=TTY:pts0"
		// } else {
		//
		// 	endpoint = endpoint + "&q=Operation=Network"
		// }

		datasourceURL := datasource.settings.URL + endpoint
		// Do HTTP request
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, datasourceURL, nil)

		if err != nil {
			ctxLogger.Error("request error :", err)
		}

		resp, err := datasource.httpClient.Do(req)
		if err != nil {
			ctxLogger.Error("load settings: failed to load settings")
			return models.NodeGraph{}, 0, ""
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				ctxLogger.Error("check health: failed to close response body", "err", err.Error())
			}
		}()
		var ESResponse models.ElasticsearchResponse

		if err := json.NewDecoder(resp.Body).Decode(&ESResponse); err != nil {

		}
		for _, item := range ESResponse.Hits.Hits {
			logs = append(logs, item.Source)
			TTY = item.Source.TTY
		}
		total = len(logs)
		break
	case "LOKI":
		endpoint = "/"

		if MyQuery.Operation == "Operation" {
			endpoint = endpoint + "body_TTY='pts0'|json"
		} else {

			endpoint = endpoint + "&q=Operation=Network|json"
		}

		datasourceURL := datasource.settings.URL + endpoint
		// Do HTTP request
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, datasourceURL, nil)

		if err != nil {
			fmt.Errorf("request error :%w", err)
		}
		resp, err := datasource.httpClient.Do(req)
		defer func() {
			if err := resp.Body.Close(); err != nil {
				ctxLogger.Error("check health: failed to close response body %w", err.Error())
			}
		}()
		var LokiResponse models.LokiSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&LokiResponse); err != nil {

		}
		for _, item := range LokiResponse.Data.Result {
			var log = models.Log{}
			log.UpdatedTime = item.Stream.BodyUpdatedTime
			log.UpdatedTime = item.Stream.BodyUpdatedTime
			log.ClusterName = item.Stream.BodyClusterName
			log.HostName = item.Stream.BodyHostName
			log.NamespaceName = item.Stream.BodyNamespaceName
			log.Owner.Name = item.Stream.BodyOwnerName
			log.Owner.Ref = item.Stream.BodyOwnerRef
			log.Owner.Namespace = item.Stream.BodyOwnerNamespace
			log.Labels = item.Stream.BodyLabels
			log.ContainerID = item.Stream.BodyContainerID
			log.ContainerName = item.Stream.BodyContainerName
			log.ContainerImage = item.Stream.BodyContainerImage
			log.ParentProcessName = item.Stream.BodyParentProcessName
			log.ProcessName = item.Stream.BodyProcessName
			log.HostPPID = convertToInt(item.Stream.BodyHostPPID)
			log.HostPID = convertToInt(item.Stream.BodyHostPID)
			log.PPID = convertToInt(item.Stream.BodyPPID)
			log.PID = convertToInt(item.Stream.BodyPID)
			log.UID = convertToInt(item.Stream.BodyUID)
			log.Type = item.Stream.BodyType
			log.Source = item.Stream.BodySource
			log.Operation = item.Stream.BodyOperation
			log.Resource = item.Stream.BodyResource
			log.Data = item.Stream.BodyData
			log.Result = item.Stream.BodyResult
			log.Cwd = item.Stream.BodyCwd

			if item.Stream.BodyTTY != "" {
				log.TTY = item.Stream.BodyTTY
			}
			logs = append(logs, log)
		}

		break
	}

	var NodeGraphData models.NodeGraph
	switch MyQuery.Operation {
	case "Process":
		NodeGraphData = getProcessGraph(logs, MyQuery)
		break
	case "Network":

		NodeGraphData = getNetworkGraph(logs, MyQuery)
		break
	}

	return NodeGraphData, total, TTY
}

func getProcessGraph(logs []models.Log, MyQuery queryModel) models.NodeGraph {

	colors := []string{"red", "orange", "green", "cyan", "rose"}

	var processLogs []models.Log

	for _, log := range logs {

		if log.TTY == pts0 &&
			log.Operation == MyQuery.Operation && (MyQuery.NamespaceQuery == "All" || log.NamespaceName == MyQuery.NamespaceQuery) &&
			(MyQuery.LabelQuery == "All" || log.Labels == MyQuery.LabelQuery) {
			processLogs = append(processLogs, log)
		}

	}

	/* Nodes */

	var ProcessNodes []models.NodeFields

	var processEdges []models.EdgeFields

	for _, log := range processLogs {
		isBlocked := log.Result == denied

		if log.PPID == 0 {
			colorIndex := random(0, len(colors)-1)
			cnode := models.NodeFields{
				ID:                  log.ContainerName + log.NamespaceName,
				Title:               log.ContainerName,
				Color:               colors[colorIndex],
				ChildNode:           fmt.Sprintf("%d%s%s", log.HostPID, log.ContainerName, log.NamespaceName),
				DetailContainerName: log.ContainerName,
				DetailNamespaceName: log.NamespaceName,
			}

			ProcessNodes = append(ProcessNodes, cnode)

			edge := models.EdgeFields{
				ID:     fmt.Sprintf("%s%s%s%s", cnode.ID, cnode.ChildNode, cnode.DetailNamespaceName, cnode.DetailContainerName),
				Source: fmt.Sprintf("%s", cnode.ID),
				Target: fmt.Sprintf("%s", cnode.ChildNode),
			}

			processEdges = append(processEdges, edge)

		} else {

			edge := models.EdgeFields{
				ID:     fmt.Sprintf("%s%d%d", fmt.Sprintf("%d%s%s", log.HostPID, log.ContainerName, log.NamespaceName), log.PPID, log.HostPID),
				Source: fmt.Sprintf("%d%s%s", log.HostPPID, log.ContainerName, log.NamespaceName),
				Target: fmt.Sprintf("%d%s%s", log.HostPID, log.ContainerName, log.NamespaceName),
			}
			processEdges = append(processEdges, edge)
		}

		node := models.NodeFields{
			ID:       fmt.Sprintf("%d%s%s", log.HostPID, log.ContainerName, log.NamespaceName),
			Title:    log.ProcessName,
			MainStat: log.Source,
			Color:    "white",
			// DetailTimestamp:         log.Timestamp,
			DetailClusterName:       log.ClusterName,
			DetailHostName:          log.HostName,
			DetailNamespaceName:     log.NamespaceName,
			DetailPodName:           log.ContainerName, // Using ContainerName as PodName for demonstration
			DetailLabels:            log.Labels,
			DetailContainerID:       log.ContainerID,
			DetailContainerName:     log.ContainerName,
			DetailContainerImage:    log.ContainerImage,
			DetailParentProcessName: log.ParentProcessName,
			DetailProcessName:       log.ProcessName,
			DetailHostPPID:          int64(log.HostPPID),
			DetailHostPID:           int64(log.HostPID),
			DetailPPID:              int64(log.PPID),
			DetailPID:               int64(log.PID),
			DetailUID:               int64(log.UID),
			DetailType:              log.Type,
			DetailSource:            log.Source,
			DetailOperation:         log.Operation,
			DetailResource:          log.Resource,
			DetailData:              log.Data,
			DetailResult:            log.Result,
			DetailCwd:               log.Cwd,
			DetailTTY:               log.TTY,
		}

		if isBlocked {
			node.Color = "red"
		}

		ProcessNodes = append(ProcessNodes, node)

	}

	var nodeGraph = models.NodeGraph{
		Nodes: ProcessNodes,
		Edges: processEdges,
	}

	return nodeGraph
}

func getNetworkGraph(logs []models.Log, MyQuery queryModel) models.NodeGraph {

	var networkGraphs []models.NetworkGraph

	for _, log := range logs {
		datamap := extractdata(log.Data)
		kprobeData := datamap["kprobe"]
		domainData := datamap["domain"]

		resourceMap := extractdata(log.Resource)
		remoteIP := resourceMap["remoteip"]
		port := resourceMap["port"]
		protocol := resourceMap["protocol"]

		node := models.NodeFields{
			ID:       fmt.Sprintf("%s%s%s", log.Owner.Name, log.Owner.Namespace, log.Owner.Ref),
			Title:    log.Owner.Name,
			MainStat: log.Owner.Namespace,
			Color:    "white",
			// DetailTimestamp:         log.Timestamp,
			DetailClusterName:       log.ClusterName,
			DetailHostName:          log.HostName,
			DetailNamespaceName:     log.NamespaceName,
			DetailPodName:           log.ContainerName, // Using ContainerName as PodName for demonstration
			DetailLabels:            log.Labels,
			DetailContainerID:       log.ContainerID,
			DetailContainerName:     log.ContainerName,
			DetailContainerImage:    log.ContainerImage,
			DetailParentProcessName: log.ParentProcessName,
			DetailProcessName:       log.ProcessName,
			DetailHostPPID:          int64(log.HostPPID),
			DetailHostPID:           int64(log.HostPID),
			DetailPPID:              int64(log.PPID),
			DetailPID:               int64(log.PID),
			DetailUID:               int64(log.UID),
			DetailType:              log.Type,
			DetailSource:            log.Source,
			DetailOperation:         log.Operation,
			DetailResource:          log.Resource,
			DetailData:              log.Data,
			DetailResult:            log.Result,
			DetailCwd:               log.Cwd,
		}

		if log.Result == denied {
			node.Color = "red"
		}

		var networkData = models.NetworkData{
			Kprobe:   kprobeData,
			Domain:   domainData,
			RemoteIP: remoteIP,
			Port:     port,
			Protocol: protocol,
		}

		switch kprobeData {
		case "tcp_accept":
			var NetworkGraph = models.NetworkGraph{
				NData: networkData,
				ID:    fmt.Sprintf("%s%s%s", log.Owner.Name, log.Owner.Namespace, remoteIP),
				Source: models.NodeFields{
					ID:       fmt.Sprintf("%s%s%s", remoteIP, port, protocol),
					Title:    fmt.Sprintf("%s", remoteIP),
					MainStat: fmt.Sprintf("%s", protocol),

					Color: "white",
				},
				Target: node,
			}
			networkGraphs = append(networkGraphs, NetworkGraph)

			break
		case "tcp_connect":

			var NetworkGraph = models.NetworkGraph{
				NData:  networkData,
				ID:     fmt.Sprintf("%s%s%s", log.Owner.Name, log.Owner.Namespace, remoteIP),
				Source: node,
				Target: models.NodeFields{
					ID:       fmt.Sprintf("%s%s%s", remoteIP, port, protocol),
					Title:    fmt.Sprintf("%s", remoteIP),
					MainStat: fmt.Sprintf("%s", protocol),

					Color: "white",
				},
			}
			networkGraphs = append(networkGraphs, NetworkGraph)
			break
		}

	}

	var NodeData []models.NodeFields
	var EdgeData []models.EdgeFields
	for _, netGraph := range networkGraphs {
		NodeData = append(NodeData, netGraph.Source)
		NodeData = append(NodeData, netGraph.Target)
		var edge = models.EdgeFields{
			ID:     netGraph.ID,
			Source: netGraph.Source.ID,
			Target: netGraph.Target.ID,
		}
		EdgeData = append(EdgeData, edge)

	}

	var nodeGraph = models.NodeGraph{
		Nodes: NodeData,
		Edges: EdgeData,
	}

	return nodeGraph
}

// CheckHealth handles health checks sent from Grafana to the plugin.
// The main use case for these health checks is the test button on the
// datasource configuration page which allows users to verify that
// a datasource is working as expected.
func (d *Datasource) CheckHealth(ctx context.Context, req *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	res := &backend.CheckHealthResult{}
	config, err := models.LoadPluginSettings(*req.PluginContext.DataSourceInstanceSettings)
	ctxLogger := log.DefaultLogger.FromContext(ctx)

	healthendpoint := d.settings.URL
	switch config.Backend {
	case "ELASTICSEARCH":
		healthendpoint += "/_cluster/health"
		break
	case "LOKI":
		healthendpoint += "/ready"
		break
	}

	r, err := http.NewRequestWithContext(ctx, http.MethodGet, healthendpoint, nil)

	resp, err := d.httpClient.Do(r)

	defer func() {
		if err := resp.Body.Close(); err != nil {
			ctxLogger.Error("check health: failed to close response body", "err", err.Error())
		}
	}()

	if err != nil {
		res.Status = backend.HealthStatusError
		res.Message = "Unable to load settings"
		ctxLogger.Error("load settings: failed to load settings")
		return res, nil
	}

	if resp.StatusCode != http.StatusOK {
		res.Status = backend.HealthStatusError
		res.Message = fmt.Sprintf("error on checking health check status from backend  %s", resp.Status)

		return res, nil
	}

	if config.Secrets.ApiKey == "" {
		res.Status = backend.HealthStatusError
		res.Message = "API key is missing"
		return res, nil
	}

	return &backend.CheckHealthResult{
		Status:  backend.HealthStatusOk,
		Message: fmt.Sprintf("Data source is working"),
	}, nil
}

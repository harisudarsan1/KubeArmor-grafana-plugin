import { DataSourceJsonData } from '@grafana/data';
import { DataQuery } from '@grafana/schema';

export interface MyQuery extends DataQuery, QueryType {
  // backendURL?: string;
}

export interface QueryType {

  NamespaceQuery?: string;
  LabelQuery?: string;
  Operation: string;
}

export const DEFAULT_QUERY: Partial<MyQuery> = {
  NamespaceQuery: "All",
  LabelQuery: "All",
  Operation: "Process"
};

// export interface DataPoint {
//   Time: number;
//   Value: number;
// }
//
// export interface DataSourceResponse {
//   datapoints: DataPoint[];
// }

/**
 * These are options configured for each DataSource instance
 */
export interface MyDataSourceOptions extends DataSourceJsonData {
  path?: string;
  backendName: string;
}

/**
 * Value that is used in the backend, but never sent over HTTP to the frontend
 */
export interface MySecureJsonData {
  apiKey?: string;
}

export interface NodeGraph {
  nodes: NodeFields[];
  edges: EdgeFields[];

}

export interface NodeFields extends KubeArmorLogs {
  id: string;
  title?: string;
  mainStat?: string;
  color?: string;
  childNode?: string;
  nodeRadius?: string;
  highlighted?: boolean;

}

export interface FrameFieldType {

  name: string;
  type: any;
  config: Record<string, any>;
}

export interface KubeArmorLogs {
  detail__Timestamp?: number;
  detail__UpdatedTime?: string; // Already commented out, assuming you still don't want this included
  detail__ClusterName?: string;
  detail__HostName?: string;
  detail__NamespaceName?: string;
  detail__PodName?: string;
  detail__Labels?: string;
  detail__ContainerID?: string;
  detail__ContainerName?: string;
  detail__ContainerImage?: string;
  detail__ParentProcessName?: string;
  detail__ProcessName?: string;
  detail__HostPPID?: number;
  detail__HostPID?: number;
  detail__PPID?: number;
  detail__PID?: number;
  detail__UID?: number;
  detail__Type?: string;
  detail__Source?: string;
  detail__Operation?: string;
  detail__Resource?: string;
  detail__Data?: string;
  detail__Result?: string;
  detail__Cwd?: string;
  detail__TTY?: string;
}

interface Podowner {
  ref: string;
  Name: string;
  Namespace: string;

  // Define fields for Podowner if necessary
}

export interface EdgeFields {
  id: string;
  source: string;
  target: string;
}


export interface Hits {
  _index: string;
  _type: string;
  _id: string;
  _score: number;
  _source: Log;
}

interface Shards {
  total: number;
  successful: number;
  skipped: number;
  failed: number;
}

interface Total {
  value: number;
  relation: string;
}

export interface ElasticsearchResponse {
  took: number;
  timed_out: boolean;
  _shards: Shards;
  hits: {
    total: Total;
    max_score: number;
    hits: Hits[];
  };
}

export interface LokiSearchResponse {
  status: string;
  Data: {
    resultType: "string";
    result: LokiResults[];
    stats: any;


  }

}
interface LokiResults {
  stream: Stream;
  values: any;
}
// interface Value {
//   0: string; // First element of array is a string
//   1: {
//     body: Log
//   }; // Second element of array is a DataBody object
// }


export interface Log {
  Timestamp?: number;
  UpdatedTime: string;
  ClusterName: string;
  HostName: string;
  NamespaceName: string;
  Owner: Podowner;
  PodName: string;
  Labels: string;
  ContainerID: string;
  ContainerName: string;
  ContainerImage: string;
  ParentProcessName: string;
  ProcessName: string;
  HostPPID: number;
  HostPID: number;
  PPID: number;
  PID: number;
  UID: number;
  Type: string;
  Source: string;
  Operation: string;
  Resource: string;
  Data: string;
  Result: string;
  Cwd: string;
  TTY: string;
}

export type HealthResponse = {
  cluster_name: string;
  status: string;
  timed_out: boolean;
  number_of_nodes: number;
  number_of_data_nodes: number;
  active_primary_shards: number;
  active_shards: number;
  relocating_shards: number;
  initializing_shards: number;
  unassigned_shards: number;
  delayed_unassigned_shards: number;
  number_of_pending_tasks: number;
  number_of_in_flight_fetch: number;
  task_max_waiting_in_queue_millis: number;
  active_shards_percent_as_number: number;
};

interface Stream {
  body_ClusterName: string;
  body_ContainerID: string;
  body_ContainerImage: string;
  body_ContainerName: string;
  body_Cwd: string;
  body_Data: string;
  body_HostName: string;
  body_HostPID: string;
  body_HostPPID: string;
  body_Labels: string;
  body_NamespaceName: string;
  body_Operation: string;
  body_Owner_Name: string;
  body_Owner_Namespace: string;
  body_Owner_Ref: string;
  body_PID: string;
  body_PPID: string;
  body_ParentProcessName: string;
  body_PodName: string;
  body_ProcessName: string;
  body_Resource: string;
  body_Result: string;
  body_Source: string;
  body_Type: string;
  body_UID: string;
  body_UpdatedTime: string;
  body_TTY?: string;
  exporter: string;
}
// export interface LokiBody {
//
//   ClusterName: string;
//   ContainerID: string;
//   ContainerImage: string;
//   ContainerName: string;
//   Cwd: string;
//   Data: string;
//   HostName: string;
//   HostPID: number;
//   HostPPID: number;
//   Labels: string;
//   NamespaceName: string;
//   Operation: string;
//   Owner: {
//     Name: string;
//     Namespace: string;
//     Ref: string;
//   };
//   PID: number;
//   PPID: number;
//   ParentProcessName: string;
//   PodName: string;
//   ProcessName: string;
//   Resource: string;
//   Result: string;
//   Source: string;
//   Type: string;
//   UID: number;
//   UpdatedTime: string; // Assuming this is a timestamp
//
// }
//

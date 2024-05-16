// import { ChangeEvent } from 'react';
import { DataSourcePluginOptionsEditorProps } from '@grafana/data';
import { DataSourceHttpSettings, Select, InlineField } from '@grafana/ui';
import React from 'react';
import { MyDataSourceOptions } from '../types';

interface Props extends DataSourcePluginOptionsEditorProps<MyDataSourceOptions> { }


export const ConfigEditor: React.FC<Props> = ({ onOptionsChange, options }) => {

  const BackendOptions = [
    { label: 'Elasticsearch', value: 'ELASTICSEARCH' },
    { label: 'Loki ', value: 'LOKI' }

  ]
  //
  const onBackendOptionsChange = (backendName: string) => {

    const jsonData = {
      ...options.jsonData,
      backendName: backendName,
    };
    onOptionsChange({ ...options, jsonData })
  }


  return (
    <div>
      <DataSourceHttpSettings
        defaultUrl="https://elasticsearch:9200"
        dataSourceConfig={options}
        onChange={onOptionsChange}
      />

      <InlineField label="Backend" labelWidth={16} >
        <Select
          options={BackendOptions}
          value={options.jsonData.backendName}
          onChange={v => {
            onBackendOptionsChange(v.value!)
          }}
        />
      </InlineField>
    </div>
  );
};

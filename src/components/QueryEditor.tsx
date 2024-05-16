import React from 'react';
import { InlineField, Stack, Select } from '@grafana/ui';
import { QueryEditorProps, SelectableValue } from '@grafana/data';
import { DataSource } from '../datasource';
import { MyDataSourceOptions, MyQuery } from '../types';

type Props = QueryEditorProps<DataSource, MyQuery, MyDataSourceOptions>;

export function QueryEditor({ query, onChange, onRunQuery, data }: Props) {

  // const Allselectable: SelectableValue<string> = {
  //   label: "All",
  //   value: "All"
  // }
  // const [namespace, setNamespace] = useState<SelectableValue<string>[]>([Allselectable])
  // const [labels, setLabels] = useState<SelectableValue<string>[]>([Allselectable])

  const onQueryChange = (qname: string, type: string) => {

    switch (type) {
      case "NAMESPACE":

        onChange({ ...query, NamespaceQuery: qname });
        break;
      case "LABEL":

        onChange({ ...query, LabelQuery: qname });
        break;
      case "OPERATION":
        onChange({ ...query, Operation: qname })
    }
    onRunQuery();
  }

  const { NamespaceQuery, LabelQuery, Operation } = query;
  const frame = data?.series[0];
  const Namespaces = frame?.fields.find(i => i.name === 'detail__NamespaceName')

  const Labels = frame?.fields.find(i => i.name === 'detail__Labels')
  const uniqueNamespaces = new Set<string>(["All"]);
  const uniqueLabels = new Set<string>(["All"])

  if (Namespaces && Namespaces.values) {
    // Iterate over each value and add it to the set
    Namespaces.values.forEach(value => {
      uniqueNamespaces.add(value);
    });
  }

  if (Labels && Labels.values) {
    // Iterate over each value and add it to the set
    Labels.values.forEach(value => {
      uniqueLabels.add(value)
    });
  }

  const uniqueNamespaceArray = Array.from(uniqueNamespaces);

  const uniqueLabelsArray = Array.from(uniqueLabels);


  const namespaceOptions = uniqueNamespaceArray.map(i => {
    const selectable: SelectableValue<string> = {
      label: i,
      value: i
    }
    return selectable
  })

  const labelOptions = uniqueLabelsArray.map(i => {
    const selectable: SelectableValue<string> = {
      label: i,
      value: i
    }
    return selectable
  })

  const operationOptions: SelectableValue[] = [
    {
      label: "Process",
      value: "Process",

    },
    {
      label: "Network",
      value: "Network"
    }
  ]

  return (
    <Stack gap={0}>
      <InlineField label="namespace" labelWidth={16} tooltip="filter using Namespaces">

        <Select
          options={namespaceOptions}
          value={NamespaceQuery || ''}
          onChange={v => {
            onQueryChange(v.value!, "NAMESPACE")
          }} />


      </InlineField>

      <InlineField label="label" labelWidth={16} tooltip="filter using labels">

        <Select
          options={labelOptions}
          value={LabelQuery || ''}
          onChange={v => {
            onQueryChange(v.value!, "LABEL")
          }} />


      </InlineField>

      <InlineField label="Operation" labelWidth={16} >

        <Select
          options={operationOptions}
          value={Operation || 'Process'}
          onChange={v => {
            onQueryChange(v.value!, "OPERATION")
          }} />


      </InlineField>
    </Stack>
  );
}

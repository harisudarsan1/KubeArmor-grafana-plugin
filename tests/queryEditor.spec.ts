import { test, expect } from '@grafana/plugin-e2e';

test('should trigger new query when Namespace field is changed', async ({ panelEditPage, readProvisionedDataSource }) => {
  const ds = await readProvisionedDataSource({ fileName: 'datasources.yml' });
  await panelEditPage.datasource.set(ds.name);

  const queryReq = panelEditPage.waitForQueryDataRequest();
  await panelEditPage.getQueryEditorRow('A').getByRole('combobox', { name: 'namespace' }).selectOption({ label: 'Namespace 1' });
  await expect(await queryReq).toBeTruthy();
});

test('should trigger new query when Label field is changed', async ({ panelEditPage, readProvisionedDataSource }) => {
  const ds = await readProvisionedDataSource({ fileName: 'datasources.yml' });
  await panelEditPage.datasource.set(ds.name);

  const queryReq = panelEditPage.waitForQueryDataRequest();
  await panelEditPage.getQueryEditorRow('A').getByRole('combobox', { name: 'label' }).selectOption({ label: 'Label 1' });
  await expect(await queryReq).toBeTruthy();
});

test('should trigger new query when Operation field is changed', async ({ panelEditPage, readProvisionedDataSource }) => {
  const ds = await readProvisionedDataSource({ fileName: 'datasources.yml' });
  await panelEditPage.datasource.set(ds.name);

  const queryReq = panelEditPage.waitForQueryDataRequest();
  await panelEditPage.getQueryEditorRow('A').getByRole('combobox', { name: 'Operation' }).selectOption({ label: 'Network' });
  await expect(await queryReq).toBeTruthy();
});

test('data query should return values 10 and 20', async ({ panelEditPage, readProvisionedDataSource }) => {
  const ds = await readProvisionedDataSource({ fileName: 'datasources.yml' });
  await panelEditPage.datasource.set(ds.name);
  await panelEditPage.getQueryEditorRow('A').getByRole('textbox', { name: 'Query Text' }).fill('test query');
  await panelEditPage.setVisualization('Table');
  await expect(panelEditPage.refreshPanel()).toBeOK();
  await expect(panelEditPage.panel.data).toContainText(['10', '20']);
});

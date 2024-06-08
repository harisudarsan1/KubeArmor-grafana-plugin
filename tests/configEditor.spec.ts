import { test, expect } from '@grafana/plugin-e2e';
import { MyDataSourceOptions, MySecureJsonData } from '../src/types';

test('"Save & test" should be successful when configuration is valid', async ({
  createDataSourceConfigPage,
  readProvisionedDataSource,
  page,
}) => {
  const ds = await readProvisionedDataSource<MyDataSourceOptions, MySecureJsonData>({ fileName: 'datasources.yml' });
  const configPage = await createDataSourceConfigPage({ type: ds.type });
  await page.getByRole('textbox', { name: 'Path' }).fill(ds.jsonData.path ?? '');
  // await page.getByRole('textbox', { name: 'API Key' }).fill(ds.secureJsonData?.apiKey ?? '');
  await expect(configPage.saveAndTest()).toBeOK();
});

test('"Save & test" should fail when configuration is invalid', async ({
  createDataSourceConfigPage,
  readProvisionedDataSource,
  page,
}) => {
  const ds = await readProvisionedDataSource<MyDataSourceOptions, MySecureJsonData>({ fileName: 'datasources.yml' });
  const configPage = await createDataSourceConfigPage({ type: ds.type });
  await page.getByRole('textbox', { name: 'Path' }).fill(ds.jsonData.path ?? '');
  await expect(configPage.saveAndTest()).not.toBeOK();
  await expect(configPage).toHaveAlert('error', { hasText: 'API key is missing' });
});

test('should change backend option and trigger onOptionsChange', async ({ createDataSourceConfigPage, readProvisionedDataSource, page }) => {
  const ds = await readProvisionedDataSource<MyDataSourceOptions, MySecureJsonData>({ fileName: 'datasources.yml' });
  const configPage = await createDataSourceConfigPage({ type: ds.type });

  // Open the backend selection dropdown and select a different backend option
  await page.getByRole('combobox', { name: 'Backend' }).selectOption('Loki');

  // Save the changes and check if they were applied correctly
  await expect(configPage.saveAndTest()).toBeOK();

  // Check that the selected option is indeed 'Loki'
  const selectedBackend = await page.getByRole('combobox', { name: 'Backend' }).inputValue();
  await expect(selectedBackend).toBe('LOKI');
});

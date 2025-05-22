import { test, expect } from '@playwright/test';

test.describe('Navigation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the app
    await page.goto('/');
  });

  test('should navigate to all pages', async ({ page }) => {
    // Check the dashboard is loaded by default
    await expect(page.getByText('Dashboard', { exact: true })).toBeVisible();
    
    // Navigate to Events page
    await page.getByRole('link', { name: 'Events' }).click();
    await expect(page.getByText('Events', { exact: true })).toBeVisible();
    
    // Navigate to Quarantine page
    await page.getByRole('link', { name: 'Quarantine' }).click();
    await expect(page.getByText('Quarantine', { exact: true })).toBeVisible();
    
    // Navigate to Rules page
    await page.getByRole('link', { name: 'Rules' }).click();
    await expect(page.getByText('Detection Rules')).toBeVisible();
    
    // Navigate to Settings page
    await page.getByRole('link', { name: 'Settings' }).click();
    await expect(page.getByText('Connection Settings')).toBeVisible();
    
    // Navigate back to Dashboard
    await page.getByRole('link', { name: 'Dashboard' }).click();
    await expect(page.getByText('Dashboard', { exact: true })).toBeVisible();
  });

  test('should toggle theme settings', async ({ page }) => {
    // Navigate to Settings page
    await page.getByRole('link', { name: 'Settings' }).click();
    
    // Toggle to Dark theme
    await page.getByRole('button', { name: 'Dark' }).click();
    
    // Check for dark theme class
    const html = await page.locator('html');
    await expect(html).toHaveClass(/dark/);
    
    // Toggle to Light theme
    await page.getByRole('button', { name: 'Light' }).click();
    
    // Check for light theme (absence of dark class)
    await expect(html).not.toHaveClass(/dark/);
  });
}); 
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi } from 'vitest';
import { Layout } from '../layout';
import { ThemeProvider } from '../theme-provider';

// Mock the Outlet component
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    Outlet: () => <div data-testid="outlet-mock">Outlet Content</div>,
  };
});

describe('Layout Component', () => {
  it('renders correctly', () => {
    render(
      <MemoryRouter>
        <ThemeProvider>
          <Layout />
        </ThemeProvider>
      </MemoryRouter>
    );

    // Check if the component renders with the title
    expect(screen.getByText('BlockWave-Ransom')).toBeInTheDocument();
    
    // Check if navigation links are present
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Events')).toBeInTheDocument();
    expect(screen.getByText('Quarantine')).toBeInTheDocument();
    expect(screen.getByText('Rules')).toBeInTheDocument();
    expect(screen.getByText('Settings')).toBeInTheDocument();
    
    // Check if the outlet is rendered
    expect(screen.getByTestId('outlet-mock')).toBeInTheDocument();
  });
}); 
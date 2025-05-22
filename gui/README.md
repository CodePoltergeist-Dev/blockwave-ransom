# BlockWave-Ransom GUI

The GUI component for the BlockWave-Ransom ransomware detection and mitigation system. This Electron-based application provides real-time monitoring, analysis, and control capabilities.

## Features

- **Real-time event monitoring**: View and filter detection and mitigation events as they occur
- **Quarantine management**: Safely restore or permanently delete quarantined files
- **Detection rule configuration**: Create, edit, and manage detection rules
- **System settings**: Configure connection settings, notification preferences, and appearance
- **Responsive design**: Works seamlessly across different screen sizes

## Technology Stack

- Electron for cross-platform desktop application
- React for UI components
- TypeScript for type safety
- Tailwind CSS for styling
- shadcn/ui for modern UI components
- Framer Motion for animations
- Socket.IO for real-time communication
- Zustand for state management
- Vite for fast development and building

## Getting Started

### Prerequisites

- Node.js 16+
- npm 7+

### Installation

1. Clone the repository
   ```
   git clone https://github.com/yourusername/blockwave-ransom.git
   cd blockwave-ransom/gui
   ```

2. Install dependencies
   ```
   npm install
   ```

3. Start the development server
   ```
   npm run dev
   ```

### Building for Production

```
npm run build
npm run build:electron
```

This will create distributable packages in the `release` directory.

## Development

### Project Structure

- `electron/`: Main process files
- `src/`: Renderer process (React application)
  - `components/`: Reusable UI components
  - `pages/`: Page components
  - `hooks/`: Custom React hooks
  - `store/`: State management
  - `lib/`: Utility functions

### Testing

Run unit tests:
```
npm test
```

Run end-to-end tests:
```
npm run test:e2e
```

## Connection to Backend

The GUI connects to the BlockWave-Ransom backend service via WebSocket. The backend service should expose the following endpoints:

- `/events/stream`: For real-time event updates 
- `/actions`: For sending control commands to the backend

## License

MIT 
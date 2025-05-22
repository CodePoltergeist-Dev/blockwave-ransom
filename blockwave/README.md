# BlockWave-Ransom

<p align="center">
  <img alt="BlockWave-Ransom Logo" src="docs/assets/blockwave-logo.png">
</p>

<h2 align="center">
Advanced Ransomware Detection and Mitigation using eBPF and Machine Learning
</h2>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg">
  <img alt="Version" src="https://img.shields.io/badge/version-1.0.0-brightgreen.svg">
</p>

## Overview

**BlockWave-Ransom** is a comprehensive ransomware detection and mitigation system that uses eBPF technology and machine learning to provide real-time protection against ransomware attacks. The system monitors file system operations, process behavior, and system calls to identify ransomware patterns and respond automatically to protect your data.

## Key Features

- **Real-time Monitoring**: Continuous monitoring of file system operations, system calls, and process behavior
- **ML-Powered Detection**: Advanced machine learning algorithms trained to identify ransomware patterns
- **YARA Rule Integration**: Static analysis using YARA rules for known ransomware signatures
- **Automated Mitigation**: Immediate ransomware containment through process termination and network isolation
- **Quarantine Management**: Safe isolation of suspicious files with restore capability
- **Backup and Restore**: Automated backup of critical files with quick restore options
- **Real-time Dashboard**: Modern Electron-based GUI for system monitoring and control
- **Low Performance Impact**: Efficient monitoring with minimal system performance impact

## System Architecture

BlockWave-Ransom consists of three main components:

1. **Backend Service**: API server, detection orchestration, and mitigation control
2. **eBPF Monitoring Service**: Kernel-level monitoring of system activities
3. **GUI Dashboard**: User interface for monitoring, configuration, and control

## Setup Instructions

### Running with Docker (Recommended)

The easiest way to set up BlockWave-Ransom is using Docker Compose:

```shell
# Clone the repository
git clone https://github.com/yourusername/blockwave-ransom.git
cd blockwave-ransom

# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### Manual Setup

#### Backend Service
```shell
cd blockwave
pip install -r requirements.txt
python main.py --config config/config.yaml
```

#### eBPF Monitoring Service (requires root)
```shell
cd blockwave
pip install -r requirements.txt
sudo python ebpf_monitor.py --config config/ebpf_config.yaml
```

#### GUI Dashboard
```shell
cd blockwave/gui
npm install
npm run build
npm start
```

For development mode:
```shell
cd blockwave/gui
npm install
npm run dev
```

## GUI Dashboard Features

The BlockWave-Ransom GUI provides:

- Real-time event monitoring with detailed information
- Interactive dashboard with threat statistics and system status
- Quarantine management for handling detected threats
- Detection rule configuration with custom rule creation
- System settings and notification preferences

## Testing

BlockWave-Ransom includes a comprehensive test suite for verifying functionality:

```shell
# Run all tests
pytest blockwave/tests/

# Run specific test categories
pytest blockwave/tests/integration/
pytest blockwave/tests/fuzzing/
```

For safe ransomware simulation testing:

```shell
python blockwave/tests/simulators/ransomware_simulator.py /path/to/test/directory
```

## Configuration

BlockWave-Ransom can be configured through YAML files in the `config` directory:

- `config.yaml`: Main configuration file
- `rules.yaml`: Detection rules configuration
- `yara_rules.yaml`: YARA rule configuration

## Security Considerations

BlockWave-Ransom requires privileged access to monitor system calls and process behavior effectively. Review the permissions and security implications before deploying in production environments.

## Contributing

Contributions to BlockWave-Ransom are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run tests (`pytest blockwave/tests/`)
5. Commit your changes (`git commit -am 'Add new feature'`)
6. Push to the branch (`git push origin feature/your-feature`)
7. Create a new Pull Request

## License

MIT License. See [LICENSE](LICENSE) for details.

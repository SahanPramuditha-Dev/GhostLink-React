# GHOSTLINK — Desktop Network Security Assessment Tool

GHOSTLINK is a Windows-oriented desktop application for **authorized network visibility, diagnostics, and security assessment workflows**. It combines an Electron desktop shell, a React/TypeScript interface, and a local FastAPI backend packaged for desktop distribution.

The project is intended for learning, defensive analysis, lab environments, and networks where the user has explicit permission to perform security testing.

> **Authorized use only:** Do not use GHOSTLINK against networks, devices, or accounts you do not own or have explicit permission to assess.

## Architecture

```text
┌─────────────────────────────────────┐
│         Electron Desktop Shell      │
│   window lifecycle · packaging      │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│      React + TypeScript Frontend    │
│  dashboards · topology · reports    │
│  visualizations · settings          │
└──────────────────┬──────────────────┘
                   │ local API / WS
                   ▼
┌─────────────────────────────────────┐
│          FastAPI Backend            │
│  scanning · recon · status · logs   │
│  settings · reports · performance   │
└─────────────────────────────────────┘
```

The backend runs locally and is bundled for desktop builds with PyInstaller, while Electron packages the application into a Windows installer.

## Technology Stack

| Layer | Technology |
| --- | --- |
| Desktop shell | Electron 26, electron-builder |
| Frontend | React 19, TypeScript, Vite 8 |
| UI | Material UI, Framer Motion, Lucide React |
| Visualization | React Flow, Recharts |
| Backend | Python, FastAPI, Uvicorn |
| Realtime transport | WebSockets |
| System information | psutil |
| Reporting | ReportLab |
| Backend packaging | PyInstaller |
| Windows packaging | NSIS via electron-builder |

## Project Areas

### Network Visibility

The application includes local workflows for discovering and presenting network information in a desktop interface. The focus is on making diagnostic data easier to understand through structured views and visualizations.

### Reconnaissance & Diagnostics

Backend modules provide authorized reconnaissance and diagnostic workflows for security-lab and defensive analysis scenarios. Detailed offensive procedures are intentionally not documented here.

### Topology & Visualization

The React interface uses graph and chart libraries to present device relationships, status information, and other telemetry in a more understandable visual form.

### Logs, Status & Performance

Dedicated backend modules support application logs, runtime status, configuration, and performance-related information for the desktop client.

### Reporting

ReportLab support allows the project to generate structured report artifacts from assessment or diagnostic data.

## Repository Structure

```text
backend/       FastAPI backend and local API modules
electron/      Electron main process and desktop integration
web-radar/     React + TypeScript frontend
scripts/       Build and packaging scripts
.github/       GitHub repository configuration
BUILD_GUIDE.md Build and packaging documentation
SECURITY.md    Security policy
CONTRIBUTING.md Contribution guide
CHANGELOG.md   Project history
```

## Getting Started

### Prerequisites

- Windows development environment
- Node.js and npm
- Python
- Git

### Install Frontend Dependencies

```bash
git clone https://github.com/SahanPramuditha-Dev/GhostLink-React.git
cd GhostLink-React
npm install
npm run frontend:install
```

### Install Backend Dependencies

The repository includes a convenience script:

```bash
npm run backend:install
```

Or install manually in a Python virtual environment using:

```bash
pip install -r backend/requirements.txt
```

### Development

```bash
npm run dev
```

This starts the frontend development workflow together with the Electron desktop shell. The local backend should be available according to the development/build configuration used by the project.

## Production Build

```bash
npm run build
```

The build pipeline:

1. builds the React frontend;
2. packages the Python backend with PyInstaller;
3. packages the desktop application with Electron Builder / NSIS.

For detailed packaging notes, see [BUILD_GUIDE.md](BUILD_GUIDE.md).

## Security & Data Handling

Security-assessment tools must treat captured network information and credentials as sensitive data.

- Do **not** commit passwords, recovered credentials, scan exports, private network data, or local vault files.
- Keep secrets and assessment artifacts outside source control.
- Use test credentials and isolated lab environments during development.
- Review [SECURITY.md](SECURITY.md) before reporting security issues.
- Rotate any credential that has accidentally been committed to a public repository.

Local runtime/generated files such as vault data should be excluded through `.gitignore` and stored only on the user's machine.

## Ethical Use

GHOSTLINK is intended for:

- your own networks and devices;
- security labs and coursework;
- defensive troubleshooting;
- explicitly authorized security assessments.

It is not intended for unauthorized access, credential theft, disruption, or surveillance of third-party networks.

## Documentation

- [Build Guide](BUILD_GUIDE.md)
- [Security Policy](SECURITY.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Changelog](CHANGELOG.md)
- [License](LICENSE.md)

## Status

**Active development / portfolio security project.** Features, backend modules, and packaging workflows may evolve as the application is refined.

## Author

**Sahan Pramuditha**  
BICT Undergraduate — University of Colombo

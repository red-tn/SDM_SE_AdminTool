# SDM SE Admin Tool

A comprehensive GUI application for managing StrongDM resources including SSH, RDP, and Database connections. Supports both individual resource creation and bulk CSV import operations for POV environments.

## Features

- **Authentication**: Secure API key authentication with StrongDM
- **Single Resource Creation**: Interactive forms for creating SSH, RDP, and database resources
- **Bulk CSV Import**: Import multiple resources from CSV files with validation
- **Secrets Management**: Complete managed secrets operations
  - List all managed secrets with metadata
  - Validate secret credentials
  - Rotate secrets on-demand
  - **Retrieve actual secret values** with RSA encryption/decryption
  - Copy secret values to clipboard
- **Dynamic Configuration**: Automatically loads available tags, secret stores, and proxy clusters from your tenant
- **Debug Tools**: Built-in testing and troubleshooting capabilities
- **Modern UI**: Professional, responsive interface with clean styling
- **Cross-Platform**: Works on Windows with plans for Mac support
- **Auto-Updates**: Automatically upgrades StrongDM SDK to latest version on startup

## Supported Resource Types

### SSH Resources
- Username/password authentication
- Private key authentication
- Certificate-based authentication
- Customer managed key authentication
- Configurable ports and hostnames
- Tag and proxy cluster assignment

### RDP Resources
- Basic username/password authentication
- Certificate-based authentication
- Resource lock configuration
- NLA connection downgrade options
- Tag and proxy cluster assignment

### Database Resources
- MySQL, PostgreSQL, MSSQL, Redis
- Database-specific configuration
- Connection string management
- Tag and proxy cluster assignment

## Installation

### Prerequisites
- Python 3.7 or higher
- StrongDM API credentials with appropriate permissions

### Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   python strongdm_manager.py
   ```

   **Note:** The application automatically checks for and upgrades to the latest StrongDM SDK version on each startup to ensure compatibility with the latest features and secret store types.

## Usage

### Initial Setup
1. Launch the application
2. Enter your StrongDM API Access Key and Secret Key in the Login tab
3. Click "Connect" to authenticate

### Creating Single Resources
1. After authentication, navigate to the "Add Single Resource" tab
2. Select the resource type (SSH, RDP, or Database)
3. Fill in the required fields marked with red asterisks
4. Configure optional settings like tags, secret stores, and proxy clusters
5. Click "Create Resource"

### Bulk CSV Import
1. Navigate to the "CSV Bulk Import" tab
2. Use the sample CSV files as references for each resource type
3. Select your CSV file using the "Browse" button
4. Configure import options:
   - Skip errors: Continue processing even if some rows fail
   - Dry run: Validate the CSV without creating resources
5. Click "Import Resources"

### CSV Format
Required columns vary by resource type. See the sample CSV files for examples:
- `sample_ssh_resources.csv` - SSH resource examples
- `sample_rdp_resources.csv` - RDP resource examples  
- `sample_rdp_certificate_resources.csv` - RDP certificate examples
- `sample_mysql_resources.csv` - MySQL database examples
- `sample_postgresql_resources.csv` - PostgreSQL database examples
- `sample_mssql_resources.csv` - SQL Server database examples
- `sample_redis_resources.csv` - Redis database examples

### Debug Tab
Use the Debug tab to:
- Test API connectivity
- List existing resources
- Query resources with filters
- Clear debug output
- Troubleshoot authentication issues

## API Permissions Required

Your StrongDM API key must have the following permissions:
- Resources: Create, Read, List
- Tags: Read, List
- Secret Stores: Read, List
- Proxy Clusters: Read, List

## Security Notes

- API credentials are only stored in memory during the session
- Passwords and private keys are masked in the interface
- All API communications use StrongDM's secure authentication
- No credentials are logged or persisted to disk

## Building Executable

### Windows
Run the provided batch script:
```bash
build_windows.bat
```

### macOS
Run the provided shell script:
```bash
chmod +x build_mac.sh
./build_mac.sh
```

This creates:
- **App Bundle**: `StrongDM-Manager.app` (drag to Applications)
- **DMG Installer**: `StrongDM-Manager.dmg` (double-click to install)
- **Standalone executable**: Command-line version
- **Installation package**: Complete package with installer script

### OCI Container
Run the provided shell script:
```bash
build_container.sh
```

## Support

For issues related to:
- StrongDM API: Consult the official StrongDM documentation
- Application bugs: Check logs in the Debug tab
- Feature requests: Review the StrongDM API capabilities

## License

This application is provided as-is for managing StrongDM resources. Ensure compliance with your organization's security policies when using API credentials.

# Changelog

All notable changes to the Cisco IOS Configuration Backup project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-02-05

### Added
- **SSH Host Key Verification** (Security Fix #1): Implemented proper SSH host key validation using paramiko's `RejectPolicy()` instead of the insecure `AutoAddPolicy()`. This prevents man-in-the-middle (MitM) attacks by rejecting connections to servers with unknown or mismatched host keys.
- **Custom known_hosts Support**: Added optional `known_hosts_file` configuration parameter in `scp_server` section to support custom SSH host key databases for air-gapped or multi-environment deployments.
- **Automatic Config File Permission Hardening** (Security Fix #2): The `--generate-config` command now automatically sets file permissions to `0600` (owner read/write only) to protect plaintext credentials (SNMPv3 passwords, SCP credentials) from unauthorized access.
- **Hostname Resolution Support** (Fix #5): SCP server addresses can now be specified as hostnames (e.g., `scp.backup.local`) in addition to IP addresses. The script automatically resolves hostnames to IPv4 addresses before passing to the CISCO-CONFIG-COPY-MIB.

### Changed
- **Async I/O for Paramiko Operations** (Performance Fix #3): Refactored all blocking paramiko SSH/SFTP operations (`verify_scp_server`, `download_backup_from_scp`) to run in thread executors via `asyncio.to_thread()`. This prevents blocking the asyncio event loop during network I/O, improving responsiveness during concurrent device backups.
- **Shared SnmpEngine Architecture** (Performance Fix #4): Replaced per-request `SnmpEngine()` instantiation with a single shared engine for the entire backup session. This reduces CPU overhead and prevents USM state (snmpEngineBoots/Time) replay protection issues on hardened Cisco devices enforcing RFC 3414 timeliness checks.
- **Enhanced Error Messages**: SSH host key verification failures now include actionable troubleshooting steps with example commands (`ssh-keyscan`, manual SSH).

### Security
- **Critical**: Replaced insecure `paramiko.AutoAddPolicy()` with `paramiko.RejectPolicy()` for SSH host key verification
- **Critical**: Automatic permission hardening (chmod 0600) for generated configuration files containing plaintext credentials
- **Important**: Added detailed SSH security documentation in README with first-time setup procedures

### Performance
- Non-blocking async I/O for all paramiko operations (prevents event loop blocking)
- Shared SNMP engine reduces per-request CPU overhead and eliminates USM replay protection errors
- Improved concurrent device backup throughput

### Documentation
- Added comprehensive "SSH Host Key Verification" section to README
- Documented new `known_hosts_file` configuration parameter
- Updated `config.yaml.example` with hostname resolution and custom known_hosts examples
- Added "Security Considerations" section with best practices for production deployments

### Fixed
- Resolved USM replay protection failures on Cisco devices with strict RFC 3414 enforcement
- Fixed event loop blocking during SSH/SFTP operations in high-concurrency scenarios
- Fixed crash when SCP server is specified as hostname instead of IP address

## [1.0.0] - 2026-02-01

### Added
- Initial release of Cisco IOS Configuration Backup via SNMPv3 + SCP
- SNMPv3-only authentication with support for SHA256/SHA512 + AES256 encryption
- Secure SCP file transfer over SSH (replacing insecure TFTP)
- Async I/O with asyncio for parallel device backups
- Automatic backup file downloads from SCP server to local storage
- Configurable retention policy with automatic cleanup of old backups
- YAML-based configuration with device inventory management
- Comprehensive error handling and logging
- SHA256 checksum generation for downloaded backups
- Cron-friendly operation with exit codes
- Device information discovery via SNMP (sysDescr, sysName, sysUpTime, etc.)
- Support for per-device SNMPv3 credential overrides
- Backup report generation (YAML format)
- Verification-only mode (--verify-only) for testing connectivity
- Cleanup-only mode (--cleanup-only) for scheduled maintenance
- Sample configuration generator (--generate-config)

### Security
- SNMPv3 with authentication and privacy (authPriv security level)
- SCP over SSH for encrypted file transfer (no plaintext TFTP)
- Support for modern cryptographic algorithms (SHA256, AES256)
- Credentials isolated in configuration file (not hardcoded)

### Documentation
- Complete README with installation instructions
- Cisco device configuration examples (SNMPv3 setup, SCP server enable)
- Troubleshooting guide with common issues and solutions
- Cron job setup examples
- MIT License

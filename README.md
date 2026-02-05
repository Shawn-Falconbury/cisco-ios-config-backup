# Cisco Configuration Backup via SNMPv3 + SCP

Automated backup of Cisco IOS router and switch configurations using SNMPv3 for secure management and SCP for encrypted file transfer.

## Features

- **SNMPv3 Only** - Secure authentication (SHA256/SHA512) and encryption (AES256)
- **SCP Transfer** - Encrypted configuration transfer over SSH (no plaintext TFTP)
- **SSH Host Key Verification** - Protection against man-in-the-middle attacks
- **Async I/O** - Efficient parallel backups using Python asyncio
- **Automatic Download** - Optionally pulls backups from SCP server to local storage
- **Retention Policy** - Automatic cleanup of old backup files
- **YAML Configuration** - Easy device inventory management with hostname resolution support
- **Cron-friendly** - Designed for scheduled execution with secure credential handling

## Security Advantages Over TFTP

| Feature | TFTP | SCP |
|---------|------|-----|
| Encryption | None (plaintext) | SSH encryption |
| Authentication | None | Username/password or keys |
| Host verification | None | SSH host key validation |
| Port | UDP 69 | TCP 22 |
| Firewall friendly | No (dynamic ports) | Yes (single port) |

## Requirements

### Python Libraries

```bash
pip install pysnmp==6.2.6 pyyaml paramiko --break-system-packages
```

**Libraries Used:**
- `pysnmp` (v6.2.6) - Actively maintained SNMP library for Python 3
- `pyyaml` - YAML configuration parsing  
- `paramiko` - SSH/SCP client for downloading backups locally

## Cisco Device Configuration

### Enable SCP Server

```cisco
ip scp server enable
aaa new-model
aaa authentication login default local
aaa authorization exec default local
username admin privilege 15 secret YourAdminPassword
```

### Configure SNMPv3

```cisco
snmp-server view BACKUP-VIEW iso included
snmp-server group BACKUP-GROUP v3 priv read BACKUP-VIEW write BACKUP-VIEW
snmp-server user backupuser BACKUP-GROUP v3 auth sha256 AuthPass123!Secure priv aes 256 PrivPass123!Secure

! Restrict to backup server (recommended)
access-list 98 permit host 192.168.1.10
snmp-server group BACKUP-GROUP v3 priv read BACKUP-VIEW write BACKUP-VIEW access 98
```

## Installation

```bash
# Clone repository
git clone https://github.com/Shawn-Falconbury/Cisco-IOS-config-backup.git
cd Cisco-IOS-config-backup

# Install dependencies
pip install pysnmp==6.2.6 pyyaml paramiko --break-system-packages

# Copy and edit configuration
cp config.yaml.example config.yaml
chmod 600 config.yaml
nano config.yaml
```

## SSH Host Key Verification

**IMPORTANT**: This script enforces SSH host key verification to prevent man-in-the-middle attacks. Before running backups for the first time, you must establish trust with your SCP server.

### First-Time Setup

Connect to your SCP server manually to seed the SSH host key:

```bash
# Method 1: Interactive SSH (recommended for first-time setup)
ssh cisco_backup@192.168.1.10
# Type "yes" when prompted to accept the host key, then exit

# Method 2: Non-interactive (for automation)
ssh-keyscan -p 22 192.168.1.10 >> ~/.ssh/known_hosts
```

### Custom known_hosts File (Optional)

For production deployments or air-gapped environments, you can specify a custom `known_hosts` file in your configuration:

```yaml
scp_server:
  ip_address: 192.168.1.10
  username: cisco_backup
  password: SecureScpPass123!
  port: 22
  remote_path: /var/backups/cisco
  known_hosts_file: /etc/cisco_backup/known_hosts  # Optional
```

To populate a custom known_hosts file:

```bash
# Create the directory
sudo mkdir -p /etc/cisco_backup

# Scan and save the host key
ssh-keyscan -p 22 192.168.1.10 | sudo tee /etc/cisco_backup/known_hosts

# Set secure permissions
sudo chmod 644 /etc/cisco_backup/known_hosts
```

### Troubleshooting Host Key Errors

If you see `Server <ip> not found in known_hosts`, this means:
- The SCP server's host key is not trusted
- The server's host key has changed (possible MitM attack or server reinstall)

**To fix:**
1. Remove the old key: `ssh-keygen -R 192.168.1.10`
2. Re-establish trust: `ssh cisco_backup@192.168.1.10`

## Usage

```bash
# Run backup
./cisco_config_backup.py -c config.yaml

# Verbose mode
./cisco_config_backup.py -c config.yaml -v

# Verify connectivity only (tests SSH host keys + SNMPv3)
./cisco_config_backup.py -c config.yaml --verify-only

# Cleanup old backups only
./cisco_config_backup.py -c config.yaml --cleanup-only

# Generate sample config (auto-applies chmod 600)
./cisco_config_backup.py --generate-config config.yaml
```

## Cron Job Setup

```bash
# Daily backup at 2:00 AM
0 2 * * * /path/to/cisco_config_backup.py -c /path/to/config.yaml >> /var/log/cisco_backup_cron.log 2>&1
```

## Configuration File

**Complete Example with All Options:**

```yaml
scp_server:
  # SCP server can be an IP address or resolvable hostname
  ip_address: 192.168.1.10  # or: scp.backup.local
  username: cisco_backup
  password: SecureScpPass123!
  port: 22
  remote_path: /var/backups/cisco
  # Optional: Custom known_hosts file for SSH host key verification
  # known_hosts_file: /etc/cisco_backup/known_hosts

backup:
  backup_dir: /var/backups/cisco
  max_workers: 5  # Concurrent device backups
  retention_days: 30
  log_file: /var/log/cisco_backup.log
  log_level: INFO  # DEBUG, INFO, WARNING, ERROR
  poll_interval: 2  # Seconds between SNMP copy status polls
  max_poll_attempts: 60  # Max polls before timeout

snmpv3_defaults:
  username: backupuser
  auth_protocol: SHA256  # MD5, SHA, SHA224, SHA256, SHA384, SHA512
  auth_password: AuthPass123!Secure
  priv_protocol: AES256  # DES, 3DES, AES128, AES192, AES256
  priv_password: PrivPass123!Secure
  security_level: authPriv  # noAuthNoPriv, authNoPriv, authPriv

devices:
  - hostname: ROUTER-01
    ip_address: 10.0.0.1
  
  - hostname: SWITCH-01
    ip_address: 10.0.0.10
    # Per-device SNMPv3 override (optional)
    snmpv3:
      username: different_user
      auth_password: DifferentPass
```

## Security Considerations

### Credential Protection

1. **Configuration File Permissions**: Always protect config.yaml with restrictive permissions:
   ```bash
   chmod 600 config.yaml
   chown root:root config.yaml  # If running as root
   ```

2. **Logging Credentials**: The script never logs passwords. Debug logs show masked credentials.

3. **SSH Host Key Enforcement**: The script uses `paramiko.RejectPolicy()` — connections to servers with unknown or mismatched keys will fail. This prevents MitM attacks.

4. **SNMPv3 Replay Protection**: The script uses a shared SNMP engine to maintain USM state, preventing replay attacks as defined in RFC 3414.

### Production Best Practices

- Store `config.yaml` in `/etc/cisco_backup/` with `chmod 600`
- Use a dedicated backup service account with minimal privileges
- Regularly rotate SNMPv3 and SCP passwords
- Enable SNMP access-lists on Cisco devices to restrict backup server IP
- Monitor backup logs for authentication failures (possible attacks)
- Use custom `known_hosts_file` for centralized SSH key management
- Schedule backups during maintenance windows to minimize load

### Network Security

- Firewall rules: Only allow backup server → Cisco devices (UDP 161) and Cisco devices → SCP server (TCP 22)
- Consider running backups over a dedicated management VLAN
- Use SNMPv3 with authPriv security level (authentication + encryption)

## Troubleshooting

### Test SNMPv3 Connectivity

```bash
snmpwalk -v3 -u backupuser -l authPriv \
  -a SHA256 -A "AuthPass123!Secure" \
  -x AES256 -X "PrivPass123!Secure" \
  10.0.0.1 sysDescr.0
```

### Test SCP from Cisco Device

```cisco
copy running-config scp://cisco_backup@192.168.1.10/var/backups/cisco/test.cfg
```

### Common Issues

| Error | Cause | Solution |
|-------|-------|----------|
| `Server <ip> not found in known_hosts` | SSH host key not trusted | Run `ssh-keyscan` or manual SSH to establish trust |
| `wrongDigest` | SNMPv3 password or auth protocol mismatch | Verify credentials in config match device |
| `SNMP timeout` | Firewall blocking UDP 161 or wrong IP | Check firewall, verify device IP and SNMP config |
| `badFileName` | SCP remote path doesn't exist or no write permission | Verify path exists and SCP user has write access |
| `SCP timeout` | Device can't reach SCP server | Test SSH from device: `ssh cisco_backup@192.168.1.10` |
| `USM unknown user name` | SNMPv3 user not configured on device | Verify `snmp-server user` configuration |
| `Cannot resolve SCP server address` | Hostname in config doesn't resolve | Use IP address or verify DNS resolution |

### Detailed Logging

Enable debug logging to see all SNMP OID operations:

```bash
./cisco_config_backup.py -c config.yaml -v
```

Debug logs show:
- SNMP GET/SET operations with OIDs
- SSH host key verification steps
- Copy operation polling states
- Row index assignments for CISCO-CONFIG-COPY-MIB

## How It Works

1. **Initialization**: Script creates a shared SnmpEngine and verifies SCP server connectivity (SSH host key check)
2. **Device Connection**: Connects to each device via SNMPv3 and retrieves device info (sysDescr, sysName, etc.)
3. **Copy Job Creation**: Uses CISCO-CONFIG-COPY-MIB to configure a backup job:
   - Protocol: SCP (4)
   - Source: running-config (4)
   - Destination: network file (1)
   - Server: Resolved IPv4 address of SCP server
   - Credentials: SCP username/password
4. **Device-Initiated Transfer**: Device establishes SCP connection to backup server and pushes running-config
5. **Status Polling**: Script polls SNMP `ccCopyState` until job completes or fails
6. **Download (Optional)**: If configured, script downloads backup from SCP server to local storage via SFTP
7. **Verification**: Generates SHA256 checksum of downloaded backup
8. **Cleanup**: Removes backups older than configured retention period

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and detailed release notes.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test thoroughly in a lab environment
4. Submit a pull request with detailed description

## License

MIT License - See [LICENSE](LICENSE) for details

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/Shawn-Falconbury/Cisco-IOS-config-backup/issues
- Pull Requests: https://github.com/Shawn-Falconbury/Cisco-IOS-config-backup/pulls

**⚠️ Security Note**: This script handles sensitive credentials. Always review code before deploying to production environments.

# Cisco Configuration Backup via SNMPv3 + SCP

Automated backup of Cisco IOS router and switch configurations using SNMPv3 for secure management and SCP for encrypted file transfer.

## Features

- **SNMPv3 Only** - Secure authentication (SHA256/SHA512) and encryption (AES256)
- **SCP Transfer** - Encrypted configuration transfer over SSH (no plaintext TFTP)
- **Async I/O** - Efficient parallel backups using Python asyncio
- **Automatic Download** - Optionally pulls backups from SCP server to local storage
- **Retention Policy** - Automatic cleanup of old backup files
- **YAML Configuration** - Easy device inventory management
- **Cron-friendly** - Designed for scheduled execution

## Security Advantages Over TFTP

| Feature | TFTP | SCP |
|---------|------|-----|
| Encryption | None (plaintext) | SSH encryption |
| Authentication | None | Username/password or keys |
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

## Usage

```bash
# Run backup
./cisco_config_backup.py -c config.yaml

# Verbose mode
./cisco_config_backup.py -c config.yaml -v

# Verify connectivity only
./cisco_config_backup.py -c config.yaml --verify-only

# Cleanup old backups only
./cisco_config_backup.py -c config.yaml --cleanup-only

# Generate sample config
./cisco_config_backup.py --generate-config config.yaml
```

## Cron Job Setup

```bash
# Daily backup at 2:00 AM
0 2 * * * /path/to/cisco_config_backup.py -c /path/to/config.yaml
```

## Configuration File

```yaml
scp_server:
  ip_address: 192.168.1.10
  username: cisco_backup
  password: SecureScpPass123!
  port: 22
  remote_path: /var/backups/cisco

backup:
  backup_dir: /var/backups/cisco
  max_workers: 5
  retention_days: 30
  log_file: /var/log/cisco_backup.log
  log_level: INFO

snmpv3_defaults:
  username: backupuser
  auth_protocol: SHA256
  auth_password: AuthPass123!Secure
  priv_protocol: AES256
  priv_password: PrivPass123!Secure
  security_level: authPriv

devices:
  - hostname: ROUTER-01
    ip_address: 10.0.0.1
  - hostname: SWITCH-01
    ip_address: 10.0.0.10
    snmpv3:
      username: different_user
      auth_password: DifferentPass
```

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

- **SNMP timeout** - Check firewall (UDP 161), verify SNMPv3 user exists
- **wrongDigest** - Password or auth protocol mismatch
- **SCP timeout** - Verify SSH connectivity from device to SCP server
- **badFileName** - Check remote path exists and user has write permission

## How It Works

1. Script connects to device via SNMPv3
2. Uses CISCO-CONFIG-COPY-MIB to create a copy job
3. Device initiates SCP connection to backup server
4. Device pushes running-config over encrypted SSH
5. Script polls for completion status
6. Optionally downloads local copy via paramiko

## License

MIT License

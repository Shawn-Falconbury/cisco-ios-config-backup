#!/usr/bin/env python3
"""
Cisco Configuration Backup Script via SNMPv3 with SCP Transfer
===============================================================
Backs up running configurations from Cisco IOS devices using SNMPv3
and SCP (Secure Copy Protocol) for secure file transfer.

This script uses the CISCO-CONFIG-COPY-MIB to trigger configuration copies
from running-config to an SCP server with encrypted transfer.

Requirements:
    pip install pysnmp==6.2.6 pyyaml paramiko --break-system-packages

Author: Network Automation Script
License: MIT
"""

import os
import sys
import logging
import argparse
import yaml
import socket
import hashlib
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
import asyncio

# pysnmp imports (v6.x - actively maintained)
from pysnmp.hlapi.asyncio import (
    getCmd,
    setCmd,
    SnmpEngine,
    UsmUserData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
)
from pysnmp.hlapi.asyncio import (
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmDESPrivProtocol,
    usm3DESEDEPrivProtocol,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)
from pysnmp.smi.rfc1902 import Integer, OctetString, IpAddress


# =============================================================================
# Configuration and Constants
# =============================================================================

# CISCO-CONFIG-COPY-MIB OIDs
CISCO_CONFIG_COPY_MIB = {
    'ccCopyProtocol': '1.3.6.1.4.1.9.9.96.1.1.1.1.2',
    'ccCopySourceFileType': '1.3.6.1.4.1.9.9.96.1.1.1.1.3',
    'ccCopyDestFileType': '1.3.6.1.4.1.9.9.96.1.1.1.1.4',
    'ccCopyServerAddress': '1.3.6.1.4.1.9.9.96.1.1.1.1.5',
    'ccCopyFileName': '1.3.6.1.4.1.9.9.96.1.1.1.1.6',
    'ccCopyUserName': '1.3.6.1.4.1.9.9.96.1.1.1.1.7',
    'ccCopyUserPassword': '1.3.6.1.4.1.9.9.96.1.1.1.1.8',
    'ccCopyState': '1.3.6.1.4.1.9.9.96.1.1.1.1.10',
    'ccCopyTimeStarted': '1.3.6.1.4.1.9.9.96.1.1.1.1.11',
    'ccCopyTimeCompleted': '1.3.6.1.4.1.9.9.96.1.1.1.1.12',
    'ccCopyFailCause': '1.3.6.1.4.1.9.9.96.1.1.1.1.13',
    'ccCopyEntryRowStatus': '1.3.6.1.4.1.9.9.96.1.1.1.1.14',
    'ccCopyServerAddressType': '1.3.6.1.4.1.9.9.96.1.1.1.1.15',
    'ccCopyServerAddressRev1': '1.3.6.1.4.1.9.9.96.1.1.1.1.16',
}

COPY_PROTOCOL = {'tftp': 1, 'ftp': 2, 'rcp': 3, 'scp': 4, 'sftp': 5}
FILE_TYPE = {'networkFile': 1, 'iosFile': 2, 'startupConfig': 3, 'runningConfig': 4, 'terminal': 5, 'fabricStartupConfig': 6}
COPY_STATE = {1: 'waiting', 2: 'running', 3: 'successful', 4: 'failed'}
FAIL_CAUSE = {1: 'unknown', 2: 'badFileName', 3: 'timeout', 4: 'noMem', 5: 'noConfig', 6: 'unsupportedProtocol', 7: 'someConfigApplyFailed', 8: 'systemNotReady', 9: 'requestAborted'}
ROW_STATUS = {'active': 1, 'notInService': 2, 'notReady': 3, 'createAndGo': 4, 'createAndWait': 5, 'destroy': 6}
DEVICE_INFO_OIDS = {'sysDescr': '1.3.6.1.2.1.1.1.0', 'sysName': '1.3.6.1.2.1.1.5.0', 'sysUpTime': '1.3.6.1.2.1.1.3.0', 'sysContact': '1.3.6.1.2.1.1.4.0', 'sysLocation': '1.3.6.1.2.1.1.6.0'}


@dataclass
class SNMPv3Credentials:
    """SNMPv3 authentication credentials."""
    username: str
    auth_protocol: str = 'SHA256'
    auth_password: str = ''
    priv_protocol: str = 'AES256'
    priv_password: str = ''
    security_level: str = 'authPriv'


@dataclass
class SCPCredentials:
    """SCP server credentials for file transfer."""
    server_ip: str
    username: str
    password: str
    port: int = 22
    remote_path: str = '/backups'


@dataclass
class DeviceConfig:
    """Configuration for a single Cisco device."""
    hostname: str
    ip_address: str
    snmpv3: SNMPv3Credentials
    snmp_port: int = 161
    timeout: int = 30
    retries: int = 3


@dataclass
class BackupConfig:
    """Global backup configuration."""
    backup_dir: str = '/var/backups/cisco'
    scp: SCPCredentials = None
    max_workers: int = 5
    retention_days: int = 30
    log_file: str = '/var/log/cisco_backup.log'
    log_level: str = 'INFO'
    poll_interval: int = 2
    max_poll_attempts: int = 60


def setup_logging(log_file: str, log_level: str) -> logging.Logger:
    """Configure logging with both file and console output."""
    logger = logging.getLogger('cisco_backup')
    logger.setLevel(getattr(logging, log_level.upper()))
    if logger.handlers:
        return logger
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def get_auth_protocol(proto_name: str):
    """Map authentication protocol name to pysnmp object."""
    auth_protocols = {
        'MD5': usmHMACMD5AuthProtocol, 'SHA': usmHMACSHAAuthProtocol, 'SHA1': usmHMACSHAAuthProtocol,
        'SHA224': usmHMAC128SHA224AuthProtocol, 'SHA256': usmHMAC192SHA256AuthProtocol,
        'SHA384': usmHMAC256SHA384AuthProtocol, 'SHA512': usmHMAC384SHA512AuthProtocol,
        'NONE': usmNoAuthProtocol, None: usmNoAuthProtocol,
    }
    return auth_protocols.get(proto_name.upper() if proto_name else None, usmHMAC192SHA256AuthProtocol)


def get_priv_protocol(proto_name: str):
    """Map privacy protocol name to pysnmp object."""
    priv_protocols = {
        'DES': usmDESPrivProtocol, '3DES': usm3DESEDEPrivProtocol, 'AES': usmAesCfb128Protocol,
        'AES128': usmAesCfb128Protocol, 'AES192': usmAesCfb192Protocol, 'AES256': usmAesCfb256Protocol,
        'NONE': usmNoPrivProtocol, None: usmNoPrivProtocol,
    }
    return priv_protocols.get(proto_name.upper() if proto_name else None, usmAesCfb256Protocol)


def get_snmpv3_auth(snmpv3: SNMPv3Credentials) -> UsmUserData:
    """Create SNMPv3 USM authentication object."""
    return UsmUserData(
        snmpv3.username,
        authKey=snmpv3.auth_password if snmpv3.auth_password else None,
        privKey=snmpv3.priv_password if snmpv3.priv_password else None,
        authProtocol=get_auth_protocol(snmpv3.auth_protocol),
        privProtocol=get_priv_protocol(snmpv3.priv_protocol),
    )


async def snmp_get(device: DeviceConfig, oid: str) -> Optional[Any]:
    """Perform SNMPv3 GET operation."""
    try:
        iterator = getCmd(
            SnmpEngine(), get_snmpv3_auth(device.snmpv3),
            await UdpTransportTarget.create((device.ip_address, device.snmp_port), timeout=device.timeout, retries=device.retries),
            ContextData(), ObjectType(ObjectIdentity(oid))
        )
        errorIndication, errorStatus, errorIndex, varBinds = await iterator
        if errorIndication:
            raise Exception(f"SNMP error: {errorIndication}")
        elif errorStatus:
            raise Exception(f"SNMP error: {errorStatus.prettyPrint()} at {varBinds[int(errorIndex) - 1][0] if errorIndex else '?'}")
        for varBind in varBinds:
            return varBind[1]
    except Exception as e:
        raise Exception(f"SNMPv3 GET failed for {device.hostname}: {e}")


async def snmp_set(device: DeviceConfig, oid: str, value) -> bool:
    """Perform SNMPv3 SET operation."""
    try:
        iterator = setCmd(
            SnmpEngine(), get_snmpv3_auth(device.snmpv3),
            await UdpTransportTarget.create((device.ip_address, device.snmp_port), timeout=device.timeout, retries=device.retries),
            ContextData(), ObjectType(ObjectIdentity(oid), value)
        )
        errorIndication, errorStatus, errorIndex, varBinds = await iterator
        if errorIndication:
            raise Exception(f"SNMP error: {errorIndication}")
        elif errorStatus:
            raise Exception(f"SNMP error: {errorStatus.prettyPrint()}")
        return True
    except Exception as e:
        raise Exception(f"SNMPv3 SET failed for {device.hostname}: {e}")


async def backup_via_scp(device: DeviceConfig, scp_config: SCPCredentials, backup_filename: str, backup_config: BackupConfig, logger: logging.Logger) -> bool:
    """Backup configuration using CISCO-CONFIG-COPY-MIB via SCP."""
    import random
    row_index = random.randint(100, 65535)
    remote_file = f"{scp_config.remote_path.rstrip('/')}/{backup_filename}"
    
    try:
        logger.info(f"[{device.hostname}] Starting SCP backup to {scp_config.server_ip}:{remote_file}")
        ip_parts = [int(x) for x in scp_config.server_ip.split('.')]
        ip_bytes = bytes(ip_parts)
        
        logger.debug(f"[{device.hostname}] Setting copy protocol to SCP (4)")
        await snmp_set(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyProtocol']}.{row_index}", Integer(COPY_PROTOCOL['scp']))
        
        logger.debug(f"[{device.hostname}] Setting source to running-config")
        await snmp_set(device, f"{CISCO_CONFIG_COPY_MIB['ccCopySourceFileType']}.{row_index}", Integer(FILE_TYPE['runningConfig']))
        
        logger.debug(f"[{device.hostname}] Setting destination to network file")
        await snmp_set(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyDestFileType']}.{row_index}", Integer(FILE_TYPE['networkFile']))
        
        logger.debug(f"[{device.hostname}] Setting server address type to IPv4")
        await snmp_set(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyServerAddressType']}.{row_index}", Integer(1))
        
        logger.debug(f"[{device.hostname}] Setting server address to {scp_config.server_ip}")
        await snmp_set(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyServerAddressRev1']}.{row_index}", OctetString(hexValue=ip_bytes.hex()))
        
        logger.debug(f"[{device.hostname}] Setting filename to {remote_file}")
        await snmp_set(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyFileName']}.{row_index}", OctetString(remote_file))
        
        logger.debug(f"[{device.hostname}] Setting SCP username")
        await snmp_set(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyUserName']}.{row_index}", OctetString(scp_config.username))
        
        logger.debug(f"[{device.hostname}] Setting SCP password")
        await snmp_set(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyUserPassword']}.{row_index}", OctetString(scp_config.password))
        
        logger.debug(f"[{device.hostname}] Activating copy operation")
        await snmp_set(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyEntryRowStatus']}.{row_index}", Integer(ROW_STATUS['createAndGo']))
        
        logger.info(f"[{device.hostname}] Waiting for SCP transfer to complete...")
        
        for attempt in range(backup_config.max_poll_attempts):
            await asyncio.sleep(backup_config.poll_interval)
            try:
                state_val = await snmp_get(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyState']}.{row_index}")
                state_int = int(state_val) if state_val else 0
                state_str = COPY_STATE.get(state_int, 'unknown')
                logger.debug(f"[{device.hostname}] Copy state: {state_str} (attempt {attempt + 1})")
                
                if state_int == 3:
                    logger.info(f"[{device.hostname}] SCP backup completed successfully")
                    try:
                        await snmp_set(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyEntryRowStatus']}.{row_index}", Integer(ROW_STATUS['destroy']))
                    except Exception as cleanup_err:
                        logger.debug(f"[{device.hostname}] Row cleanup note: {cleanup_err}")
                    return True
                elif state_int == 4:
                    fail_val = await snmp_get(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyFailCause']}.{row_index}")
                    fail_int = int(fail_val) if fail_val else 1
                    fail_str = FAIL_CAUSE.get(fail_int, f'unknown ({fail_int})')
                    try:
                        await snmp_set(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyEntryRowStatus']}.{row_index}", Integer(ROW_STATUS['destroy']))
                    except:
                        pass
                    raise Exception(f"SCP copy failed: {fail_str}")
            except Exception as poll_err:
                if "failed" in str(poll_err).lower():
                    raise
                logger.debug(f"[{device.hostname}] Poll error (will retry): {poll_err}")
        
        raise Exception(f"Copy operation timed out after {backup_config.max_poll_attempts * backup_config.poll_interval} seconds")
    except Exception as e:
        logger.error(f"[{device.hostname}] SCP backup failed: {e}")
        try:
            await snmp_set(device, f"{CISCO_CONFIG_COPY_MIB['ccCopyEntryRowStatus']}.{row_index}", Integer(ROW_STATUS['destroy']))
        except:
            pass
        return False


async def get_device_info(device: DeviceConfig, logger: logging.Logger) -> Dict[str, str]:
    """Get basic device information via SNMPv3."""
    info = {}
    for name, oid in DEVICE_INFO_OIDS.items():
        try:
            value = await snmp_get(device, oid)
            info[name] = str(value) if value else None
            logger.debug(f"[{device.hostname}] {name}: {info[name]}")
        except Exception as e:
            logger.warning(f"[{device.hostname}] Failed to get {name}: {e}")
            info[name] = None
    return info


async def verify_scp_server(scp_config: SCPCredentials, logger: logging.Logger) -> bool:
    """Verify SCP server is accessible using paramiko."""
    try:
        import paramiko
        logger.info(f"Verifying SCP server connectivity to {scp_config.server_ip}...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=scp_config.server_ip, port=scp_config.port, username=scp_config.username,
                      password=scp_config.password, timeout=10, allow_agent=False, look_for_keys=False)
        sftp = client.open_sftp()
        try:
            sftp.stat(scp_config.remote_path)
            logger.info(f"SCP server verified: {scp_config.remote_path} exists")
        except FileNotFoundError:
            logger.warning(f"Creating backup directory: {scp_config.remote_path}")
            sftp.mkdir(scp_config.remote_path)
        sftp.close()
        client.close()
        return True
    except ImportError:
        logger.warning("paramiko not installed - skipping SCP server verification")
        return True
    except Exception as e:
        logger.error(f"SCP server verification failed: {e}")
        return False


async def download_backup_from_scp(scp_config: SCPCredentials, remote_filename: str, local_path: Path, logger: logging.Logger) -> Optional[str]:
    """Download the backup file from SCP server to local storage."""
    try:
        import paramiko
        remote_file = f"{scp_config.remote_path.rstrip('/')}/{remote_filename}"
        local_file = local_path / remote_filename
        logger.info(f"Downloading backup from SCP server: {remote_file}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=scp_config.server_ip, port=scp_config.port, username=scp_config.username,
                      password=scp_config.password, timeout=30, allow_agent=False, look_for_keys=False)
        sftp = client.open_sftp()
        sftp.get(remote_file, str(local_file))
        sftp.close()
        client.close()
        logger.info(f"Backup downloaded to: {local_file}")
        return str(local_file)
    except ImportError:
        logger.warning("paramiko not installed - backup remains on SCP server only")
        return None
    except Exception as e:
        logger.error(f"Failed to download backup: {e}")
        return None


async def backup_device(device: DeviceConfig, backup_config: BackupConfig, logger: logging.Logger) -> Dict[str, Any]:
    """Perform backup for a single device."""
    result = {
        'hostname': device.hostname, 'ip_address': device.ip_address, 'success': False,
        'timestamp': datetime.now().isoformat(), 'backup_file': None, 'local_file': None,
        'error': None, 'device_info': {}, 'checksum': None,
    }
    try:
        logger.info(f"[{device.hostname}] Connecting via SNMPv3...")
        result['device_info'] = await get_device_info(device, logger)
        if not result['device_info'].get('sysName'):
            raise Exception("Failed to retrieve device information - check SNMPv3 credentials")
        logger.info(f"[{device.hostname}] Connected - {result['device_info'].get('sysDescr', 'Unknown')[:60]}...")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_hostname = device.hostname.replace(' ', '_').replace('/', '-').replace('\\', '-')
        backup_filename = f"{safe_hostname}_{timestamp}.cfg"
        backup_dir = Path(backup_config.backup_dir) / safe_hostname
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        if backup_config.scp:
            success = await backup_via_scp(device, backup_config.scp, backup_filename, backup_config, logger)
            if success:
                result['backup_file'] = f"scp://{backup_config.scp.server_ip}{backup_config.scp.remote_path}/{backup_filename}"
                result['success'] = True
                local_file = await download_backup_from_scp(backup_config.scp, backup_filename, backup_dir, logger)
                if local_file:
                    result['local_file'] = local_file
                    with open(local_file, 'rb') as f:
                        result['checksum'] = hashlib.sha256(f.read()).hexdigest()
        else:
            raise Exception("No SCP server configured - cannot perform backup")
        logger.info(f"[{device.hostname}] Backup completed: {result['backup_file']}")
    except Exception as e:
        result['error'] = str(e)
        logger.error(f"[{device.hostname}] Backup failed: {e}")
    return result


def cleanup_old_backups(backup_dir: str, retention_days: int, logger: logging.Logger):
    """Remove backups older than retention_days."""
    from datetime import timedelta
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    backup_path = Path(backup_dir)
    if not backup_path.exists():
        return
    removed_count = 0
    for device_dir in backup_path.iterdir():
        if not device_dir.is_dir():
            continue
        for backup_file in device_dir.iterdir():
            if backup_file.is_file() and backup_file.suffix == '.cfg':
                file_time = datetime.fromtimestamp(backup_file.stat().st_mtime)
                if file_time < cutoff_date:
                    logger.info(f"Removing old backup: {backup_file}")
                    backup_file.unlink()
                    removed_count += 1
        if device_dir.is_dir() and not any(device_dir.iterdir()):
            device_dir.rmdir()
            logger.debug(f"Removed empty directory: {device_dir}")
    logger.info(f"Cleanup complete: {removed_count} old backups removed")


def load_config(config_file: str) -> tuple[BackupConfig, List[DeviceConfig]]:
    """Load configuration from YAML file."""
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    scp_settings = config.get('scp_server', {})
    scp_config = None
    if scp_settings:
        scp_config = SCPCredentials(
            server_ip=scp_settings['ip_address'], username=scp_settings['username'],
            password=scp_settings['password'], port=scp_settings.get('port', 22),
            remote_path=scp_settings.get('remote_path', '/backups'),
        )
    
    backup_settings = config.get('backup', {})
    backup_config = BackupConfig(
        backup_dir=backup_settings.get('backup_dir', '/var/backups/cisco'), scp=scp_config,
        max_workers=backup_settings.get('max_workers', 5), retention_days=backup_settings.get('retention_days', 30),
        log_file=backup_settings.get('log_file', '/var/log/cisco_backup.log'),
        log_level=backup_settings.get('log_level', 'INFO'), poll_interval=backup_settings.get('poll_interval', 2),
        max_poll_attempts=backup_settings.get('max_poll_attempts', 60),
    )
    
    snmpv3_defaults = config.get('snmpv3_defaults', {})
    default_snmpv3 = SNMPv3Credentials(
        username=snmpv3_defaults.get('username', 'backupuser'),
        auth_protocol=snmpv3_defaults.get('auth_protocol', 'SHA256'),
        auth_password=snmpv3_defaults.get('auth_password', ''),
        priv_protocol=snmpv3_defaults.get('priv_protocol', 'AES256'),
        priv_password=snmpv3_defaults.get('priv_password', ''),
        security_level=snmpv3_defaults.get('security_level', 'authPriv'),
    )
    
    devices = []
    for device_cfg in config.get('devices', []):
        snmpv3_cfg = device_cfg.get('snmpv3', {})
        snmpv3 = SNMPv3Credentials(
            username=snmpv3_cfg.get('username', default_snmpv3.username),
            auth_protocol=snmpv3_cfg.get('auth_protocol', default_snmpv3.auth_protocol),
            auth_password=snmpv3_cfg.get('auth_password', default_snmpv3.auth_password),
            priv_protocol=snmpv3_cfg.get('priv_protocol', default_snmpv3.priv_protocol),
            priv_password=snmpv3_cfg.get('priv_password', default_snmpv3.priv_password),
            security_level=snmpv3_cfg.get('security_level', default_snmpv3.security_level),
        )
        device = DeviceConfig(
            hostname=device_cfg['hostname'], ip_address=device_cfg['ip_address'], snmpv3=snmpv3,
            snmp_port=device_cfg.get('snmp_port', 161), timeout=device_cfg.get('timeout', 30),
            retries=device_cfg.get('retries', 3),
        )
        devices.append(device)
    return backup_config, devices


def generate_sample_config(output_file: str):
    """Generate a sample configuration file."""
    sample_config = """# Cisco Configuration Backup via SNMPv3 + SCP
# Protect this file: chmod 600 config.yaml

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
  poll_interval: 2
  max_poll_attempts: 60

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
"""
    with open(output_file, 'w') as f:
        f.write(sample_config)
    print(f"Sample configuration written to: {output_file}")
    print(f"\nIMPORTANT: Protect this file with: chmod 600 {output_file}")


async def run_backups(backup_config: BackupConfig, devices: List[DeviceConfig], logger: logging.Logger) -> List[Dict[str, Any]]:
    """Run backups for all devices with concurrency control."""
    if backup_config.scp:
        scp_ok = await verify_scp_server(backup_config.scp, logger)
        if not scp_ok:
            logger.error("SCP server verification failed - aborting backups")
            return [{'hostname': 'SYSTEM', 'success': False, 'error': 'SCP server verification failed', 'timestamp': datetime.now().isoformat()}]
    
    semaphore = asyncio.Semaphore(backup_config.max_workers)
    
    async def bounded_backup(device):
        async with semaphore:
            return await backup_device(device, backup_config, logger)
    
    tasks = [bounded_backup(device) for device in devices]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    processed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            processed_results.append({'hostname': devices[i].hostname, 'ip_address': devices[i].ip_address,
                                     'success': False, 'error': str(result), 'timestamp': datetime.now().isoformat()})
        else:
            processed_results.append(result)
    return processed_results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Backup Cisco device configurations via SNMPv3 + SCP',
                                    formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-c', '--config', help='Path to YAML configuration file')
    parser.add_argument('--generate-config', metavar='FILE', help='Generate sample configuration file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--cleanup-only', action='store_true', help='Only run backup cleanup')
    parser.add_argument('--verify-only', action='store_true', help='Verify connectivity without backing up')
    args = parser.parse_args()
    
    if args.generate_config:
        generate_sample_config(args.generate_config)
        return 0
    
    if not args.config:
        parser.print_help()
        return 1
    
    try:
        backup_config, devices = load_config(args.config)
    except FileNotFoundError:
        print(f"Error: Configuration file not found: {args.config}")
        return 1
    except Exception as e:
        print(f"Error loading configuration: {e}")
        return 1
    
    if args.verbose:
        backup_config.log_level = 'DEBUG'
    
    logger = setup_logging(backup_config.log_file, backup_config.log_level)
    logger.info("=" * 70)
    logger.info("Cisco Configuration Backup (SNMPv3 + SCP) Started")
    logger.info(f"Devices to backup: {len(devices)}")
    if backup_config.scp:
        logger.info(f"SCP Server: {backup_config.scp.server_ip}:{backup_config.scp.remote_path}")
    
    if args.cleanup_only:
        cleanup_old_backups(backup_config.backup_dir, backup_config.retention_days, logger)
        return 0
    
    if args.verify_only:
        async def verify_all():
            if backup_config.scp:
                scp_ok = await verify_scp_server(backup_config.scp, logger)
                if not scp_ok:
                    return False
            for device in devices:
                try:
                    info = await get_device_info(device, logger)
                    if info.get('sysName'):
                        logger.info(f"[{device.hostname}] OK - {info.get('sysDescr', 'Unknown')[:50]}")
                    else:
                        logger.error(f"[{device.hostname}] FAILED - No response")
                except Exception as e:
                    logger.error(f"[{device.hostname}] FAILED - {e}")
            return True
        asyncio.run(verify_all())
        return 0
    
    if not backup_config.scp:
        logger.error("No SCP server configured in config file")
        return 1
    
    start_time = datetime.now()
    try:
        results = asyncio.run(run_backups(backup_config, devices, logger))
    except KeyboardInterrupt:
        logger.warning("Backup interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Backup failed with exception: {e}")
        return 1
    
    elapsed = datetime.now() - start_time
    successful = sum(1 for r in results if r.get('success'))
    failed = len(results) - successful
    
    logger.info("=" * 70)
    logger.info(f"Backup Complete - Elapsed: {elapsed}")
    logger.info(f"Successful: {successful}, Failed: {failed}")
    
    for result in results:
        if not result.get('success'):
            logger.error(f"FAILED: {result.get('hostname', 'Unknown')} - {result.get('error', 'Unknown error')}")
    
    cleanup_old_backups(backup_config.backup_dir, backup_config.retention_days, logger)
    
    report_file = Path(backup_config.backup_dir) / 'last_backup_report.yaml'
    report_file.parent.mkdir(parents=True, exist_ok=True)
    with open(report_file, 'w') as f:
        yaml.dump({'timestamp': datetime.now().isoformat(), 'elapsed_seconds': elapsed.total_seconds(),
                  'total_devices': len(devices), 'successful': successful, 'failed': failed,
                  'scp_server': backup_config.scp.server_ip if backup_config.scp else None, 'results': results},
                 f, default_flow_style=False)
    logger.info(f"Report saved to: {report_file}")
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""
BlockWave-Ransom Backup Restore Module

This module provides functionality to:
- List available borgbackup snapshots
- Restore full or partial backups
- Validate restored files with checksums
- Support dry-run mode to preview restore operations
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import yaml
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("backup_restore")


class RestoreStatus(Enum):
    """Status of a restore operation"""
    PENDING = auto()
    IN_PROGRESS = auto()
    COMPLETED = auto()
    FAILED = auto()
    VERIFICATION_FAILED = auto()


@dataclass
class SnapshotInfo:
    """Information about a borgbackup snapshot"""
    name: str
    time: datetime
    description: str
    size: int
    path: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "name": self.name,
            "time": self.time.isoformat() if self.time else None,
            "description": self.description,
            "size": self.size,
            "path": self.path
        }


@dataclass
class RestoreOperation:
    """Details of a backup restore operation"""
    operation_id: str
    snapshot: str
    target_path: str
    items: List[str]
    start_time: float
    status: RestoreStatus = RestoreStatus.PENDING
    end_time: Optional[float] = None
    error: Optional[str] = None
    restored_files: List[str] = field(default_factory=list)
    failed_files: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "operation_id": self.operation_id,
            "snapshot": self.snapshot,
            "target_path": self.target_path,
            "items": self.items,
            "start_time": self.start_time,
            "status": self.status.name,
            "end_time": self.end_time,
            "error": self.error,
            "restored_files_count": len(self.restored_files),
            "failed_files_count": len(self.failed_files)
        }


class BackupRestore:
    """
    Handles backup restore operations using borgbackup.
    
    This class:
    1. Lists available borgbackup snapshots (archives)
    2. Restores full or partial backups to specified target paths
    3. Verifies restored files using checksums
    4. Supports dry-run mode to preview operations
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize the backup restore module with configuration"""
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Settings
        settings = self.config.get("backup_restore", {})
        self.borg_repo = settings.get("borg_repo", "")
        self.passphrase = settings.get("passphrase", "")
        self.restore_temp_dir = settings.get("restore_temp_dir", "/tmp/blockwave/restore")
        self.verify_checksums = settings.get("verify_checksums", True)
        self.hash_algorithm = settings.get("hash_algorithm", "sha256")
        self.concurrent_extractions = settings.get("concurrent_extractions", 4)
        
        # State tracking
        self.snapshots: List[SnapshotInfo] = []
        self.current_operations: Dict[str, RestoreOperation] = {}
        self.completed_operations: List[RestoreOperation] = []
        
        # Executor for running commands
        self.executor = None
        
        logger.info("Backup Restore module initialized")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            # Add default backup_restore config if not present
            if "backup_restore" not in config:
                config["backup_restore"] = {
                    "borg_repo": "",
                    "passphrase": "",
                    "restore_temp_dir": "/tmp/blockwave/restore",
                    "verify_checksums": True,
                    "hash_algorithm": "sha256",
                    "concurrent_extractions": 4,
                    "logging": {
                        "level": "INFO",
                        "file": "/var/log/blockwave/backup_restore.log"
                    }
                }
            return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)
    
    def _setup_logging(self) -> None:
        """Configure logging based on configuration"""
        log_config = self.config.get("backup_restore", {}).get("logging", {})
        log_level = getattr(logging, log_config.get("level", "INFO"))
        
        # Set up file handler if file path is provided
        if "file" in log_config and log_config["file"]:
            log_dir = os.path.dirname(log_config["file"])
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            file_handler = logging.FileHandler(log_config["file"])
            file_handler.setLevel(log_level)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            logger.addHandler(file_handler)
        
        logger.setLevel(log_level)
    
    async def _run_command(self, cmd: List[str], env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
        """Run a shell command asynchronously"""
        logger.debug(f"Running command: {' '.join(cmd)}")
        
        # Set up environment with borgbackup passphrase if needed
        command_env = os.environ.copy()
        if env:
            command_env.update(env)
        
        # Run the command
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=command_env
        )
        
        # Wait for command to complete
        stdout, stderr = await process.communicate()
        
        # Decode output
        stdout_str = stdout.decode('utf-8', errors='replace')
        stderr_str = stderr.decode('utf-8', errors='replace')
        
        if process.returncode != 0:
            logger.error(f"Command failed with code {process.returncode}: {stderr_str}")
        
        return process.returncode, stdout_str, stderr_str
    
    async def _ensure_repo_exists(self) -> bool:
        """Check if the borgbackup repository exists and is accessible"""
        if not self.borg_repo:
            logger.error("Borgbackup repository not configured")
            return False
        
        env = {}
        if self.passphrase:
            env["BORG_PASSPHRASE"] = self.passphrase
        
        cmd = ["borg", "info", self.borg_repo]
        returncode, stdout, stderr = await self._run_command(cmd, env)
        
        return returncode == 0
    
    async def list_snapshots(self) -> List[SnapshotInfo]:
        """List available borgbackup snapshots"""
        if not await self._ensure_repo_exists():
            return []
        
        env = {}
        if self.passphrase:
            env["BORG_PASSPHRASE"] = self.passphrase
        
        # Get list of archives in JSON format
        cmd = ["borg", "list", "--json", self.borg_repo]
        returncode, stdout, stderr = await self._run_command(cmd, env)
        
        if returncode != 0:
            logger.error(f"Failed to list snapshots: {stderr}")
            return []
        
        try:
            # Parse JSON output
            data = json.loads(stdout)
            self.snapshots = []
            
            for archive in data.get("archives", []):
                # Extract snapshot information
                snapshot = SnapshotInfo(
                    name=archive.get("name", ""),
                    time=datetime.fromisoformat(archive.get("time", "")) if "time" in archive else None,
                    description=archive.get("comment", ""),
                    size=archive.get("stats", {}).get("original_size", 0),
                    path=self.borg_repo
                )
                self.snapshots.append(snapshot)
            
            # Sort snapshots by time (newest first)
            self.snapshots.sort(key=lambda x: x.time if x.time else datetime.min, reverse=True)
            return self.snapshots
        
        except json.JSONDecodeError:
            logger.error(f"Failed to parse snapshot list: {stdout}")
            return []
        except Exception as e:
            logger.error(f"Error processing snapshot list: {e}")
            return []
    
    async def _calculate_file_hash(self, filepath: str) -> Optional[str]:
        """Calculate hash for a file using the configured algorithm"""
        try:
            h = hashlib.new(self.hash_algorithm)
            with open(filepath, 'rb') as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {filepath}: {e}")
            return None
    
    async def _verify_file(self, source_path: str, dest_path: str) -> bool:
        """Verify a restored file by comparing checksums"""
        source_hash = await self._calculate_file_hash(source_path)
        dest_hash = await self._calculate_file_hash(dest_path)
        
        if not source_hash or not dest_hash:
            return False
        
        return source_hash == dest_hash
    
    async def _extract_archive(self, snapshot_name: str, target_path: str, 
                               items: Optional[List[str]] = None, 
                               dry_run: bool = False) -> Tuple[bool, List[str], List[str]]:
        """Extract files from a snapshot to the target path"""
        if not await self._ensure_repo_exists():
            return False, [], []
        
        # Create temp directory for extraction
        temp_dir = os.path.join(self.restore_temp_dir, f"restore_{int(time.time())}")
        os.makedirs(temp_dir, exist_ok=True)
        
        env = {}
        if self.passphrase:
            env["BORG_PASSPHRASE"] = self.passphrase
        
        # Build borg extract command
        cmd = ["borg", "extract"]
        if dry_run:
            cmd.append("--dry-run")
        
        # Add archive path
        archive_path = f"{self.borg_repo}::{snapshot_name}"
        cmd.append(archive_path)
        
        # Add directory to extract to
        cmd.extend(["-p", "--directory", temp_dir])
        
        # Add specific items if provided
        if items:
            cmd.extend(items)
        
        # Run extract command
        returncode, stdout, stderr = await self._run_command(cmd, env)
        
        if returncode != 0:
            logger.error(f"Extraction failed: {stderr}")
            # Clean up temp directory
            if os.path.exists(temp_dir) and not dry_run:
                shutil.rmtree(temp_dir)
            return False, [], []
        
        # If dry run, just return success
        if dry_run:
            # Parse the output to get the list of files that would be extracted
            file_list = []
            for line in stdout.splitlines():
                # Borgbackup dry-run output format varies, but typically shows files with their paths
                match = re.search(r'would extract (\S+)', line)
                if match:
                    file_list.append(match.group(1))
            
            # Clean up temp directory
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            
            return True, file_list, []
        
        # Get list of extracted files
        extracted_files = []
        for root, _, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                extracted_files.append(os.path.relpath(file_path, temp_dir))
        
        # Move files to target path
        moved_files = []
        failed_files = []
        
        for file in extracted_files:
            source = os.path.join(temp_dir, file)
            dest = os.path.join(target_path, file)
            
            try:
                # Ensure destination directory exists
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                
                # If we're verifying checksums, do it before moving
                if self.verify_checksums:
                    if not await self._verify_file(source, dest):
                        logger.warning(f"Checksum verification failed for {file}")
                        failed_files.append(file)
                        continue
                
                # Move the file
                shutil.move(source, dest)
                logger.info(f"Restored {file} to {dest}")
                moved_files.append(file)
            
            except Exception as e:
                logger.error(f"Failed to restore {file}: {e}")
                failed_files.append(file)
        
        # Clean up temp directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        
        return len(failed_files) == 0, moved_files, failed_files
    
    async def restore_snapshot(self, snapshot_name: str, target_path: str, 
                               items: Optional[List[str]] = None, 
                               dry_run: bool = False) -> RestoreOperation:
        """
        Restore a snapshot to the target path.
        
        Args:
            snapshot_name: Name of the snapshot to restore
            target_path: Target path to restore to
            items: List of specific items to restore (None for full restore)
            dry_run: If True, only show what would be restored without actually restoring
            
        Returns:
            RestoreOperation with status and details
        """
        # Generate operation ID
        operation_id = f"restore_{int(time.time())}_{snapshot_name.replace(':', '_')}"
        
        # Create restore operation object
        operation = RestoreOperation(
            operation_id=operation_id,
            snapshot=snapshot_name,
            target_path=target_path,
            items=items or [],
            start_time=time.time(),
            status=RestoreStatus.PENDING
        )
        
        # Store in current operations
        self.current_operations[operation_id] = operation
        
        try:
            # Check if snapshot exists
            snapshots = await self.list_snapshots()
            if not snapshots or not any(s.name == snapshot_name for s in snapshots):
                logger.error(f"Snapshot {snapshot_name} not found")
                operation.status = RestoreStatus.FAILED
                operation.error = f"Snapshot {snapshot_name} not found"
                return operation
            
            # Check if target path exists
            if not os.path.exists(target_path) and not dry_run:
                try:
                    os.makedirs(target_path, exist_ok=True)
                except Exception as e:
                    logger.error(f"Failed to create target directory {target_path}: {e}")
                    operation.status = RestoreStatus.FAILED
                    operation.error = f"Failed to create target directory: {str(e)}"
                    return operation
            
            # Update status
            operation.status = RestoreStatus.IN_PROGRESS
            
            # Perform extraction
            success, restored, failed = await self._extract_archive(
                snapshot_name, target_path, items, dry_run
            )
            
            # Update operation with results
            operation.end_time = time.time()
            operation.restored_files = restored
            operation.failed_files = failed
            
            if success:
                operation.status = RestoreStatus.COMPLETED
                logger.info(f"Restore operation {operation_id} completed successfully")
            else:
                if failed and self.verify_checksums:
                    operation.status = RestoreStatus.VERIFICATION_FAILED
                    operation.error = f"{len(failed)} files failed verification"
                else:
                    operation.status = RestoreStatus.FAILED
                    operation.error = "Restore operation failed"
                
                logger.warning(f"Restore operation {operation_id} failed: {operation.error}")
            
            # Move to completed operations
            if operation_id in self.current_operations:
                del self.current_operations[operation_id]
            self.completed_operations.append(operation)
            
            return operation
        
        except Exception as e:
            logger.error(f"Error in restore operation {operation_id}: {e}")
            operation.status = RestoreStatus.FAILED
            operation.error = str(e)
            operation.end_time = time.time()
            
            # Move to completed operations
            if operation_id in self.current_operations:
                del self.current_operations[operation_id]
            self.completed_operations.append(operation)
            
            return operation
    
    def get_operation_status(self, operation_id: str) -> Optional[RestoreOperation]:
        """Get the status of a restore operation"""
        # Check current operations
        if operation_id in self.current_operations:
            return self.current_operations[operation_id]
        
        # Check completed operations
        for operation in self.completed_operations:
            if operation.operation_id == operation_id:
                return operation
        
        return None


async def main():
    """Main entry point for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Backup Restore for BlockWave-Ransom')
    parser.add_argument('--config', type=str, default='config/config.yaml', help='Path to config file')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # List snapshots command
    list_parser = subparsers.add_parser('list', help='List available snapshots')
    
    # Restore snapshot command
    restore_parser = subparsers.add_parser('restore', help='Restore a snapshot')
    restore_parser.add_argument('snapshot', help='Name of the snapshot to restore')
    restore_parser.add_argument('target', help='Target path to restore to')
    restore_parser.add_argument('--items', nargs='+', help='Specific items to restore (paths relative to backup root)')
    restore_parser.add_argument('--dry-run', action='store_true', help='Show what would be restored without restoring')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Initialize backup restore
    backup_restore = BackupRestore(args.config)
    
    if args.command == 'list':
        # List snapshots
        snapshots = await backup_restore.list_snapshots()
        
        if not snapshots:
            print("No snapshots found")
            return
        
        print(f"\nFound {len(snapshots)} snapshots:\n")
        print(f"{'Name':<30} {'Time':<20} {'Size':<15} {'Description':<30}")
        print("-" * 95)
        
        for snapshot in snapshots:
            time_str = snapshot.time.strftime('%Y-%m-%d %H:%M:%S') if snapshot.time else 'Unknown'
            size_str = f"{snapshot.size / (1024*1024):.2f} MB" if snapshot.size else 'Unknown'
            print(f"{snapshot.name:<30} {time_str:<20} {size_str:<15} {snapshot.description:<30}")
    
    elif args.command == 'restore':
        # Restore snapshot
        operation = await backup_restore.restore_snapshot(
            args.snapshot, args.target, args.items, args.dry_run
        )
        
        if args.dry_run:
            print("\nDry run - files that would be restored:")
            for file in operation.restored_files:
                print(f"  {file}")
            print(f"\nTotal: {len(operation.restored_files)} files would be restored")
        else:
            print(f"\nRestore operation {operation.operation_id} {operation.status.name}")
            
            if operation.status == RestoreStatus.COMPLETED:
                print(f"Successfully restored {len(operation.restored_files)} files")
            else:
                print(f"Failed: {operation.error}")
                if operation.failed_files:
                    print(f"Failed files: {len(operation.failed_files)}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting due to keyboard interrupt")
        sys.exit(0) 
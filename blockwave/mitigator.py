#!/usr/bin/env python3
"""
BlockWave-Ransom Mitigator

This module handles mitigation actions in response to detected threats:
- Process termination (SIGTERM → SIGKILL)
- File quarantine (atomic moving to quarantine directory)
- Rollback mechanisms for failed operations
- Logging of all mitigation actions
"""

import asyncio
import logging
import os
import shutil
import signal
import sys
import time
import yaml
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple, Union
import psutil
import uuid
import json
import stat

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mitigator")


class MitigationStatus(Enum):
    """Status of a mitigation action"""
    PENDING = auto()
    IN_PROGRESS = auto()
    COMPLETED = auto()
    FAILED = auto()
    ROLLED_BACK = auto()


class MitigationType(Enum):
    """Types of mitigation actions"""
    PROCESS_TERMINATION = auto()
    FILE_QUARANTINE = auto()
    NETWORK_BLOCK = auto()
    CUSTOM_ACTION = auto()


@dataclass
class MitigationAction:
    """Details of a mitigation action to be performed"""
    action_id: str
    type: MitigationType
    timestamp: float
    target: Dict[str, Any]  # Process info or file path or other targets
    status: MitigationStatus = MitigationStatus.PENDING
    error: Optional[str] = None
    completion_time: Optional[float] = None
    rollback_info: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "action_id": self.action_id,
            "type": self.type.name,
            "timestamp": self.timestamp,
            "target": self.target,
            "status": self.status.name,
            "error": self.error,
            "completion_time": self.completion_time,
            "rollback_info": self.rollback_info
        }


class Mitigator:
    """
    Handles mitigation actions in response to security alerts.
    
    This class:
    1. Receives mitigation actions from a queue
    2. Executes process termination (SIGTERM with SIGKILL fallback)
    3. Quarantines suspicious files (with atomic operations)
    4. Logs all actions and maintains audit trails
    5. Implements rollback for failed operations
    """
    
    def __init__(self, config_path: str = "config/config.yaml", action_queue: Optional[asyncio.Queue] = None):
        """Initialize the mitigator with configuration"""
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Initialize the action queue
        self.action_queue = action_queue or asyncio.Queue(
            maxsize=self.config.get("mitigator", {}).get("queue_size", 1000)
        )
        
        # Settings
        settings = self.config.get("mitigator", {})
        self.quarantine_dir = settings.get("quarantine_dir", "/var/lib/blockwave/quarantine")
        self.quarantine_mode = settings.get("quarantine_mode", 0o750)  # Default: rwxr-x---
        self.sigkill_timeout = settings.get("sigkill_timeout_sec", 5.0)  # Time to wait before SIGKILL
        self.max_retry_count = settings.get("max_retry_count", 3)
        self.retry_delay = settings.get("retry_delay_sec", 1.0)
        
        # State tracking
        self.pending_actions: Dict[str, MitigationAction] = {}
        self.completed_actions: List[MitigationAction] = []
        self.failed_actions: List[MitigationAction] = []
        
        # Controlling flags
        self.is_running = False
        self.shutdown_event = asyncio.Event()
        
        # Audit log
        self.audit_log_path = settings.get("audit_log", "/var/log/blockwave/mitigation_audit.log")
        self._ensure_log_directory()
        
        logger.info("Mitigator initialized")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            # Add default mitigator config if not present
            if "mitigator" not in config:
                config["mitigator"] = {
                    "enabled": True,
                    "queue_size": 1000,
                    "quarantine_dir": "/var/lib/blockwave/quarantine",
                    "quarantine_mode": 0o750,  # rwxr-x---
                    "sigkill_timeout_sec": 5.0,
                    "max_retry_count": 3,
                    "retry_delay_sec": 1.0,
                    "audit_log": "/var/log/blockwave/mitigation_audit.log",
                    "logging": {
                        "level": "INFO",
                        "file": "/var/log/blockwave/mitigator.log"
                    }
                }
            return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)
    
    def _setup_logging(self) -> None:
        """Configure logging based on configuration"""
        log_config = self.config.get("mitigator", {}).get("logging", {})
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
    
    def _ensure_quarantine_directory(self) -> None:
        """Ensure the quarantine directory exists with proper permissions"""
        try:
            quarantine_path = Path(self.quarantine_dir)
            if not quarantine_path.exists():
                quarantine_path.mkdir(parents=True, exist_ok=True)
                # Set directory permissions
                os.chmod(quarantine_path, self.quarantine_mode)
                logger.info(f"Created quarantine directory: {quarantine_path}")
            
            # Create subdirectories for organization
            (quarantine_path / "files").mkdir(exist_ok=True)
            (quarantine_path / "metadata").mkdir(exist_ok=True)
            
            # Verify permissions are correct
            current_mode = stat.S_IMODE(os.stat(quarantine_path).st_mode)
            if current_mode != self.quarantine_mode:
                logger.warning(
                    f"Quarantine directory permissions incorrect. "
                    f"Current: {oct(current_mode)}, Expected: {oct(self.quarantine_mode)}"
                )
                os.chmod(quarantine_path, self.quarantine_mode)
        
        except Exception as e:
            logger.error(f"Failed to set up quarantine directory: {e}")
            raise
    
    def _ensure_log_directory(self) -> None:
        """Ensure the log directory exists"""
        if self.audit_log_path:
            log_dir = os.path.dirname(self.audit_log_path)
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
                logger.info(f"Created log directory: {log_dir}")
    
    def _record_audit_entry(self, action: MitigationAction) -> None:
        """Record an entry in the audit log"""
        if not self.audit_log_path:
            return
        
        try:
            audit_entry = {
                "timestamp": datetime.now().isoformat(),
                "action": action.to_dict()
            }
            
            with open(self.audit_log_path, "a") as f:
                f.write(json.dumps(audit_entry) + "\n")
        
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    async def terminate_process(self, action: MitigationAction) -> bool:
        """
        Terminate a process gracefully (SIGTERM), then forcefully (SIGKILL) if needed.
        
        Returns True if successful, False otherwise.
        """
        pid = action.target.get("pid")
        if not pid:
            action.status = MitigationStatus.FAILED
            action.error = "No PID provided"
            return False
        
        try:
            # Get process info
            process = psutil.Process(pid)
            action.target["name"] = process.name()
            action.target["cmdline"] = process.cmdline()
            
            # Update status
            action.status = MitigationStatus.IN_PROGRESS
            self._record_audit_entry(action)
            
            # First try SIGTERM
            logger.info(f"Sending SIGTERM to process {pid} ({action.target.get('name', 'unknown')})")
            process.terminate()
            
            # Wait for process to terminate
            try:
                process.wait(timeout=self.sigkill_timeout)
                logger.info(f"Process {pid} terminated successfully with SIGTERM")
                action.status = MitigationStatus.COMPLETED
                action.completion_time = time.time()
                self._record_audit_entry(action)
                return True
            
            except psutil.TimeoutExpired:
                # Process didn't terminate, try SIGKILL
                logger.warning(f"Process {pid} did not respond to SIGTERM, sending SIGKILL")
                process.kill()
                
                # Wait again for termination
                try:
                    process.wait(timeout=2.0)
                    logger.info(f"Process {pid} terminated successfully with SIGKILL")
                    action.status = MitigationStatus.COMPLETED
                    action.completion_time = time.time()
                    self._record_audit_entry(action)
                    return True
                
                except psutil.TimeoutExpired:
                    logger.error(f"Process {pid} could not be terminated even with SIGKILL")
                    action.status = MitigationStatus.FAILED
                    action.error = "Process could not be terminated even with SIGKILL"
                    self._record_audit_entry(action)
                    return False
        
        except psutil.NoSuchProcess:
            logger.info(f"Process {pid} no longer exists")
            action.status = MitigationStatus.COMPLETED
            action.completion_time = time.time()
            self._record_audit_entry(action)
            return True
        
        except Exception as e:
            logger.error(f"Error terminating process {pid}: {e}")
            action.status = MitigationStatus.FAILED
            action.error = f"Error: {str(e)}"
            self._record_audit_entry(action)
            return False
    
    async def quarantine_file(self, action: MitigationAction) -> bool:
        """
        Move a file to quarantine directory atomically.
        
        Returns True if successful, False otherwise.
        """
        file_path = action.target.get("file_path")
        if not file_path:
            action.status = MitigationStatus.FAILED
            action.error = "No file path provided"
            self._record_audit_entry(action)
            return False
        
        try:
            # Ensure quarantine directory exists
            self._ensure_quarantine_directory()
            
            # Update status
            action.status = MitigationStatus.IN_PROGRESS
            self._record_audit_entry(action)
            
            src_path = Path(file_path)
            if not src_path.exists():
                logger.warning(f"File {file_path} does not exist, cannot quarantine")
                action.status = MitigationStatus.FAILED
                action.error = f"File {file_path} does not exist"
                self._record_audit_entry(action)
                return False
            
            # Generate unique name for quarantined file
            quarantine_name = f"{src_path.name}_{uuid.uuid4().hex}"
            quarantine_path = Path(self.quarantine_dir) / "files" / quarantine_name
            
            # Store original metadata for potential rollback
            file_stat = src_path.stat()
            metadata = {
                "original_path": str(src_path),
                "quarantine_path": str(quarantine_path),
                "size": file_stat.st_size,
                "modified_time": file_stat.st_mtime,
                "creation_time": file_stat.st_ctime,
                "mode": file_stat.st_mode,
                "quarantine_time": time.time()
            }
            
            # Add metadata to action for rollback purposes
            action.rollback_info = metadata
            
            # Save metadata to a separate file
            metadata_path = Path(self.quarantine_dir) / "metadata" / f"{quarantine_name}.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Move file atomically
            logger.info(f"Quarantining file: {file_path} -> {quarantine_path}")
            shutil.move(src_path, quarantine_path)
            
            # Set restrictive permissions on quarantined file
            os.chmod(quarantine_path, 0o440)  # r--r-----
            
            # Update action status
            action.status = MitigationStatus.COMPLETED
            action.completion_time = time.time()
            self._record_audit_entry(action)
            
            return True
        
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}")
            action.status = MitigationStatus.FAILED
            action.error = f"Error: {str(e)}"
            self._record_audit_entry(action)
            return False
    
    async def rollback_quarantine(self, action: MitigationAction) -> bool:
        """Attempt to restore a quarantined file to its original location"""
        if not action.rollback_info:
            logger.error(f"No rollback information available for action {action.action_id}")
            return False
        
        original_path = action.rollback_info.get("original_path")
        quarantine_path = action.rollback_info.get("quarantine_path")
        
        if not original_path or not quarantine_path:
            logger.error(f"Missing path information for rollback of action {action.action_id}")
            return False
        
        try:
            # Check if quarantined file exists
            q_path = Path(quarantine_path)
            if not q_path.exists():
                logger.error(f"Quarantined file {quarantine_path} does not exist for rollback")
                return False
            
            # Check if original location is available
            orig_path = Path(original_path)
            if orig_path.exists():
                logger.warning(
                    f"Original path {original_path} already exists, cannot rollback. "
                    f"File will remain in quarantine."
                )
                return False
            
            # Ensure original directory exists
            orig_dir = orig_path.parent
            if not orig_dir.exists():
                orig_dir.mkdir(parents=True, exist_ok=True)
            
            # Move file back to original location
            logger.info(f"Rolling back quarantine: {quarantine_path} -> {original_path}")
            shutil.move(q_path, orig_path)
            
            # Restore original permissions if available
            if "mode" in action.rollback_info:
                os.chmod(orig_path, action.rollback_info["mode"])
            
            # Update action status
            action.status = MitigationStatus.ROLLED_BACK
            self._record_audit_entry(action)
            
            return True
        
        except Exception as e:
            logger.error(f"Error during rollback of quarantine action {action.action_id}: {e}")
            return False
    
    async def process_action(self, action: MitigationAction) -> None:
        """Process a single mitigation action"""
        logger.info(f"Processing mitigation action: {action.type.name} for {action.target}")
        
        retry_count = 0
        success = False
        
        while retry_count < self.max_retry_count and not success:
            if retry_count > 0:
                logger.info(f"Retrying {action.type.name} (attempt {retry_count+1}/{self.max_retry_count})")
                await asyncio.sleep(self.retry_delay)
            
            if action.type == MitigationType.PROCESS_TERMINATION:
                success = await self.terminate_process(action)
            
            elif action.type == MitigationType.FILE_QUARANTINE:
                success = await self.quarantine_file(action)
            
            elif action.type == MitigationType.NETWORK_BLOCK:
                # TODO: Implement network blocking functionality
                logger.warning("Network blocking not yet implemented")
                action.status = MitigationStatus.FAILED
                action.error = "Network blocking not implemented"
                success = False
            
            else:
                logger.error(f"Unknown mitigation type: {action.type}")
                action.status = MitigationStatus.FAILED
                action.error = f"Unknown mitigation type: {action.type}"
                success = False
            
            retry_count += 1
        
        # Handle action completion
        if success:
            self.completed_actions.append(action)
        else:
            self.failed_actions.append(action)
            
            # Try to rollback if applicable
            if action.type == MitigationType.FILE_QUARANTINE and action.rollback_info:
                logger.info(f"Attempting to rollback failed quarantine action {action.action_id}")
                await self.rollback_quarantine(action)
    
    async def action_processor(self) -> None:
        """Main loop to process mitigation actions from queue"""
        while not self.shutdown_event.is_set():
            try:
                # Wait for an action or shutdown event
                action = None
                try:
                    action = await asyncio.wait_for(
                        self.action_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    # Check shutdown flag and continue
                    continue
                
                if action is None:
                    continue
                
                # Store action in pending actions
                self.pending_actions[action.action_id] = action
                
                # Process the action
                await self.process_action(action)
                
                # Remove from pending actions
                if action.action_id in self.pending_actions:
                    del self.pending_actions[action.action_id]
                
                # Mark task as done
                self.action_queue.task_done()
            
            except asyncio.CancelledError:
                logger.info("Action processor task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in action processor: {e}")
                # Brief pause to avoid error flood
                await asyncio.sleep(1)
    
    async def start(self) -> None:
        """Start the mitigator"""
        if self.is_running:
            logger.warning("Mitigator is already running")
            return
        
        logger.info("Starting Mitigator...")
        self.is_running = True
        self.shutdown_event.clear()
        
        # Ensure quarantine directory exists
        self._ensure_quarantine_directory()
        
        # Start action processor
        self.processor_task = asyncio.create_task(self.action_processor())
        
        logger.info("Mitigator started successfully")
    
    async def stop(self) -> None:
        """Stop the mitigator"""
        if not self.is_running:
            logger.warning("Mitigator is not running")
            return
        
        logger.info("Stopping Mitigator...")
        self.shutdown_event.set()
        
        # Wait for processor to complete
        if hasattr(self, 'processor_task'):
            try:
                await asyncio.wait_for(self.processor_task, timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Timeout waiting for processor task to complete, cancelling...")
                self.processor_task.cancel()
                try:
                    await self.processor_task
                except asyncio.CancelledError:
                    pass
        
        # Process any remaining items in the queue
        remaining_count = self.action_queue.qsize()
        if remaining_count > 0:
            logger.warning(f"{remaining_count} actions still in queue during shutdown")
        
        self.is_running = False
        logger.info("Mitigator stopped")
    
    async def queue_process_termination(self, pid: int, reason: str) -> str:
        """
        Queue a process termination action.
        
        Returns the action ID.
        """
        action_id = str(uuid.uuid4())
        action = MitigationAction(
            action_id=action_id,
            type=MitigationType.PROCESS_TERMINATION,
            timestamp=time.time(),
            target={"pid": pid, "reason": reason}
        )
        
        await self.action_queue.put(action)
        logger.info(f"Queued process termination for PID {pid}: {action_id}")
        return action_id
    
    async def queue_file_quarantine(self, file_path: str, reason: str) -> str:
        """
        Queue a file quarantine action.
        
        Returns the action ID.
        """
        action_id = str(uuid.uuid4())
        action = MitigationAction(
            action_id=action_id,
            type=MitigationType.FILE_QUARANTINE,
            timestamp=time.time(),
            target={"file_path": file_path, "reason": reason}
        )
        
        await self.action_queue.put(action)
        logger.info(f"Queued file quarantine for {file_path}: {action_id}")
        return action_id
    
    def get_action_status(self, action_id: str) -> Optional[MitigationAction]:
        """Get the status of a specific action"""
        # Check pending actions
        if action_id in self.pending_actions:
            return self.pending_actions[action_id]
        
        # Check completed actions
        for action in self.completed_actions:
            if action.action_id == action_id:
                return action
        
        # Check failed actions
        for action in self.failed_actions:
            if action.action_id == action_id:
                return action
        
        return None


async def main():
    """Main entry point for testing/standalone usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Mitigator for BlockWave-Ransom')
    parser.add_argument('--config', type=str, default='config/config.yaml', help='Path to config file')
    parser.add_argument('--test', action='store_true', help='Run a test mitigation')
    parser.add_argument('--test-pid', type=int, help='Test process termination with specific PID')
    parser.add_argument('--test-file', type=str, help='Test file quarantine with specific file')
    args = parser.parse_args()
    
    # Initialize mitigator
    mitigator = Mitigator(args.config)
    
    # Start the mitigator
    await mitigator.start()
    
    try:
        if args.test:
            if args.test_pid:
                # Test process termination
                action_id = await mitigator.queue_process_termination(
                    args.test_pid, "Test mitigation"
                )
                print(f"Queued termination of PID {args.test_pid}, action ID: {action_id}")
            
            elif args.test_file:
                # Test file quarantine
                action_id = await mitigator.queue_file_quarantine(
                    args.test_file, "Test quarantine"
                )
                print(f"Queued quarantine of file {args.test_file}, action ID: {action_id}")
            
            else:
                print("No test action specified. Use --test-pid or --test-file.")
                await mitigator.stop()
                return
            
            # Wait for action to complete
            print("Waiting for action to complete...")
            await asyncio.sleep(5)
            
            # Check action status
            action = mitigator.get_action_status(action_id)
            if action:
                print(f"Action status: {action.status.name}")
                if action.error:
                    print(f"Error: {action.error}")
            else:
                print(f"Action {action_id} not found")
        
        else:
            print("Mitigator running. Press Ctrl+C to exit.")
            while True:
                await asyncio.sleep(1)
    
    except KeyboardInterrupt:
        print("\nShutting down...")
    
    finally:
        # Stop the mitigator
        await mitigator.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting due to keyboard interrupt")
        sys.exit(0) 
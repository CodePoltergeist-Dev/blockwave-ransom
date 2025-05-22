#!/usr/bin/env python3
"""
Process Inspector Module

This module monitors system processes for suspicious behavior:
- High CPU usage (>80% for >5 seconds)
- High memory consumption (>200MB)
- Unknown binary paths
It collects process metrics and publishes alerts via asyncio queue.
"""

import asyncio
import logging
import os
import sys
import time
import yaml
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple, Union

try:
    import psutil
except ImportError:
    print("Error: psutil is required. Please install it first.")
    print("pip install psutil")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("proc_inspector")


class ProcessAlertType(Enum):
    """Types of process alerts that can be generated"""
    HIGH_CPU = auto()
    HIGH_MEMORY = auto()
    UNKNOWN_BINARY = auto()
    SUSPICIOUS_NAME = auto()
    NEW_PROCESS = auto()
    TERMINATED_PROCESS = auto()


@dataclass
class ProcessInfo:
    """Information about a monitored process"""
    pid: int
    name: str
    create_time: float
    cmdline: List[str]
    exe: Optional[str] = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_bytes: int = 0
    status: str = "unknown"
    username: Optional[str] = None
    open_files: List[str] = field(default_factory=list)
    connections: List[Any] = field(default_factory=list)
    
    # Tracking data
    high_cpu_start_time: Optional[float] = None
    is_flagged: bool = False
    flagged_reasons: List[ProcessAlertType] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "pid": self.pid,
            "name": self.name,
            "create_time": self.create_time,
            "cmdline": self.cmdline,
            "exe": self.exe,
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "memory_bytes": self.memory_bytes,
            "status": self.status,
            "username": self.username,
            "open_files_count": len(self.open_files),
            "connections_count": len(self.connections),
            "is_flagged": self.is_flagged,
            "flagged_reasons": [reason.name for reason in self.flagged_reasons]
        }


@dataclass
class ProcessAlert:
    """Alert generated for suspicious processes"""
    timestamp: float
    process_info: ProcessInfo
    alert_type: ProcessAlertType
    details: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "timestamp": self.timestamp,
            "pid": self.process_info.pid,
            "process_name": self.process_info.name,
            "alert_type": self.alert_type.name,
            "details": self.details,
            "process_info": self.process_info.to_dict()
        }


class ProcessInspector:
    """
    Monitors system processes for suspicious behavior.

    This class:
    1. Samples running processes at configurable intervals
    2. Tracks processes over time to detect sustained high CPU usage
    3. Flags processes with high memory consumption or unknown binaries
    4. Publishes alerts via an asyncio queue
    """
    
    def __init__(self, config_path: str = "config/config.yaml", alert_queue: Optional[asyncio.Queue] = None):
        """Initialize the process inspector with configuration"""
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Initialize the alert queue
        self.alert_queue = alert_queue or asyncio.Queue(
            maxsize=self.config.get("proc_inspector", {}).get("queue_size", 1000)
        )
        
        # Settings
        settings = self.config.get("proc_inspector", {})
        self.sample_interval = settings.get("sample_interval_sec", 1.0)  # Default: 1 second
        self.high_cpu_threshold = settings.get("high_cpu_threshold", 80.0)  # Default: 80%
        self.high_cpu_duration = settings.get("high_cpu_duration_sec", 5.0)  # Default: 5 seconds
        self.high_memory_threshold = settings.get("high_memory_threshold_mb", 200) * 1024 * 1024  # Convert to bytes
        
        # Load known binary paths
        self.known_binary_paths = settings.get("known_binary_paths", [
            "/bin", "/usr/bin", "/usr/local/bin",
            "/sbin", "/usr/sbin", "/usr/local/sbin",
            "/opt", "/usr/lib", "/lib",
            "C:\\Windows\\System32", "C:\\Program Files", "C:\\Program Files (x86)"
        ])
        
        # Load suspicious process names
        self.suspicious_process_names = settings.get("suspicious_process_names", [
            "cryptor", "ransom", "wncry", "wcry", "localbitcoins", "taskdl", "taskse"
        ])
        
        # State tracking
        self.tracked_processes: Dict[int, ProcessInfo] = {}
        
        # Controlling flags
        self.is_running = False
        self.shutdown_event = asyncio.Event()
        
        logger.info("Process Inspector initialized")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            # Add default process inspector config if not present
            if "proc_inspector" not in config:
                config["proc_inspector"] = {
                    "enabled": True,
                    "sample_interval_sec": 1.0,
                    "queue_size": 1000,
                    "high_cpu_threshold": 80.0,
                    "high_cpu_duration_sec": 5.0,
                    "high_memory_threshold_mb": 200,
                    "exclude_pids": ["self"],
                    "known_binary_paths": [
                        "/bin", "/usr/bin", "/usr/local/bin",
                        "/sbin", "/usr/sbin", "/usr/local/sbin",
                        "/opt", "/usr/lib", "/lib",
                        "C:\\Windows\\System32", "C:\\Program Files", "C:\\Program Files (x86)"
                    ],
                    "suspicious_process_names": [
                        "cryptor", "ransom", "wncry", "wcry", "localbitcoins", "taskdl", "taskse"
                    ],
                    "logging": {
                        "level": "INFO",
                        "file": "/var/log/blockwave/proc_inspector.log"
                    }
                }
            return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)
    
    def _setup_logging(self) -> None:
        """Configure logging based on configuration"""
        log_config = self.config.get("proc_inspector", {}).get("logging", {})
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
    
    def _should_exclude_pid(self, pid: int) -> bool:
        """Check if a process should be excluded from monitoring"""
        exclude_pids = self.config.get("proc_inspector", {}).get("exclude_pids", [])
        
        # Handle 'self' special case
        if "self" in exclude_pids and pid == os.getpid():
            return True
        
        # Convert string PIDs to integers
        try:
            int_exclude_pids = [int(pid) for pid in exclude_pids if pid != "self"]
            return pid in int_exclude_pids
        except ValueError:
            logger.warning(f"Invalid PID in exclude_pids: {exclude_pids}")
            return False
    
    def _is_binary_path_unknown(self, exe_path: Optional[str]) -> bool:
        """Check if binary is from an unknown location"""
        if exe_path is None:
            return True
        
        return not any(Path(exe_path).is_relative_to(Path(known_path)) 
                     for known_path in self.known_binary_paths)
    
    def _has_suspicious_name(self, process_name: str, cmdline: List[str]) -> bool:
        """Check if process has a suspicious name"""
        # Check process name
        process_name_lower = process_name.lower()
        if any(susp_name in process_name_lower for susp_name in self.suspicious_process_names):
            return True
        
        # Check command line arguments
        full_cmdline = " ".join(cmdline).lower()
        return any(susp_name in full_cmdline for susp_name in self.suspicious_process_names)
    
    async def _get_process_info(self, proc: psutil.Process) -> Optional[ProcessInfo]:
        """Get detailed information about a process"""
        try:
            with proc.oneshot():
                pid = proc.pid
                if self._should_exclude_pid(pid):
                    return None
                
                # Basic process info
                create_time = proc.create_time()
                name = proc.name()
                
                try:
                    cmdline = proc.cmdline()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cmdline = []
                
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    exe = None
                
                cpu_percent = proc.cpu_percent()
                memory_info = proc.memory_info()
                memory_bytes = getattr(memory_info, 'rss', 0)  # Resident Set Size
                memory_percent = proc.memory_percent()
                
                try:
                    status = proc.status()
                except psutil.AccessDenied:
                    status = "unknown"
                
                try:
                    username = proc.username()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    username = None
                
                # Get open files if possible
                try:
                    open_files = [f.path for f in proc.open_files()]
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    open_files = []
                
                # Get network connections if possible
                try:
                    connections = proc.connections()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    connections = []
                
                # Create ProcessInfo object
                process_info = ProcessInfo(
                    pid=pid,
                    name=name,
                    create_time=create_time,
                    cmdline=cmdline,
                    exe=exe,
                    cpu_percent=cpu_percent,
                    memory_percent=memory_percent,
                    memory_bytes=memory_bytes,
                    status=status,
                    username=username,
                    open_files=open_files,
                    connections=connections
                )
                
                return process_info
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
    
    def _check_process_for_alerts(self, current_time: float, process_info: ProcessInfo) -> List[ProcessAlert]:
        """Check a process for alert conditions"""
        alerts = []
        
        # Check for high CPU usage
        if process_info.cpu_percent > self.high_cpu_threshold:
            if process_info.high_cpu_start_time is None:
                # Start tracking high CPU usage
                process_info.high_cpu_start_time = current_time
            
            elif current_time - process_info.high_cpu_start_time > self.high_cpu_duration:
                # CPU usage has been high for the threshold duration
                if ProcessAlertType.HIGH_CPU not in process_info.flagged_reasons:
                    alerts.append(ProcessAlert(
                        timestamp=current_time,
                        process_info=process_info,
                        alert_type=ProcessAlertType.HIGH_CPU,
                        details={
                            "cpu_percent": process_info.cpu_percent,
                            "duration_sec": current_time - process_info.high_cpu_start_time
                        }
                    ))
                    process_info.flagged_reasons.append(ProcessAlertType.HIGH_CPU)
                    process_info.is_flagged = True
        else:
            # Reset high CPU tracking if CPU usage drops below threshold
            process_info.high_cpu_start_time = None
        
        # Check for high memory usage
        if process_info.memory_bytes > self.high_memory_threshold:
            if ProcessAlertType.HIGH_MEMORY not in process_info.flagged_reasons:
                alerts.append(ProcessAlert(
                    timestamp=current_time,
                    process_info=process_info,
                    alert_type=ProcessAlertType.HIGH_MEMORY,
                    details={
                        "memory_bytes": process_info.memory_bytes,
                        "memory_mb": process_info.memory_bytes / (1024 * 1024),
                        "threshold_mb": self.high_memory_threshold / (1024 * 1024)
                    }
                ))
                process_info.flagged_reasons.append(ProcessAlertType.HIGH_MEMORY)
                process_info.is_flagged = True
        
        # Check for unknown binary path
        if process_info.exe and self._is_binary_path_unknown(process_info.exe):
            if ProcessAlertType.UNKNOWN_BINARY not in process_info.flagged_reasons:
                alerts.append(ProcessAlert(
                    timestamp=current_time,
                    process_info=process_info,
                    alert_type=ProcessAlertType.UNKNOWN_BINARY,
                    details={
                        "exe_path": process_info.exe,
                        "known_paths": self.known_binary_paths
                    }
                ))
                process_info.flagged_reasons.append(ProcessAlertType.UNKNOWN_BINARY)
                process_info.is_flagged = True
        
        # Check for suspicious process name
        if self._has_suspicious_name(process_info.name, process_info.cmdline):
            if ProcessAlertType.SUSPICIOUS_NAME not in process_info.flagged_reasons:
                alerts.append(ProcessAlert(
                    timestamp=current_time,
                    process_info=process_info,
                    alert_type=ProcessAlertType.SUSPICIOUS_NAME,
                    details={
                        "name": process_info.name,
                        "cmdline": process_info.cmdline,
                        "matched_patterns": [
                            pattern for pattern in self.suspicious_process_names
                            if pattern in process_info.name.lower() or 
                               pattern in " ".join(process_info.cmdline).lower()
                        ]
                    }
                ))
                process_info.flagged_reasons.append(ProcessAlertType.SUSPICIOUS_NAME)
                process_info.is_flagged = True
        
        return alerts
    
    async def _process_sample(self) -> None:
        """Sample and analyze all running processes"""
        current_time = time.time()
        current_pids = set()
        alerts = []
        
        # Sample all running processes
        for proc in psutil.process_iter(['pid']):
            try:
                pid = proc.pid
                current_pids.add(pid)
                
                # Get detailed info for the process
                process_info = await self._get_process_info(proc)
                
                if process_info is None:
                    continue
                
                # Check if this is a new process
                if pid not in self.tracked_processes:
                    # New process detected
                    alerts.append(ProcessAlert(
                        timestamp=current_time,
                        process_info=process_info,
                        alert_type=ProcessAlertType.NEW_PROCESS,
                        details={
                            "create_time": datetime.fromtimestamp(process_info.create_time).isoformat()
                        }
                    ))
                    
                    self.tracked_processes[pid] = process_info
                else:
                    # Update existing process data
                    existing_process = self.tracked_processes[pid]
                    existing_process.cpu_percent = process_info.cpu_percent
                    existing_process.memory_percent = process_info.memory_percent
                    existing_process.memory_bytes = process_info.memory_bytes
                    existing_process.status = process_info.status
                    existing_process.open_files = process_info.open_files
                    existing_process.connections = process_info.connections
                    
                    # Check for alert conditions
                    process_alerts = self._check_process_for_alerts(current_time, existing_process)
                    alerts.extend(process_alerts)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Check for terminated processes
        terminated_pids = set(self.tracked_processes.keys()) - current_pids
        for pid in terminated_pids:
            process_info = self.tracked_processes[pid]
            alerts.append(ProcessAlert(
                timestamp=current_time,
                process_info=process_info,
                alert_type=ProcessAlertType.TERMINATED_PROCESS,
                details={
                    "last_seen": process_info.to_dict()
                }
            ))
            
            # Remove from tracked processes
            del self.tracked_processes[pid]
        
        # Send alerts to the queue
        for alert in alerts:
            try:
                # Use put_nowait to avoid blocking
                self.alert_queue.put_nowait(alert)
                logger.debug(f"Alert generated: {alert.alert_type.name} for PID {alert.process_info.pid}")
            except asyncio.QueueFull:
                logger.warning("Alert queue is full, dropping alert")
    
    async def start(self) -> None:
        """Start the process inspector"""
        if self.is_running:
            logger.warning("Process Inspector is already running")
            return
        
        logger.info("Starting Process Inspector...")
        self.is_running = True
        self.shutdown_event.clear()
        
        # Initial sample to build baseline
        try:
            await self._process_sample()
            logger.info(f"Initial process sample completed, tracking {len(self.tracked_processes)} processes")
        except Exception as e:
            logger.error(f"Error during initial process sample: {e}")
        
        # Start sampling loop
        while not self.shutdown_event.is_set():
            try:
                # Wait for sample interval or shutdown
                try:
                    await asyncio.wait_for(
                        self.shutdown_event.wait(),
                        timeout=self.sample_interval
                    )
                except asyncio.TimeoutError:
                    # Timeout is expected, continue with sampling
                    pass
                
                if self.shutdown_event.is_set():
                    break
                
                # Sample processes
                await self._process_sample()
                
            except asyncio.CancelledError:
                logger.info("Process sampling task cancelled")
                break
            except Exception as e:
                logger.error(f"Error during process sampling: {e}")
                # Brief pause to avoid error flood
                await asyncio.sleep(1)
        
        self.is_running = False
        logger.info("Process Inspector stopped")
    
    async def stop(self) -> None:
        """Stop the process inspector"""
        if not self.is_running:
            logger.warning("Process Inspector is not running")
            return
        
        logger.info("Stopping Process Inspector...")
        self.shutdown_event.set()
        
        # Wait for a short time to ensure clean shutdown
        await asyncio.sleep(0.5)
        
        # Clear process tracking data
        self.tracked_processes.clear()
        
        self.is_running = False
        logger.info("Process Inspector cleanup complete")
    
    async def get_alert(self) -> ProcessAlert:
        """Get the next alert from the queue"""
        return await self.alert_queue.get()
    
    def get_tracked_processes(self) -> Dict[int, ProcessInfo]:
        """Get currently tracked processes (for API or testing)"""
        return self.tracked_processes.copy()


async def main():
    """Main entry point for testing/standalone usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Process Inspector for BlockWave-Ransom')
    parser.add_argument('--config', type=str, default='config/config.yaml', help='Path to config file')
    parser.add_argument('--sample-time', type=int, default=30, help='How long to run sampling (seconds)')
    parser.add_argument('--show-all', action='store_true', help='Show all processes, not just suspicious ones')
    args = parser.parse_args()
    
    # Initialize and start inspector
    inspector = ProcessInspector(args.config)
    
    # Start consumer task
    async def alert_consumer():
        while True:
            try:
                alert = await inspector.get_alert()
                print(f"\n[ALERT] {alert.alert_type.name} - Process: {alert.process_info.name} (PID: {alert.process_info.pid})")
                print(f"Details: {alert.details}")
            except asyncio.CancelledError:
                break
    
    consumer_task = asyncio.create_task(alert_consumer())
    
    # Start the inspector
    inspector_task = asyncio.create_task(inspector.start())
    
    try:
        print(f"Process Inspector running for {args.sample_time} seconds...")
        await asyncio.sleep(args.sample_time)
        
        # Print summary
        print("\n--- Process Summary ---")
        flagged_count = 0
        
        for pid, proc_info in sorted(inspector.get_tracked_processes().items()):
            if proc_info.is_flagged or args.show_all:
                status = "[FLAGGED]" if proc_info.is_flagged else ""
                print(f"{pid:6} {proc_info.name:20} CPU: {proc_info.cpu_percent:5.1f}% MEM: {proc_info.memory_bytes/(1024*1024):6.1f}MB {status}")
                if proc_info.is_flagged:
                    print(f"      Flagged for: {', '.join(reason.name for reason in proc_info.flagged_reasons)}")
                    flagged_count += 1
        
        print(f"\nFound {flagged_count} suspicious processes out of {len(inspector.get_tracked_processes())} total")
    
    finally:
        # Clean shutdown
        await inspector.stop()
        consumer_task.cancel()
        
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting due to keyboard interrupt")
        sys.exit(0) 
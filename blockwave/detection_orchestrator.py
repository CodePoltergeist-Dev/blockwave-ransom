#!/usr/bin/env python3
"""
BlockWave-Ransom Detection Orchestrator

This module coordinates all monitoring components and implements detection and response logic.
"""

import asyncio
import logging
import os
import signal
import sys
import time
import yaml
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum, auto
from datetime import datetime

# Import monitoring components
from fs_monitor import FileSystemMonitor, FileEvent, EventType
from ebpf_monitor import EBPFMonitor, EBPFEvent, EBPFSeverity
from yara_scanner import YaraScanner, YaraMatch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("detection_orchestrator")


class AlertSeverity(Enum):
    """Severity levels for security alerts"""
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


@dataclass
class Alert:
    """Security alert with details about the detected threat"""
    severity: AlertSeverity
    source: str
    timestamp: datetime
    details: Dict[str, Any]
    affected_files: Set[str]
    process_info: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for serialization"""
        return {
            "severity": self.severity.name,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "affected_files": list(self.affected_files),
            "process_info": self.process_info,
        }


class ResponseAction(Enum):
    """Possible response actions to take when ransomware is detected"""
    LOG_ONLY = auto()             # Just log the incident
    KILL_PROCESS = auto()         # Kill the suspicious process
    SUSPEND_PROCESS = auto()      # Suspend the process
    QUARANTINE_FILE = auto()      # Move suspicious file to quarantine
    BLOCK_NETWORK = auto()        # Block outbound network connections
    SNAPSHOT_RESTORE = auto()     # Restore from a clean snapshot
    NOTIFY_ADMIN = auto()         # Send notification to administrator


class DetectionOrchestrator:
    """
    Main orchestrator that coordinates monitoring components and responses.
    
    This class:
    1. Initializes all monitoring components
    2. Processes events from all sources
    3. Correlates events to detect ransomware
    4. Initiates appropriate response actions
    5. Manages the alert lifecycle
    """
    
    def __init__(self, config_path: str):
        """Initialize the orchestrator with configuration"""
        self.config = self._load_config(config_path)
        self.setup_logging()
        
        self.fs_monitor = None
        self.ebpf_monitor = None
        self.yara_scanner = None
        
        # Event queues
        self.fs_event_queue = asyncio.Queue(
            maxsize=self.config["orchestrator"]["queue_sizes"]["fs_events"]
        )
        self.ebpf_event_queue = asyncio.Queue(
            maxsize=self.config["orchestrator"]["queue_sizes"]["ebpf_events"]
        )
        self.yara_event_queue = asyncio.Queue(
            maxsize=self.config["orchestrator"]["queue_sizes"]["yara_events"]
        )
        self.alert_queue = asyncio.Queue(
            maxsize=self.config["orchestrator"]["queue_sizes"]["alerts"]
        )
        
        # Track active alerts and affected entities
        self.active_alerts: List[Alert] = []
        self.monitored_processes: Dict[int, Dict[str, Any]] = {}
        self.suspicious_files: Set[str] = set()
        
        # Shutdown flag
        self.shutdown_event = asyncio.Event()
        self._setup_signal_handlers()
        
        logger.info("Detection Orchestrator initialized")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            # Add default orchestrator config if not present
            if "orchestrator" not in config:
                config["orchestrator"] = {
                    "queue_sizes": {
                        "fs_events": 1000,
                        "ebpf_events": 1000,
                        "yara_events": 1000,
                        "alerts": 500,
                    },
                    "thresholds": {
                        "suspicious_file_ops": 50,
                        "encryption_score": 75,
                        "yara_matches_required": 1,
                    },
                    "response": {
                        "default_action": "LOG_ONLY",
                        "high_severity_action": "KILL_PROCESS",
                        "critical_severity_action": "BLOCK_NETWORK",
                        "quarantine_dir": "/var/lib/blockwave/quarantine",
                    },
                    "correlation": {
                        "time_window_sec": 60,
                        "min_events_for_alert": 3,
                    },
                    "logging": {
                        "level": "INFO",
                        "file": "/var/log/blockwave/orchestrator.log",
                    }
                }
            return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)
    
    def setup_logging(self):
        """Configure logging based on configuration"""
        log_config = self.config["orchestrator"]["logging"]
        log_level = getattr(logging, log_config["level"])
        
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
    
    def _setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown"""
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        """Handle signals for graceful shutdown"""
        logger.info(f"Received signal {sig}, initiating shutdown")
        if not self.shutdown_event.is_set():
            # Use call_soon_threadsafe as signal handlers run in the main thread
            asyncio.get_event_loop().call_soon_threadsafe(
                self.shutdown_event.set
            )
    
    async def initialize_components(self):
        """Initialize all monitoring components"""
        # Initialize FileSystemMonitor
        self.fs_monitor = FileSystemMonitor(
            self.config["fs_monitor"],
            self.fs_event_queue
        )
        
        # Initialize EBPFMonitor
        self.ebpf_monitor = EBPFMonitor(
            self.config["ebpf_monitor"],
            self.ebpf_event_queue
        )
        
        # Initialize YaraScanner
        yara_rules_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            "rules"
        )
        self.yara_scanner = YaraScanner(
            yara_rules_path,
            self.yara_event_queue
        )
        
        logger.info("All monitoring components initialized")
    
    async def start(self):
        """Start the orchestrator and all monitoring components"""
        await self.initialize_components()
        
        # Start monitoring components
        await self.fs_monitor.start()
        await self.ebpf_monitor.start()
        await self.yara_scanner.start()
        
        # Start processing tasks
        tasks = [
            asyncio.create_task(self.process_fs_events()),
            asyncio.create_task(self.process_ebpf_events()),
            asyncio.create_task(self.process_yara_events()),
            asyncio.create_task(self.correlate_events()),
            asyncio.create_task(self.process_alerts()),
        ]
        
        logger.info("Orchestrator started")
        
        # Wait for shutdown signal
        await self.shutdown_event.wait()
        logger.info("Shutdown signal received, stopping orchestrator")
        
        # Stop all components
        await self.fs_monitor.stop()
        await self.ebpf_monitor.stop()
        await self.yara_scanner.stop()
        
        # Cancel all tasks
        for task in tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Orchestrator stopped")
    
    async def process_fs_events(self):
        """Process file system events"""
        logger.info("Started processing filesystem events")
        while not self.shutdown_event.is_set():
            try:
                event = await asyncio.wait_for(
                    self.fs_event_queue.get(),
                    timeout=1.0
                )
                
                # Process the event
                logger.debug(f"Processing FS event: {event}")
                
                # Update monitored files
                if event.event_type in [EventType.CREATED, EventType.MODIFIED]:
                    # Queue file for YARA scanning
                    if os.path.isfile(event.src_path):
                        await self.yara_scanner.scan_file(event.src_path)
                
                # Check for potential ransomware indicators
                if self._is_suspicious_file_operation(event):
                    logger.info(f"Suspicious file operation detected: {event}")
                    self.suspicious_files.add(event.src_path)
                
                self.fs_event_queue.task_done()
            
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                logger.info("FS event processor task cancelled")
                break
            except Exception as e:
                logger.error(f"Error processing FS event: {e}")
    
    async def process_ebpf_events(self):
        """Process eBPF events"""
        logger.info("Started processing eBPF events")
        while not self.shutdown_event.is_set():
            try:
                event = await asyncio.wait_for(
                    self.ebpf_event_queue.get(),
                    timeout=1.0
                )
                
                # Process the event
                logger.debug(f"Processing eBPF event: {event}")
                
                # Update process tracking
                if event.pid not in self.monitored_processes:
                    self.monitored_processes[event.pid] = {
                        "process_name": event.process_name,
                        "start_time": datetime.now(),
                        "file_ops_count": 0,
                        "suspicious_score": 0,
                        "paths_accessed": set(),
                    }
                
                process_info = self.monitored_processes[event.pid]
                process_info["file_ops_count"] += 1
                
                if event.file_path:
                    process_info["paths_accessed"].add(event.file_path)
                
                # Update suspicion score based on severity
                if event.severity == EBPFSeverity.HIGH:
                    process_info["suspicious_score"] += 10
                elif event.severity == EBPFSeverity.MEDIUM:
                    process_info["suspicious_score"] += 5
                elif event.severity == EBPFSeverity.LOW:
                    process_info["suspicious_score"] += 1
                
                # Check if process meets threshold for scanning
                if (process_info["suspicious_score"] >= 
                    self.config["orchestrator"]["thresholds"]["encryption_score"]):
                    logger.warning(
                        f"Process {event.pid} ({event.process_name}) exceeds "
                        f"suspicion threshold: {process_info['suspicious_score']}"
                    )
                    await self.yara_scanner.scan_process(event.pid)
                
                self.ebpf_event_queue.task_done()
            
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                logger.info("eBPF event processor task cancelled")
                break
            except Exception as e:
                logger.error(f"Error processing eBPF event: {e}")
    
    async def process_yara_events(self):
        """Process YARA scanning events"""
        logger.info("Started processing YARA events")
        while not self.shutdown_event.is_set():
            try:
                match = await asyncio.wait_for(
                    self.yara_event_queue.get(),
                    timeout=1.0
                )
                
                # Process the YARA match
                logger.debug(f"Processing YARA match: {match}")
                
                # Create an alert for the YARA match
                severity = AlertSeverity.MEDIUM
                if any("ransomware" in tag.lower() for tag in match.tags):
                    severity = AlertSeverity.HIGH
                
                if any("wannacry" in tag.lower() for tag in match.tags):
                    severity = AlertSeverity.CRITICAL
                
                alert = Alert(
                    severity=severity,
                    source="yara_scanner",
                    timestamp=datetime.now(),
                    details={
                        "rule": match.rule,
                        "tags": match.tags,
                        "strings": match.matched_strings,
                        "metadata": match.metadata,
                    },
                    affected_files={match.target} if match.target_type == "file" else set(),
                    process_info={
                        "pid": match.pid if match.target_type == "process" else None,
                        "process_name": match.process_name if match.target_type == "process" else None,
                    }
                )
                
                await self.alert_queue.put(alert)
                logger.warning(f"YARA match found: {match.rule} in {match.target}")
                
                self.yara_event_queue.task_done()
            
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                logger.info("YARA event processor task cancelled")
                break
            except Exception as e:
                logger.error(f"Error processing YARA event: {e}")
    
    async def correlate_events(self):
        """Correlate events from different sources to detect ransomware"""
        logger.info("Started event correlation")
        while not self.shutdown_event.is_set():
            try:
                # Sleep to allow events to accumulate
                await asyncio.sleep(1.0)
                
                # Skip if no suspicious activity detected
                if (not self.suspicious_files and 
                    not any(p["suspicious_score"] > 10 for p in self.monitored_processes.values())):
                    continue
                
                # Check for correlation indicators
                for pid, process in list(self.monitored_processes.items()):
                    # Skip if process score is too low
                    if process["suspicious_score"] < 10:
                        continue
                    
                    # Calculate file modification rate
                    time_window = self.config["orchestrator"]["correlation"]["time_window_sec"]
                    elapsed_time = (datetime.now() - process["start_time"]).total_seconds()
                    
                    if elapsed_time <= 0:
                        continue
                    
                    file_ops_rate = process["file_ops_count"] / elapsed_time
                    
                    # Check if file operation rate exceeds threshold
                    if file_ops_rate > (
                        self.config["orchestrator"]["thresholds"]["suspicious_file_ops"] / time_window
                    ):
                        # Create correlation alert
                        alert = Alert(
                            severity=AlertSeverity.HIGH,
                            source="correlation_engine",
                            timestamp=datetime.now(),
                            details={
                                "file_ops_rate": file_ops_rate,
                                "file_ops_count": process["file_ops_count"],
                                "elapsed_time_sec": elapsed_time,
                                "suspicious_score": process["suspicious_score"],
                            },
                            affected_files=process["paths_accessed"],
                            process_info={
                                "pid": pid,
                                "process_name": process["process_name"],
                            }
                        )
                        
                        await self.alert_queue.put(alert)
                        logger.warning(
                            f"Correlated alert: Process {pid} ({process['process_name']}) "
                            f"has suspicious file operation rate: {file_ops_rate:.2f} ops/sec"
                        )
            
            except asyncio.CancelledError:
                logger.info("Correlation task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in event correlation: {e}")
    
    async def process_alerts(self):
        """Process and respond to security alerts"""
        logger.info("Started alert processor")
        while not self.shutdown_event.is_set():
            try:
                alert = await asyncio.wait_for(
                    self.alert_queue.get(),
                    timeout=1.0
                )
                
                # Add to active alerts
                self.active_alerts.append(alert)
                
                # Determine response action based on severity
                action = self._determine_response_action(alert)
                
                # Execute response action
                await self._execute_response(alert, action)
                
                self.alert_queue.task_done()
            
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                logger.info("Alert processor task cancelled")
                break
            except Exception as e:
                logger.error(f"Error processing alert: {e}")
    
    def _is_suspicious_file_operation(self, event: FileEvent) -> bool:
        """Determine if a file operation is suspicious"""
        # Check for typical ransomware extensions
        suspicious_extensions = [
            '.encrypted', '.locked', '.crypto', '.crypt', '.crinf', '.r5a', 
            '.WNCRY', '.wcry', '.wncrypt', '.wncryt', '.wnry', '.zzzz',
            '.locky', '.zepto', '.cerber', '.cerber2', '.cerber3',
            '.encrypt', '.encrypted', '.crypted', '.crypt', '.aaa', '.xyz',
            '.abc', '.ecc', '.exx', '.ezz', '.vvv', '.rsplite', '.vault',
            '.pays', '.odcodc', '.hush', '.silent', '.pky', '.blt', '.bleep',
            '.bloc', '.btc', '.CTBL', '.CTB2', '.UNITRIX', '.EnCiPhErEd'
        ]
        
        if event.event_type == EventType.CREATED:
            for ext in suspicious_extensions:
                if event.src_path.endswith(ext):
                    return True
        
        # Check for ransomware notes
        suspicious_filenames = [
            'DECRYPT_INSTRUCTIONS', 'HOW_TO_DECRYPT', 'HELP_DECRYPT',
            'RECOVERY_KEY', 'HELP_RESTORE_FILES', 'HELP_YOUR_FILES',
            'READ_ME_FOR_DECRYPT', 'HOW_TO_RECOVER_FILES', 'YOUR_FILES',
            'YOUR_FILES_ARE_ENCRYPTED', 'YOUR_FILES_ARE_DEAD',
            'DECRYPT_YOUR_FILES', 'UNLOCK_FILES', 'RECOVER_FILES',
            '@Please_Read_Me@', '@WanaDecryptor@', 'WannaDecryptor',
            'FILES_ENCRYPTED', 'DECRYPT_INFORMATION', 'README',
            'README.txt', 'README.TXT', 'Instructions_'
        ]
        
        for filename in suspicious_filenames:
            if os.path.basename(event.src_path).startswith(filename):
                return True
        
        # TODO: Add more sophisticated detection methods
        return False
    
    def _determine_response_action(self, alert: Alert) -> ResponseAction:
        """Determine appropriate response action based on alert severity"""
        response_config = self.config["orchestrator"]["response"]
        
        if alert.severity == AlertSeverity.CRITICAL:
            action_str = response_config.get(
                "critical_severity_action", "BLOCK_NETWORK"
            )
        elif alert.severity == AlertSeverity.HIGH:
            action_str = response_config.get(
                "high_severity_action", "KILL_PROCESS"
            )
        else:
            action_str = response_config.get(
                "default_action", "LOG_ONLY"
            )
        
        try:
            return ResponseAction[action_str]
        except (KeyError, ValueError):
            logger.error(f"Invalid response action: {action_str}, using LOG_ONLY")
            return ResponseAction.LOG_ONLY
    
    async def _execute_response(self, alert: Alert, action: ResponseAction):
        """Execute the determined response action"""
        logger.info(f"Executing response action: {action.name} for alert: {alert.severity.name}")
        
        if action == ResponseAction.LOG_ONLY:
            # Just log the alert
            logger.warning(
                f"ALERT [{alert.severity.name}] from {alert.source}: "
                f"Process {alert.process_info.get('process_name', 'Unknown')} "
                f"(PID: {alert.process_info.get('pid', 'Unknown')})"
            )
            return
        
        # Get PID from alert
        pid = alert.process_info.get('pid')
        
        try:
            if action == ResponseAction.KILL_PROCESS and pid:
                logger.warning(f"Killing process PID {pid}")
                os.kill(pid, signal.SIGKILL)
            
            elif action == ResponseAction.SUSPEND_PROCESS and pid:
                logger.warning(f"Suspending process PID {pid}")
                os.kill(pid, signal.SIGSTOP)
            
            elif action == ResponseAction.QUARANTINE_FILE:
                quarantine_dir = self.config["orchestrator"]["response"].get(
                    "quarantine_dir", "/var/lib/blockwave/quarantine"
                )
                
                # Ensure quarantine directory exists
                if not os.path.exists(quarantine_dir):
                    os.makedirs(quarantine_dir, exist_ok=True)
                
                # Quarantine affected files
                for filepath in alert.affected_files:
                    if os.path.exists(filepath):
                        dest = os.path.join(
                            quarantine_dir, 
                            f"{os.path.basename(filepath)}.{int(time.time())}.quarantine"
                        )
                        logger.warning(f"Quarantining file: {filepath} -> {dest}")
                        os.rename(filepath, dest)
            
            elif action == ResponseAction.BLOCK_NETWORK and pid:
                # This would require integration with firewall or iptables
                logger.warning(f"Network blocking for PID {pid} not implemented")
                # Example implementation would call iptables or other firewall API
            
            elif action == ResponseAction.NOTIFY_ADMIN:
                # This would send email or other notification
                logger.warning("Admin notification not implemented")
            
            elif action == ResponseAction.SNAPSHOT_RESTORE:
                # This would require integration with backup/snapshot system
                logger.warning("Snapshot restore not implemented")
        
        except Exception as e:
            logger.error(f"Failed to execute response {action.name}: {e}")


async def main():
    """Main entry point for the application"""
    # Default config path
    config_path = "config/config.yaml"
    
    # Use command line arg if provided
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    
    # Get absolute path if not already
    if not os.path.isabs(config_path):
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            config_path
        )
    
    # Create and start orchestrator
    orchestrator = DetectionOrchestrator(config_path)
    await orchestrator.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Keyboard interrupt received, exiting")
        sys.exit(0) 
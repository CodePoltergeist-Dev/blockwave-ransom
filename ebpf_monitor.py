#!/usr/bin/env python3
"""
eBPF Monitor Module

This module integrates with eBPFAngel to monitor kernel events using eBPF,
parse events from ring-buffers/maps, and emit structured alerts via an asyncio queue.
"""

import asyncio
import ctypes
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple, Callable

import yaml
try:
    from bcc import BPF
except ImportError:
    print("Error: BCC (BPF Compiler Collection) is required. Please install it first.")
    print("See: https://github.com/iovisor/bcc/blob/master/INSTALL.md")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ebpf_monitor")


# Event type constants (from eBPFAngel's bpf.h)
class EventType(Enum):
    OPEN = 0
    CREATE = 1
    DELETE = 2
    ENCRYPT = 3


class EventSeverity(Enum):
    OK = 0
    MINOR = 1
    MAJOR = 2


@dataclass
class EbpfEvent:
    """Container for an eBPF event from eBPFAngel"""
    timestamp: float
    pid: int
    event_type: EventType
    severity: EventSeverity
    pattern_id: int
    thresholds_crossed: int
    filename: str
    process_name: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            "timestamp": self.timestamp,
            "pid": self.pid,
            "event_type": self.event_type.name,
            "severity": self.severity.name,
            "pattern_id": self.pattern_id,
            "thresholds_crossed": self._decode_thresholds(),
            "filename": self.filename,
            "process_name": self.process_name
        }
    
    def _decode_thresholds(self) -> Dict[str, bool]:
        """Decode thresholds bitmap to dictionary"""
        return {
            "open": bool(self.thresholds_crossed & 1),
            "create": bool(self.thresholds_crossed & 2),
            "delete": bool(self.thresholds_crossed & 4),
            "encrypt": bool(self.thresholds_crossed & 8)
        }


@dataclass
class EbpfEventBatch:
    """Container for a batch of eBPF events"""
    timestamp: float = field(default_factory=time.time)
    events: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_event(self, event: EbpfEvent) -> None:
        """Add an event to the batch"""
        self.events.append(event.to_dict())
    
    def to_json(self) -> str:
        """Convert batch to JSON string"""
        batch_dict = {
            "source": "ebpf_monitor",
            "batch_timestamp": self.timestamp,
            "batch_size": len(self.events),
            "events": self.events
        }
        return json.dumps(batch_dict)
    
    def is_empty(self) -> bool:
        """Check if batch is empty"""
        return len(self.events) == 0


# Structures matching eBPFAngel's bpf.h
class Flags(ctypes.Structure):
    _fields_ = [
        ('severity', ctypes.c_uint8),
        ('pattern_id', ctypes.c_uint8),
        ('thresholds_crossed', ctypes.c_uint8),
    ]


FILENAME_SIZE = 64
TASK_COMM_LEN = 16

class EbpfEventStruct(ctypes.Structure):
    _fields_ = [
        ('ts', ctypes.c_uint64),
        ('pid', ctypes.c_uint32),
        ('type', ctypes.c_uint),
        ('flags', Flags),
        ('filename', ctypes.c_char * FILENAME_SIZE),
        ('comm', ctypes.c_char * TASK_COMM_LEN),
    ]


class Config(ctypes.Structure):
    _fields_ = [
        ('thresholds', ctypes.c_uint16 * 4),
        ('reset_period_ns', ctypes.c_uint32),
        ('min_severity', ctypes.c_uint8),
    ]


class Pattern(ctypes.Structure):
    _fields_ = [
        ('bitmap', ctypes.c_uint32),
        ('bitmask', ctypes.c_uint32),
    ]


class EbpfMonitor:
    """
    eBPF monitor using eBPFAngel to detect kernel events and
    emit structured alerts through an asyncio queue.
    """
    
    def __init__(self, config_path: str = "config/config.yaml", 
                 ebpfangel_path: Optional[str] = None):
        """Initialize the eBPF monitor"""
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Set paths
        self.ebpfangel_path = ebpfangel_path or self._find_ebpfangel_path()
        self.bpf_c_path = os.path.join(self.ebpfangel_path, "detector", "bpf.c")
        self.bpf_h_path = os.path.join(self.ebpfangel_path, "detector", "bpf.h")
        
        # Check if files exist
        if not os.path.exists(self.bpf_c_path) or not os.path.exists(self.bpf_h_path):
            logger.error(f"eBPFAngel BPF sources not found at {self.ebpfangel_path}")
            raise FileNotFoundError(f"eBPFAngel BPF sources not found")
        
        # Set up event queue
        queue_size = self.config.get('ebpf_monitor', {}).get('queue_size', 1000)
        self.event_queue = asyncio.Queue(maxsize=queue_size)
        
        # BPF program state
        self.bpf = None
        self.ring_buffer_task = None
        self.is_running = False
    
    def _find_ebpfangel_path(self) -> str:
        """Find the path to eBPFAngel codebase"""
        # Try to find eBPFAngel relative to current directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # First check if we're in a directory inside eBPFAngel
        parent_dir = os.path.dirname(current_dir)
        if os.path.exists(os.path.join(parent_dir, "detector", "bpf.c")):
            return parent_dir
        
        # Check if eBPFAngel is a sibling directory
        sibling_dir = os.path.join(os.path.dirname(parent_dir), "ebpfangel")
        if os.path.exists(os.path.join(sibling_dir, "detector", "bpf.c")):
            return sibling_dir
        
        # Otherwise, look for it in the parent's parent directory
        grandparent_dir = os.path.dirname(parent_dir)
        if os.path.exists(os.path.join(grandparent_dir, "ebpfangel", "detector", "bpf.c")):
            return os.path.join(grandparent_dir, "ebpfangel")
        
        # If not found, default to current directory
        return current_dir
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        config_path = Path(config_path)
        
        if not config_path.exists():
            logger.error(f"Configuration file {config_path} not found.")
            default_config = {
                'ebpf_monitor': {
                    'enabled': True,
                    'queue_size': 1000,
                    'ebpfangel': {
                        'thresholds': {
                            'open': 50,
                            'create': 25,
                            'delete': 25,
                            'encrypt': 10
                        },
                        'reset_period_sec': 10,
                        'min_severity': 1
                    },
                    'logging': {'level': 'INFO', 'file': None}
                }
            }
            return default_config
        
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except (yaml.YAMLError, OSError) as e:
            logger.error(f"Error loading configuration: {e}")
            sys.exit(1)
    
    def _setup_logging(self) -> None:
        """Configure logging based on settings"""
        log_config = self.config.get('ebpf_monitor', {}).get('logging', {})
        level_str = log_config.get('level', 'INFO')
        level = getattr(logging, level_str.upper(), logging.INFO)
        
        logger.setLevel(level)
        
        # Add file handler if specified
        log_file = log_config.get('file')
        if log_file:
            try:
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                ))
                logger.addHandler(file_handler)
            except (OSError, IOError) as e:
                logger.error(f"Could not set up log file {log_file}: {e}")
    
    def _load_ebpf_program(self) -> BPF:
        """Load eBPFAngel BPF program"""
        logger.info("Loading eBPF program...")
        
        # Compile and load the BPF program
        cflags = ["-Wno-macro-redefined"]
        try:
            bpf = BPF(src_file=self.bpf_c_path, cflags=cflags, debug=4)
            logger.info("eBPF program loaded successfully")
            return bpf
        except Exception as e:
            logger.error(f"Failed to load eBPF program: {e}")
            raise
    
    def _update_config_map(self, bpf: BPF) -> None:
        """Update eBPFAngel configuration map"""
        logger.info("Updating eBPF configuration map...")
        
        # Get thresholds from config
        ebpfangel_config = self.config.get('ebpf_monitor', {}).get('ebpfangel', {})
        thresholds = ebpfangel_config.get('thresholds', {})
        
        # Create thresholds array
        thresholds_array = (ctypes.c_uint16 * 4)(
            thresholds.get('open', 50),
            thresholds.get('create', 25),
            thresholds.get('delete', 25),
            thresholds.get('encrypt', 10)
        )
        
        # Convert reset period from seconds to nanoseconds
        reset_period_sec = ebpfangel_config.get('reset_period_sec', 10)
        reset_period_ns = reset_period_sec * 1_000_000_000
        
        # Set minimum severity
        min_severity = ebpfangel_config.get('min_severity', 1)
        
        # Create config struct
        config_struct = Config(thresholds_array, reset_period_ns, min_severity)
        
        # Update config map
        bpf['config'][ctypes.c_int(0)] = config_struct
        logger.debug(f"Updated eBPF config map with thresholds: {thresholds}")
    
    def _update_patterns_map(self, bpf: BPF) -> None:
        """Update eBPFAngel patterns map"""
        logger.info("Updating eBPF patterns map...")
        
        # Default patterns from eBPFAngel
        default_patterns = [
            # Open-Create-Delete pattern (common in ransomware)
            Pattern(0x0000_0012, 0x0000_0FFF),
            # More complex pattern
            Pattern(0x0013_3332, 0x0FFF_FFFF)
        ]
        
        # Get custom patterns from config
        ebpfangel_config = self.config.get('ebpf_monitor', {}).get('ebpfangel', {})
        custom_patterns = ebpfangel_config.get('patterns', [])
        
        # Use custom patterns if provided, otherwise use defaults
        patterns = []
        if custom_patterns:
            for pattern in custom_patterns:
                bitmap = pattern.get('bitmap', 0)
                bitmask = pattern.get('bitmask', 0)
                patterns.append(Pattern(bitmap, bitmask))
        else:
            patterns = default_patterns
        
        # Update patterns map
        patterns_map = bpf['patterns']
        for idx, pattern in enumerate(patterns):
            patterns_map[ctypes.c_int(idx)] = pattern
        
        logger.debug(f"Updated eBPF patterns map with {len(patterns)} patterns")
    
    def _attach_probes(self, bpf: BPF) -> None:
        """Attach probes to crypto libraries"""
        logger.info("Attaching uprobes to crypto libraries...")
        
        # Function to find library path
        def find_lib(lib: str) -> Optional[str]:
            for path in ['/usr/lib/', '/opt', '/lib', '/usr/local/lib']:
                for root, _, files in os.walk(path):
                    if lib in files:
                        return os.path.join(root, lib)
            return None
        
        # Try to attach uprobes to different versions of libcrypto
        for lib in ['libcrypto.so.1.1', 'libcrypto.so.3']:
            pathname = find_lib(lib)
            if pathname:
                logger.info(f"Found {lib} at {pathname}")
                try:
                    bpf.attach_uprobe(name=pathname, sym="EVP_EncryptInit_ex", fn_name="trace_encrypt1")
                    bpf.attach_uprobe(name=pathname, sym="EVP_CipherInit_ex", fn_name="trace_encrypt1")
                    bpf.attach_uprobe(name=pathname, sym="EVP_SealInit", fn_name="trace_encrypt2")
                    logger.info(f"Attached uprobes to {lib}")
                except Exception as e:
                    logger.error(f"Failed to attach uprobes to {lib}: {e}")
            else:
                logger.warning(f"Library {lib} not found")
    
    def _process_event(self, cpu: int, data: Any, size: int) -> None:
        """Process an event from the eBPF ring buffer"""
        event = ctypes.cast(data, ctypes.POINTER(EbpfEventStruct)).contents
        
        # Convert to our event format
        ebpf_event = EbpfEvent(
            timestamp=float(event.ts) / 1e9,  # Convert ns to seconds
            pid=event.pid,
            event_type=EventType(event.type),
            severity=EventSeverity(event.flags.severity),
            pattern_id=event.flags.pattern_id,
            thresholds_crossed=event.flags.thresholds_crossed,
            filename=event.filename.decode('utf-8', errors='replace'),
            process_name=event.comm.decode('utf-8', errors='replace')
        )
        
        # Add to batch
        self._add_event_to_batch(ebpf_event)
    
    def _add_event_to_batch(self, event: EbpfEvent) -> None:
        """Add event to batch and schedule batch sending if needed"""
        # Create a batch with this event
        batch = EbpfEventBatch()
        batch.add_event(event)
        
        # Put batch in the queue
        batch_json = batch.to_json()
        
        # Use create_task to avoid blocking
        asyncio.create_task(self._send_batch_to_queue(batch_json))
    
    async def _send_batch_to_queue(self, batch_json: str) -> None:
        """Send batch to the queue"""
        try:
            await self.event_queue.put(batch_json)
            logger.debug("Sent batch to queue")
        except Exception as e:
            logger.error(f"Error sending batch to queue: {e}")
    
    async def _process_ring_buffer(self) -> None:
        """Process ring buffer events"""
        try:
            while self.is_running:
                try:
                    # Process events
                    self.bpf.ring_buffer_consume()
                    
                    # Sleep to avoid high CPU usage
                    await asyncio.sleep(0.1)
                except Exception as e:
                    if self.is_running:
                        logger.error(f"Error processing ring buffer: {e}")
                        await asyncio.sleep(1)  # Avoid tight loop on error
        except asyncio.CancelledError:
            logger.info("Ring buffer processing task cancelled")
            raise
    
    async def start(self) -> None:
        """Start the eBPF monitor"""
        if self.is_running:
            logger.warning("eBPF monitor is already running")
            return
        
        logger.info("Starting eBPF monitor...")
        
        try:
            # Load BPF program
            self.bpf = self._load_ebpf_program()
            
            # Update config and patterns maps
            self._update_config_map(self.bpf)
            self._update_patterns_map(self.bpf)
            
            # Attach probes
            self._attach_probes(self.bpf)
            
            # Set up ring buffer callback
            self.bpf.ring_buffer_register(name="events", callback=self._process_event)
            
            # Start ring buffer processing task
            self.is_running = True
            self.ring_buffer_task = asyncio.create_task(self._process_ring_buffer())
            
            logger.info("eBPF monitor started successfully")
        except Exception as e:
            logger.error(f"Failed to start eBPF monitor: {e}")
            self.is_running = False
            raise
    
    async def stop(self) -> None:
        """Stop the eBPF monitor"""
        if not self.is_running:
            logger.warning("eBPF monitor is not running")
            return
        
        logger.info("Stopping eBPF monitor...")
        
        # Set running flag to false
        self.is_running = False
        
        # Cancel ring buffer task
        if self.ring_buffer_task:
            self.ring_buffer_task.cancel()
            try:
                await self.ring_buffer_task
            except asyncio.CancelledError:
                pass
        
        # Clean up BPF resources
        self.bpf = None
        
        logger.info("eBPF monitor stopped")
    
    async def get_events(self) -> str:
        """Get the next batch of events from the queue"""
        return await self.event_queue.get()


# Simulator class for testing
class EbpfEventSimulator:
    """Simulates eBPF events for testing"""
    
    def __init__(self, queue: asyncio.Queue):
        self.queue = queue
        self.is_running = False
        self.task = None
    
    async def simulate_events(self, interval: float = 1.0, count: int = 10,
                              event_types: List[EventType] = None) -> None:
        """Simulate eBPF events"""
        event_types = event_types or list(EventType)
        try:
            for i in range(count):
                if not self.is_running:
                    break
                
                # Create an event
                event_type = event_types[i % len(event_types)]
                severity = EventSeverity.MINOR if i % 3 != 0 else EventSeverity.MAJOR
                
                event = EbpfEvent(
                    timestamp=time.time(),
                    pid=10000 + i,
                    event_type=event_type,
                    severity=severity,
                    pattern_id=(i % 2) + 1 if i % 3 == 0 else 0,
                    thresholds_crossed=1 << (i % 4),  # Binary: 0001, 0010, 0100, 1000
                    filename=f"/tmp/test_file_{i}.txt",
                    process_name=f"test_process_{i}"
                )
                
                # Create batch and add to queue
                batch = EbpfEventBatch()
                batch.add_event(event)
                await self.queue.put(batch.to_json())
                
                # Sleep
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            logger.info("Event simulation cancelled")
            raise
    
    async def start(self, **kwargs) -> None:
        """Start event simulation"""
        if self.is_running:
            logger.warning("Event simulator is already running")
            return
        
        self.is_running = True
        self.task = asyncio.create_task(self.simulate_events(**kwargs))
    
    async def stop(self) -> None:
        """Stop event simulation"""
        if not self.is_running:
            return
        
        self.is_running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass


async def main():
    """Main entry point for testing"""
    # Check if running as root (required for eBPF)
    if os.geteuid() != 0:
        print("This program must be run as root (sudo).")
        sys.exit(1)
    
    monitor = EbpfMonitor()
    
    # Set up signal handling
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(monitor, loop)))
    
    async def consumer():
        while True:
            batch = await monitor.get_events()
            print(f"Received batch: {batch}")
    
    await monitor.start()
    consumer_task = asyncio.create_task(consumer())
    
    try:
        # Run indefinitely
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        consumer_task.cancel()
        await monitor.stop()


async def shutdown(monitor: EbpfMonitor, loop: asyncio.AbstractEventLoop):
    """Handle graceful shutdown"""
    logger.info("Shutting down...")
    await monitor.stop()
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    loop.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1) 
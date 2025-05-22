#!/usr/bin/env python3
"""
Filesystem Monitor Module

This module uses watchdog to monitor filesystem events, batch them at regular intervals,
and emit them via an asyncio queue for consumption by other components.
"""

import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple

import yaml
from watchdog.events import (
    FileSystemEvent, 
    FileSystemEventHandler,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent
)
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver  # Fallback if native fails

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("fs_monitor")

@dataclass
class EventBatch:
    """Container for a batch of filesystem events"""
    timestamp: float = field(default_factory=time.time)
    events: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_event(self, event_type: str, src_path: str, dest_path: Optional[str] = None, 
                  file_size: Optional[int] = None, is_directory: bool = False) -> None:
        """Add an event to the batch"""
        event_dict = {
            "type": event_type,
            "path": src_path,
            "is_directory": is_directory,
            "timestamp": time.time()
        }
        
        if dest_path:
            event_dict["dest_path"] = dest_path
            
        if file_size is not None:
            event_dict["size"] = file_size
            
        self.events.append(event_dict)
    
    def to_json(self) -> str:
        """Convert batch to JSON string"""
        batch_dict = {
            "batch_timestamp": self.timestamp,
            "batch_size": len(self.events),
            "events": self.events
        }
        return json.dumps(batch_dict)
    
    def is_empty(self) -> bool:
        """Check if batch is empty"""
        return len(self.events) == 0


class EventBatcher:
    """Collects and batches filesystem events"""
    
    def __init__(self, interval_ms: int = 500, max_events: int = 100):
        self.interval_sec = interval_ms / 1000
        self.max_events = max_events
        self.current_batch = EventBatch()
        self.lock = asyncio.Lock()
    
    async def add_event(self, event_type: str, src_path: str, dest_path: Optional[str] = None,
                        file_size: Optional[int] = None, is_directory: bool = False) -> None:
        """Add an event to the current batch"""
        async with self.lock:
            self.current_batch.add_event(event_type, src_path, dest_path, file_size, is_directory)
    
    async def get_batch(self) -> EventBatch:
        """Get the current batch and create a new one"""
        async with self.lock:
            batch = self.current_batch
            self.current_batch = EventBatch()
            return batch


class BlockwaveEventHandler(FileSystemEventHandler):
    """Custom event handler for filesystem events"""
    
    def __init__(self, event_batcher: EventBatcher, ignore_patterns: List[str] = None):
        super().__init__()
        self.event_batcher = event_batcher
        self.ignore_patterns = ignore_patterns or []
        self._loop = asyncio.get_event_loop()
    
    def _should_ignore(self, path: str) -> bool:
        """Check if the path matches any ignore patterns"""
        from fnmatch import fnmatch
        path = path.replace('\\', '/')  # Normalize path separators
        
        for pattern in self.ignore_patterns:
            if fnmatch(path, pattern):
                return True
        return False
    
    def _get_file_size(self, path: str) -> Optional[int]:
        """Get file size if the path exists and is a file"""
        try:
            if os.path.isfile(path):
                return os.path.getsize(path)
            return None
        except (OSError, FileNotFoundError):
            return None
    
    def _process_event(self, event_type: str, event: FileSystemEvent) -> None:
        """Process a filesystem event"""
        if self._should_ignore(event.src_path):
            return
            
        src_path = os.path.abspath(event.src_path)
        dest_path = getattr(event, 'dest_path', None)
        is_directory = getattr(event, 'is_directory', False)
        
        if dest_path:
            dest_path = os.path.abspath(dest_path)
            if self._should_ignore(dest_path):
                return
        
        file_size = self._get_file_size(src_path)
        
        # Schedule the event to be added to the batch
        asyncio.run_coroutine_threadsafe(
            self.event_batcher.add_event(
                event_type, src_path, dest_path, file_size, is_directory
            ),
            self._loop
        )
    
    def on_created(self, event: FileCreatedEvent) -> None:
        """Handle file/directory creation event"""
        self._process_event("created", event)
    
    def on_deleted(self, event: FileDeletedEvent) -> None:
        """Handle file/directory deletion event"""
        self._process_event("deleted", event)
    
    def on_modified(self, event: FileModifiedEvent) -> None:
        """Handle file/directory modification event"""
        self._process_event("modified", event)
    
    def on_moved(self, event: FileMovedEvent) -> None:
        """Handle file/directory move event"""
        self._process_event("moved", event)


class FSMonitor:
    """
    Filesystem monitor using watchdog to detect file changes
    and emit batched events through an asyncio queue.
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize the filesystem monitor"""
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Set up event batching
        batch_config = self.config['fs_monitor']['batch']
        self.event_batcher = EventBatcher(
            interval_ms=batch_config['interval_ms'],
            max_events=batch_config['max_events']
        )
        
        # Set up event queue
        queue_size = self.config['fs_monitor']['performance']['queue_size']
        self.event_queue = asyncio.Queue(maxsize=queue_size)
        
        # Set up watchdog
        self.event_handler = BlockwaveEventHandler(
            self.event_batcher,
            ignore_patterns=self.config['fs_monitor']['ignore_patterns']
        )
        
        self.observer = self._create_observer()
        self.watch_dirs = self.config['fs_monitor']['watch_dirs']
        
        # State tracking
        self.watches = []
        self.is_running = False
        self.batch_task = None
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        config_path = Path(config_path)
        
        if not config_path.exists():
            logger.error(f"Configuration file {config_path} not found.")
            default_config = {
                'fs_monitor': {
                    'watch_dirs': ['/tmp'],
                    'ignore_patterns': ['*.tmp', '*.swp'],
                    'batch': {'interval_ms': 500, 'max_events': 100},
                    'performance': {'threads': 1, 'queue_size': 1000},
                    'logging': {'level': 'INFO', 'file': None}
                },
                'app': {'name': 'BlockWave-Ransom', 'version': '1.0.0'}
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
        log_config = self.config['fs_monitor']['logging']
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
    
    def _create_observer(self) -> Observer:
        """Create the file system observer"""
        threads = self.config['fs_monitor']['performance'].get('threads', 1)
        
        try:
            # Try to create the native observer first
            observer = Observer(timeout=1)
            return observer
        except Exception as e:
            logger.warning(f"Native observer failed, falling back to polling: {e}")
            return PollingObserver(timeout=1)
    
    async def start(self) -> None:
        """Start the filesystem monitor"""
        if self.is_running:
            logger.warning("Filesystem monitor is already running.")
            return
        
        logger.info("Starting filesystem monitor...")
        
        # Start the batch processing task
        self.batch_task = asyncio.create_task(self._process_batches())
        
        # Start observing directories
        for directory in self.watch_dirs:
            try:
                dir_path = Path(directory)
                if not dir_path.exists():
                    logger.warning(f"Directory {directory} does not exist, skipping.")
                    continue
                
                logger.info(f"Watching directory: {directory}")
                watch = self.observer.schedule(
                    self.event_handler,
                    directory,
                    recursive=True
                )
                self.watches.append(watch)
            except Exception as e:
                logger.error(f"Error watching directory {directory}: {e}")
        
        if not self.watches:
            logger.error("No valid directories to watch.")
            return
        
        self.observer.start()
        self.is_running = True
        logger.info("Filesystem monitor started successfully.")
    
    async def stop(self) -> None:
        """Stop the filesystem monitor"""
        if not self.is_running:
            logger.warning("Filesystem monitor is not running.")
            return
        
        logger.info("Stopping filesystem monitor...")
        
        # Cancel batch processing task
        if self.batch_task:
            self.batch_task.cancel()
            try:
                await self.batch_task
            except asyncio.CancelledError:
                pass
        
        # Stop and join the observer
        self.observer.stop()
        self.observer.join()
        
        self.is_running = False
        logger.info("Filesystem monitor stopped.")
    
    async def _process_batches(self) -> None:
        """Process event batches and push them to the queue"""
        try:
            while True:
                # Wait for the batch interval
                await asyncio.sleep(self.event_batcher.interval_sec)
                
                # Get the current batch
                batch = await self.event_batcher.get_batch()
                
                # Skip empty batches
                if batch.is_empty():
                    continue
                
                # Put the batch in the queue
                try:
                    batch_json = batch.to_json()
                    logger.debug(f"Sending batch of {len(batch.events)} events")
                    await self.event_queue.put(batch_json)
                except Exception as e:
                    logger.error(f"Error processing batch: {e}")
        except asyncio.CancelledError:
            logger.info("Batch processing task cancelled.")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in batch processing: {e}")
    
    async def get_events(self) -> str:
        """Get the next batch of events from the queue"""
        return await self.event_queue.get()


async def main():
    """Main entry point for testing"""
    monitor = FSMonitor()
    
    async def consumer():
        while True:
            batch = await monitor.get_events()
            print(f"Received batch: {batch}")
    
    await monitor.start()
    consumer_task = asyncio.create_task(consumer())
    
    try:
        # Run for 1 minute for testing
        await asyncio.sleep(60)
    finally:
        consumer_task.cancel()
        await monitor.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1) 
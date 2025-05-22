#!/usr/bin/env python3
"""
BlockWave-Ransom Logger

A logging module that creates and manages an SQLite3 database for storing
detection and mitigation events. Features include:
- Configurable database path
- Schema versioning and migration
- Concurrent writes support (WAL mode)
- Timestamped events with hash and metadata storage
- Query methods for event retrieval and analysis
"""

import asyncio
import json
import logging
import os
import sqlite3
import sys
import threading
import time
import traceback
import uuid
import yaml
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, Iterator

# Configure standard logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("logger")

# Current schema version
SCHEMA_VERSION = 1


class EventType(Enum):
    """Types of events that can be logged"""
    DETECTION = auto()      # Ransomware detection event
    MITIGATION = auto()     # Mitigation action event
    SYSTEM = auto()         # System event (startup, shutdown, etc.)
    FILE = auto()           # File event (create, modify, delete)
    PROCESS = auto()        # Process event (start, stop, etc.)
    NETWORK = auto()        # Network event
    BACKUP = auto()         # Backup event
    RESTORE = auto()        # Restore event
    ERROR = auto()          # Error event
    WARNING = auto()        # Warning event
    INFO = auto()           # Info event


class EventSeverity(Enum):
    """Severity levels for events"""
    DEBUG = auto()
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()


@dataclass
class Event:
    """Base class for all loggable events"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    type: EventType = EventType.INFO
    severity: EventSeverity = EventSeverity.INFO
    source: str = ""
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage"""
        result = {
            "id": self.id,
            "timestamp": self.timestamp,
            "type": self.type.name,
            "severity": self.severity.name,
            "source": self.source,
            "message": self.message,
            "metadata": json.dumps(self.metadata)
        }
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Event':
        """Create an Event from a dictionary"""
        # Convert string enum values back to enum objects
        event_type = EventType[data.pop('type')] if 'type' in data else EventType.INFO
        severity = EventSeverity[data.pop('severity')] if 'severity' in data else EventSeverity.INFO
        
        # Parse metadata if it exists
        metadata = {}
        if 'metadata' in data:
            try:
                metadata = json.loads(data.pop('metadata'))
            except (json.JSONDecodeError, TypeError):
                pass
        
        # Create event with remaining data and parsed values
        return cls(
            type=event_type,
            severity=severity,
            metadata=metadata,
            **{k: v for k, v in data.items() if k in ['id', 'timestamp', 'source', 'message']}
        )


@dataclass
class DetectionEvent(Event):
    """Event for ransomware detection"""
    def __init__(self, **kwargs):
        super().__init__(type=EventType.DETECTION, **kwargs)


@dataclass
class MitigationEvent(Event):
    """Event for mitigation actions"""
    def __init__(self, **kwargs):
        super().__init__(type=EventType.MITIGATION, **kwargs)


@dataclass
class SystemEvent(Event):
    """Event for system operations"""
    def __init__(self, **kwargs):
        super().__init__(type=EventType.SYSTEM, **kwargs)


@dataclass
class FileEvent(Event):
    """Event for file operations"""
    def __init__(self, **kwargs):
        super().__init__(type=EventType.FILE, **kwargs)


@dataclass
class ProcessEvent(Event):
    """Event for process operations"""
    def __init__(self, **kwargs):
        super().__init__(type=EventType.PROCESS, **kwargs)


class DBLock:
    """Thread-safe lock for database access"""
    def __init__(self):
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()
    
    @contextmanager
    def acquire(self) -> Iterator[None]:
        """Acquire the lock for synchronous operations"""
        try:
            self._lock.acquire()
            yield
        finally:
            self._lock.release()
    
    async def acquire_async(self) -> None:
        """Acquire the lock for async operations"""
        await self._async_lock.acquire()
    
    def release_async(self) -> None:
        """Release the async lock"""
        self._async_lock.release()


class Logger:
    """
    SQLite3 logger for BlockWave-Ransom system.
    
    This class:
    1. Creates and manages an SQLite3 database
    2. Handles schema migration for version updates
    3. Provides methods for logging various event types
    4. Supports querying events with filtering
    5. Implements concurrent write support
    6. Includes error handling and retry logic
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize the logger with configuration"""
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Database settings from config
        settings = self.config.get("logger", {})
        self.db_path = settings.get("db_path", "/var/lib/blockwave/events.db")
        self.retention_days = settings.get("retention_days", 30)
        self.max_retries = settings.get("max_retries", 3)
        self.retry_delay = settings.get("retry_delay_sec", 0.5)
        
        # Create database directory if it doesn't exist
        db_dir = os.path.dirname(self.db_path)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        # Initialize lock for thread safety
        self.lock = DBLock()
        
        # Create or migrate the database
        self._init_database()
        
        logger.info(f"Logger initialized with database at {self.db_path}")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            # Add default logger config if not present
            if "logger" not in config:
                config["logger"] = {
                    "db_path": "/var/lib/blockwave/events.db",
                    "retention_days": 30,
                    "max_retries": 3,
                    "retry_delay_sec": 0.5,
                    "logging": {
                        "level": "INFO",
                        "file": "/var/log/blockwave/logger.log"
                    }
                }
            return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)
    
    def _setup_logging(self) -> None:
        """Configure logging based on configuration"""
        log_config = self.config.get("logger", {}).get("logging", {})
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
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a connection to the SQLite database with WAL mode enabled"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            
            # Enable WAL mode for better concurrency
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            
            return conn
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
    
    def _init_database(self) -> None:
        """Initialize the database schema or migrate if needed"""
        with self.lock.acquire():
            try:
                conn = self._get_connection()
                try:
                    # Check if schema_version table exists
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
                    )
                    if not cursor.fetchone():
                        self._create_schema(conn)
                    else:
                        # Check if migration is needed
                        cursor.execute("SELECT version FROM schema_version")
                        version = cursor.fetchone()[0]
                        if version < SCHEMA_VERSION:
                            self._migrate_schema(conn, version)
                finally:
                    conn.close()
            except Exception as e:
                logger.error(f"Failed to initialize database: {e}")
                raise
    
    def _create_schema(self, conn: sqlite3.Connection) -> None:
        """Create the initial database schema"""
        try:
            cursor = conn.cursor()
            
            # Schema version table
            cursor.execute('''
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY
            )
            ''')
            
            # Events table
            cursor.execute('''
            CREATE TABLE events (
                id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                metadata TEXT
            )
            ''')
            
            # Index for efficient timestamp queries
            cursor.execute('''
            CREATE INDEX idx_events_timestamp ON events (timestamp)
            ''')
            
            # Index for efficient type queries
            cursor.execute('''
            CREATE INDEX idx_events_type ON events (type)
            ''')
            
            # Insert current schema version
            cursor.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
            
            conn.commit()
            logger.info(f"Database schema created at version {SCHEMA_VERSION}")
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to create database schema: {e}")
            raise
    
    def _migrate_schema(self, conn: sqlite3.Connection, current_version: int) -> None:
        """Migrate the database schema to the latest version"""
        try:
            cursor = conn.cursor()
            
            # Example migration from version 1 to 2 (not needed yet)
            if current_version == 1 and SCHEMA_VERSION >= 2:
                # Future schema changes would go here
                pass
            
            # Update schema version
            cursor.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))
            
            conn.commit()
            logger.info(f"Database schema migrated from version {current_version} to {SCHEMA_VERSION}")
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to migrate database schema: {e}")
            raise
    
    def _purge_old_events(self) -> int:
        """Remove events older than retention period, returns count of deleted events"""
        with self.lock.acquire():
            try:
                conn = self._get_connection()
                try:
                    cursor = conn.cursor()
                    
                    # Calculate cutoff timestamp
                    cutoff = time.time() - (self.retention_days * 24 * 60 * 60)
                    
                    # Delete old events
                    cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
                    deleted_count = cursor.rowcount
                    
                    conn.commit()
                    logger.info(f"Purged {deleted_count} events older than {self.retention_days} days")
                    return deleted_count
                finally:
                    conn.close()
            except Exception as e:
                logger.error(f"Failed to purge old events: {e}")
                return 0
    
    def log_event(self, event: Event) -> bool:
        """Log an event to the database, with retries on failure"""
        with self.lock.acquire():
            retries = 0
            while retries < self.max_retries:
                try:
                    conn = self._get_connection()
                    try:
                        cursor = conn.cursor()
                        
                        # Convert event to dictionary for database
                        event_dict = event.to_dict()
                        
                        # Insert the event
                        cursor.execute(
                            '''
                            INSERT INTO events 
                            (id, timestamp, type, severity, source, message, metadata)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            ''',
                            (
                                event_dict['id'],
                                event_dict['timestamp'],
                                event_dict['type'],
                                event_dict['severity'],
                                event_dict['source'],
                                event_dict['message'],
                                event_dict['metadata']
                            )
                        )
                        
                        conn.commit()
                        return True
                    finally:
                        conn.close()
                except sqlite3.Error as e:
                    logger.warning(f"Database error while logging event (attempt {retries+1}/{self.max_retries}): {e}")
                    retries += 1
                    if retries < self.max_retries:
                        time.sleep(self.retry_delay)
                except Exception as e:
                    logger.error(f"Unexpected error while logging event: {e}")
                    return False
            
            logger.error(f"Failed to log event after {self.max_retries} attempts")
            return False
    
    async def log_event_async(self, event: Event) -> bool:
        """Async version of log_event"""
        await self.lock.acquire_async()
        try:
            return self.log_event(event)
        finally:
            self.lock.release_async()
    
    def get_events(self, 
                  event_type: Optional[EventType] = None,
                  severity: Optional[EventSeverity] = None,
                  source: Optional[str] = None,
                  start_time: Optional[float] = None,
                  end_time: Optional[float] = None,
                  limit: int = 100,
                  offset: int = 0) -> List[Event]:
        """Query events with filters"""
        with self.lock.acquire():
            try:
                conn = self._get_connection()
                try:
                    cursor = conn.cursor()
                    
                    # Build the query with filters
                    query = "SELECT * FROM events WHERE 1=1"
                    params = []
                    
                    if event_type:
                        query += " AND type = ?"
                        params.append(event_type.name)
                    
                    if severity:
                        query += " AND severity = ?"
                        params.append(severity.name)
                    
                    if source:
                        query += " AND source = ?"
                        params.append(source)
                    
                    if start_time:
                        query += " AND timestamp >= ?"
                        params.append(start_time)
                    
                    if end_time:
                        query += " AND timestamp <= ?"
                        params.append(end_time)
                    
                    # Add order, limit and offset
                    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                    params.extend([limit, offset])
                    
                    # Execute the query
                    cursor.execute(query, params)
                    rows = cursor.fetchall()
                    
                    # Convert rows to Event objects
                    events = []
                    for row in rows:
                        row_dict = dict(row)
                        events.append(Event.from_dict(row_dict))
                    
                    return events
                finally:
                    conn.close()
            except Exception as e:
                logger.error(f"Failed to query events: {e}")
                return []
    
    async def get_events_async(self, **kwargs) -> List[Event]:
        """Async version of get_events"""
        await self.lock.acquire_async()
        try:
            return self.get_events(**kwargs)
        finally:
            self.lock.release_async()
    
    def get_event_by_id(self, event_id: str) -> Optional[Event]:
        """Get a specific event by ID"""
        with self.lock.acquire():
            try:
                conn = self._get_connection()
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
                    row = cursor.fetchone()
                    
                    if row:
                        return Event.from_dict(dict(row))
                    return None
                finally:
                    conn.close()
            except Exception as e:
                logger.error(f"Failed to get event by ID {event_id}: {e}")
                return None
    
    def log_detection(self, source: str, message: str, 
                     severity: EventSeverity = EventSeverity.WARNING,
                     metadata: Optional[Dict[str, Any]] = None) -> str:
        """Log a detection event and return the event ID"""
        event = DetectionEvent(
            source=source,
            message=message,
            severity=severity,
            metadata=metadata or {}
        )
        success = self.log_event(event)
        return event.id if success else ""
    
    def log_mitigation(self, source: str, message: str, 
                      severity: EventSeverity = EventSeverity.INFO,
                      metadata: Optional[Dict[str, Any]] = None) -> str:
        """Log a mitigation event and return the event ID"""
        event = MitigationEvent(
            source=source,
            message=message,
            severity=severity,
            metadata=metadata or {}
        )
        success = self.log_event(event)
        return event.id if success else ""
    
    def log_system(self, source: str, message: str, 
                  severity: EventSeverity = EventSeverity.INFO,
                  metadata: Optional[Dict[str, Any]] = None) -> str:
        """Log a system event and return the event ID"""
        event = SystemEvent(
            source=source,
            message=message,
            severity=severity,
            metadata=metadata or {}
        )
        success = self.log_event(event)
        return event.id if success else ""
    
    def log_file(self, source: str, message: str, 
                severity: EventSeverity = EventSeverity.INFO,
                metadata: Optional[Dict[str, Any]] = None) -> str:
        """Log a file event and return the event ID"""
        event = FileEvent(
            source=source,
            message=message,
            severity=severity,
            metadata=metadata or {}
        )
        success = self.log_event(event)
        return event.id if success else ""
    
    def log_process(self, source: str, message: str, 
                   severity: EventSeverity = EventSeverity.INFO,
                   metadata: Optional[Dict[str, Any]] = None) -> str:
        """Log a process event and return the event ID"""
        event = ProcessEvent(
            source=source,
            message=message,
            severity=severity,
            metadata=metadata or {}
        )
        success = self.log_event(event)
        return event.id if success else ""
    
    def get_event_count(self, 
                       event_type: Optional[EventType] = None,
                       severity: Optional[EventSeverity] = None,
                       source: Optional[str] = None,
                       start_time: Optional[float] = None,
                       end_time: Optional[float] = None) -> int:
        """Get count of events matching filters"""
        with self.lock.acquire():
            try:
                conn = self._get_connection()
                try:
                    cursor = conn.cursor()
                    
                    # Build the query with filters
                    query = "SELECT COUNT(*) FROM events WHERE 1=1"
                    params = []
                    
                    if event_type:
                        query += " AND type = ?"
                        params.append(event_type.name)
                    
                    if severity:
                        query += " AND severity = ?"
                        params.append(severity.name)
                    
                    if source:
                        query += " AND source = ?"
                        params.append(source)
                    
                    if start_time:
                        query += " AND timestamp >= ?"
                        params.append(start_time)
                    
                    if end_time:
                        query += " AND timestamp <= ?"
                        params.append(end_time)
                    
                    # Execute the query
                    cursor.execute(query, params)
                    count = cursor.fetchone()[0]
                    
                    return count
                finally:
                    conn.close()
            except Exception as e:
                logger.error(f"Failed to get event count: {e}")
                return 0
    
    def close(self) -> None:
        """Close the logger (perform any cleanup operations)"""
        try:
            # Purge old events before closing
            self._purge_old_events()
            logger.info("Logger closed successfully")
        except Exception as e:
            logger.error(f"Error closing logger: {e}")


async def main():
    """Main entry point for testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='BlockWave-Ransom Logger')
    parser.add_argument('--config', type=str, default='config/config.yaml', 
                        help='Path to configuration file')
    parser.add_argument('--purge', action='store_true', 
                        help='Purge old events based on retention period')
    parser.add_argument('--log-test', action='store_true', 
                        help='Log a test event')
    parser.add_argument('--query', action='store_true', 
                        help='Query recent events')
    args = parser.parse_args()
    
    # Initialize logger
    db_logger = Logger(args.config)
    
    try:
        if args.purge:
            # Purge old events
            count = db_logger._purge_old_events()
            print(f"Purged {count} old events")
            
        elif args.log_test:
            # Log test events
            print("Logging test events...")
            for severity in EventSeverity:
                event_id = db_logger.log_detection(
                    source="test",
                    message=f"Test {severity.name} event",
                    severity=severity,
                    metadata={"test": True, "value": severity.name}
                )
                print(f"Logged {severity.name} event with ID: {event_id}")
            
        elif args.query:
            # Query events
            events = db_logger.get_events(limit=10)
            print(f"Recent events ({len(events)}):")
            for event in events:
                time_str = datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')
                print(f"{time_str} [{event.severity.name}] {event.source}: {event.message}")
        
        else:
            # Show help
            parser.print_help()
    
    finally:
        # Close logger
        db_logger.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting due to keyboard interrupt")
        sys.exit(0) 
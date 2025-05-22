#!/usr/bin/env python3
"""
Test suite for BlockWave-Ransom logger module
"""

import asyncio
import json
import os
import pytest
import sqlite3
import tempfile
import time
import yaml
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path to import module
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from blockwave.logger import (
    Logger, Event, EventType, EventSeverity,
    DetectionEvent, MitigationEvent, SystemEvent
)


@pytest.fixture
def temp_db():
    """Create a temporary database file for testing"""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    yield path
    # Clean up after test
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def temp_config():
    """Create a temporary configuration file for testing"""
    fd, path = tempfile.mkstemp(suffix='.yaml')
    config = {
        "logger": {
            "db_path": "",  # Will be set in tests
            "retention_days": 7,
            "max_retries": 2,
            "retry_delay_sec": 0.1,
            "logging": {
                "level": "INFO",
                "file": None
            }
        }
    }
    
    with os.fdopen(fd, 'w') as f:
        yaml.dump(config, f)
    
    yield path
    
    # Clean up after test
    if os.path.exists(path):
        os.unlink(path)


class TestLogger:
    """Test cases for the Logger class"""
    
    def test_init_database(self, temp_db, temp_config):
        """Test database initialization"""
        # Modify config to use temp_db
        with open(temp_config, 'r') as f:
            config = yaml.safe_load(f)
        
        config["logger"]["db_path"] = temp_db
        
        with open(temp_config, 'w') as f:
            yaml.dump(config, f)
        
        # Init logger with temp config
        db_logger = Logger(temp_config)
        
        # Check database tables exist
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Check schema_version table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
        assert cursor.fetchone() is not None
        
        # Check schema version
        cursor.execute("SELECT version FROM schema_version")
        assert cursor.fetchone()[0] == 1
        
        # Check events table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        assert cursor.fetchone() is not None
        
        # Check indexes
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_events_timestamp'")
        assert cursor.fetchone() is not None
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_events_type'")
        assert cursor.fetchone() is not None
        
        conn.close()
        db_logger.close()
    
    def test_log_event(self, temp_db, temp_config):
        """Test logging an event"""
        # Modify config to use temp_db
        with open(temp_config, 'r') as f:
            config = yaml.safe_load(f)
        
        config["logger"]["db_path"] = temp_db
        
        with open(temp_config, 'w') as f:
            yaml.dump(config, f)
        
        # Init logger with temp config
        db_logger = Logger(temp_config)
        
        # Create test event
        event = Event(
            id="test-id-123",
            timestamp=time.time(),
            type=EventType.DETECTION,
            severity=EventSeverity.WARNING,
            source="test_module",
            message="Test detection event",
            metadata={"test_key": "test_value", "count": 42}
        )
        
        # Log the event
        success = db_logger.log_event(event)
        assert success is True
        
        # Check event was logged
        conn = sqlite3.connect(temp_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM events WHERE id = ?", ("test-id-123",))
        row = dict(cursor.fetchone())
        
        assert row["id"] == "test-id-123"
        assert row["type"] == "DETECTION"
        assert row["severity"] == "WARNING"
        assert row["source"] == "test_module"
        assert row["message"] == "Test detection event"
        
        # Check metadata was serialized correctly
        metadata = json.loads(row["metadata"])
        assert metadata["test_key"] == "test_value"
        assert metadata["count"] == 42
        
        conn.close()
        db_logger.close()
    
    def test_event_query(self, temp_db, temp_config):
        """Test querying events with filters"""
        # Setup logger with temp files
        with open(temp_config, 'r') as f:
            config = yaml.safe_load(f)
        
        config["logger"]["db_path"] = temp_db
        
        with open(temp_config, 'w') as f:
            yaml.dump(config, f)
        
        db_logger = Logger(temp_config)
        
        # Create test events with different types and severities
        now = time.time()
        
        # Event 1: Detection Warning
        db_logger.log_detection(
            source="test_module", 
            message="Detection warning", 
            severity=EventSeverity.WARNING,
            metadata={"type": "test", "count": 1}
        )
        
        # Event 2: Mitigation Info
        db_logger.log_mitigation(
            source="test_module", 
            message="Mitigation action", 
            severity=EventSeverity.INFO,
            metadata={"type": "test", "count": 2}
        )
        
        # Event 3: System Error
        db_logger.log_system(
            source="test_module", 
            message="System error", 
            severity=EventSeverity.ERROR,
            metadata={"type": "test", "count": 3}
        )
        
        # Event 4: Detection Critical
        db_logger.log_detection(
            source="other_module", 
            message="Critical detection", 
            severity=EventSeverity.CRITICAL,
            metadata={"type": "test", "count": 4}
        )
        
        # Test filtering by type
        events = db_logger.get_events(event_type=EventType.DETECTION)
        assert len(events) == 2
        
        # Test filtering by severity
        events = db_logger.get_events(severity=EventSeverity.ERROR)
        assert len(events) == 1
        assert events[0].message == "System error"
        
        # Test filtering by source
        events = db_logger.get_events(source="other_module")
        assert len(events) == 1
        assert events[0].source == "other_module"
        
        # Test filtering by time range
        events = db_logger.get_events(start_time=now, end_time=now + 3600)
        assert len(events) == 4
        
        # Test limiting results
        events = db_logger.get_events(limit=2)
        assert len(events) == 2
        
        # Test ordering
        events = db_logger.get_events()
        assert len(events) == 4
        # Most recent first
        assert events[0].severity == EventSeverity.CRITICAL
        assert events[-1].severity == EventSeverity.WARNING
        
        # Test get_event_count
        count = db_logger.get_event_count(event_type=EventType.DETECTION)
        assert count == 2
        
        db_logger.close()
    
    def test_event_purging(self, temp_db, temp_config):
        """Test purging old events"""
        # Setup logger with temp files
        with open(temp_config, 'r') as f:
            config = yaml.safe_load(f)
        
        config["logger"]["db_path"] = temp_db
        config["logger"]["retention_days"] = 7  # 7 days retention
        
        with open(temp_config, 'w') as f:
            yaml.dump(config, f)
        
        db_logger = Logger(temp_config)
        
        # Create some events with different timestamps
        # Current time
        now = time.time()
        
        # Recent event (today)
        event1 = Event(
            timestamp=now,
            type=EventType.INFO,
            source="test_module",
            message="Recent event"
        )
        db_logger.log_event(event1)
        
        # Old event (10 days ago - beyond retention period)
        ten_days_ago = now - (10 * 24 * 60 * 60)
        event2 = Event(
            timestamp=ten_days_ago,
            type=EventType.INFO,
            source="test_module",
            message="Old event"
        )
        
        # Directly insert into database to avoid timestamp auto-setting
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        event_dict = event2.to_dict()
        cursor.execute(
            '''
            INSERT INTO events (id, timestamp, type, severity, source, message, metadata)
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
        conn.close()
        
        # Verify we have 2 events
        assert db_logger.get_event_count() == 2
        
        # Purge old events
        deleted = db_logger._purge_old_events()
        
        # Verify the old event was purged
        assert deleted == 1
        assert db_logger.get_event_count() == 1
        
        # Get remaining event and verify it's the recent one
        events = db_logger.get_events()
        assert len(events) == 1
        assert events[0].message == "Recent event"
        
        db_logger.close()
    
    @pytest.mark.asyncio
    async def test_async_methods(self, temp_db, temp_config):
        """Test async methods"""
        # Setup logger with temp files
        with open(temp_config, 'r') as f:
            config = yaml.safe_load(f)
        
        config["logger"]["db_path"] = temp_db
        
        with open(temp_config, 'w') as f:
            yaml.dump(config, f)
        
        db_logger = Logger(temp_config)
        
        # Test async log event
        event = DetectionEvent(
            source="test_async",
            message="Async test event",
            severity=EventSeverity.WARNING
        )
        
        success = await db_logger.log_event_async(event)
        assert success is True
        
        # Test async get events
        events = await db_logger.get_events_async(source="test_async")
        assert len(events) == 1
        assert events[0].source == "test_async"
        assert events[0].message == "Async test event"
        
        db_logger.close()
    
    def test_event_specific_loggers(self, temp_db, temp_config):
        """Test the specific event type loggers"""
        # Setup logger with temp files
        with open(temp_config, 'r') as f:
            config = yaml.safe_load(f)
        
        config["logger"]["db_path"] = temp_db
        
        with open(temp_config, 'w') as f:
            yaml.dump(config, f)
        
        db_logger = Logger(temp_config)
        
        # Test specific loggers
        detection_id = db_logger.log_detection(
            source="detector",
            message="Suspicious activity",
            severity=EventSeverity.WARNING,
            metadata={"file_count": 42}
        )
        
        mitigation_id = db_logger.log_mitigation(
            source="mitigator",
            message="Process terminated",
            severity=EventSeverity.INFO,
            metadata={"pid": 1234}
        )
        
        system_id = db_logger.log_system(
            source="system",
            message="Startup complete",
        )
        
        file_id = db_logger.log_file(
            source="fs_monitor",
            message="File modified",
            metadata={"path": "/tmp/test.txt"}
        )
        
        process_id = db_logger.log_process(
            source="proc_inspector",
            message="Process created",
            metadata={"pid": 5678, "name": "test.exe"}
        )
        
        # Verify we have 5 events
        assert db_logger.get_event_count() == 5
        
        # Check each type
        detection = db_logger.get_event_by_id(detection_id)
        assert detection.type == EventType.DETECTION
        assert detection.source == "detector"
        assert detection.metadata["file_count"] == 42
        
        mitigation = db_logger.get_event_by_id(mitigation_id)
        assert mitigation.type == EventType.MITIGATION
        assert mitigation.source == "mitigator"
        assert mitigation.metadata["pid"] == 1234
        
        system = db_logger.get_event_by_id(system_id)
        assert system.type == EventType.SYSTEM
        
        file_event = db_logger.get_event_by_id(file_id)
        assert file_event.type == EventType.FILE
        assert file_event.metadata["path"] == "/tmp/test.txt"
        
        process = db_logger.get_event_by_id(process_id)
        assert process.type == EventType.PROCESS
        assert process.metadata["name"] == "test.exe"
        
        db_logger.close()
    
    def test_error_handling(self, temp_db, temp_config):
        """Test error handling with connection issues"""
        # Setup logger with temp files
        with open(temp_config, 'r') as f:
            config = yaml.safe_load(f)
        
        config["logger"]["db_path"] = temp_db
        config["logger"]["max_retries"] = 2
        
        with open(temp_config, 'w') as f:
            yaml.dump(config, f)
        
        db_logger = Logger(temp_config)
        
        # Test with a valid connection first
        event = Event(
            source="test_error",
            message="Test before error"
        )
        assert db_logger.log_event(event) is True
        
        # Now simulate a connection error
        with patch('sqlite3.connect') as mock_connect:
            mock_connect.side_effect = sqlite3.OperationalError("test error")
            
            event = Event(
                source="test_error",
                message="This should fail"
            )
            
            # Should retry and ultimately fail
            assert db_logger.log_event(event) is False
            
            # Verify it attempted to retry
            assert mock_connect.call_count == 2  # Two retries
        
        db_logger.close()


class TestEvent:
    """Test cases for Event classes"""
    
    def test_event_to_dict(self):
        """Test converting an event to a dictionary"""
        timestamp = time.time()
        event = Event(
            id="test-id-456",
            timestamp=timestamp,
            type=EventType.WARNING,
            severity=EventSeverity.ERROR,
            source="test_source",
            message="Test message",
            metadata={"key1": "value1", "key2": 42}
        )
        
        event_dict = event.to_dict()
        
        assert event_dict["id"] == "test-id-456"
        assert event_dict["timestamp"] == timestamp
        assert event_dict["type"] == "WARNING"
        assert event_dict["severity"] == "ERROR"
        assert event_dict["source"] == "test_source"
        assert event_dict["message"] == "Test message"
        
        # Check metadata
        metadata = json.loads(event_dict["metadata"])
        assert metadata["key1"] == "value1"
        assert metadata["key2"] == 42
    
    def test_event_from_dict(self):
        """Test creating an event from a dictionary"""
        timestamp = time.time()
        data = {
            "id": "test-id-789",
            "timestamp": timestamp,
            "type": "DETECTION",
            "severity": "CRITICAL",
            "source": "test_source",
            "message": "Test from dict",
            "metadata": json.dumps({"test": True, "count": 123})
        }
        
        event = Event.from_dict(data)
        
        assert event.id == "test-id-789"
        assert event.timestamp == timestamp
        assert event.type == EventType.DETECTION
        assert event.severity == EventSeverity.CRITICAL
        assert event.source == "test_source"
        assert event.message == "Test from dict"
        assert event.metadata["test"] is True
        assert event.metadata["count"] == 123
    
    def test_specialized_events(self):
        """Test specialized event classes"""
        # Test DetectionEvent
        detection = DetectionEvent(
            source="detector",
            message="Detection event"
        )
        assert detection.type == EventType.DETECTION
        
        # Test MitigationEvent
        mitigation = MitigationEvent(
            source="mitigator",
            message="Mitigation event"
        )
        assert mitigation.type == EventType.MITIGATION
        
        # Test SystemEvent
        system = SystemEvent(
            source="system",
            message="System event"
        )
        assert system.type == EventType.SYSTEM


if __name__ == "__main__":
    pytest.main(["-xvs", __file__]) 
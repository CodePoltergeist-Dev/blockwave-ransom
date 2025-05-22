#!/usr/bin/env python3
"""
BlockWave-Ransom Logger Usage Example

This example demonstrates how to use the Logger module from other components,
showing proper integration patterns with both synchronous and asynchronous code.
"""

import asyncio
import logging
import os
import sys
import time

# Add the parent directory to the path so we can import the blockwave modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from blockwave.logger import (
    Logger, Event, EventType, EventSeverity,
    DetectionEvent, MitigationEvent, FileEvent, ProcessEvent
)

# Configure standard logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("logger_example")


class ExampleComponent:
    """Example component that uses the logger"""
    
    def __init__(self, config_path: str):
        """Initialize the component with a database logger"""
        self.component_name = "example_component"
        
        # Initialize the database logger
        self.db_logger = Logger(config_path)
        
        logger.info("Example component initialized")
    
    def log_file_activity(self, file_path: str, action: str) -> str:
        """Log a file activity synchronously"""
        event_id = self.db_logger.log_file(
            source=self.component_name,
            message=f"File {action}: {file_path}",
            severity=EventSeverity.INFO,
            metadata={
                "path": file_path,
                "action": action,
                "timestamp": time.time(),
                "user": os.getenv("USER", "unknown")
            }
        )
        
        logger.debug(f"Logged file activity with ID: {event_id}")
        return event_id
    
    def handle_detection(self, detection_type: str, confidence: float, details: dict) -> str:
        """Handle and log a ransomware detection"""
        # Log the detection event
        event_id = self.db_logger.log_detection(
            source=self.component_name,
            message=f"Ransomware activity detected: {detection_type}",
            severity=EventSeverity.CRITICAL if confidence > 0.8 else EventSeverity.WARNING,
            metadata={
                "detection_type": detection_type,
                "confidence": confidence,
                "timestamp": time.time(),
                "details": details
            }
        )
        
        # Now log that we've taken action
        self.db_logger.log_mitigation(
            source=self.component_name,
            message=f"Mitigation action taken for detection {event_id}",
            severity=EventSeverity.INFO,
            metadata={
                "detection_id": event_id,
                "action": "quarantine" if confidence > 0.8 else "monitor",
                "timestamp": time.time()
            }
        )
        
        logger.info(f"Handled detection with ID: {event_id}")
        return event_id
    
    async def process_events_async(self, event_count: int) -> None:
        """Demonstrate async logging with multiple events"""
        logger.info(f"Processing {event_count} events asynchronously")
        
        for i in range(event_count):
            # Create an event
            event = ProcessEvent(
                source=self.component_name,
                message=f"Async process event {i+1}",
                severity=EventSeverity.INFO,
                metadata={"process_id": i, "async": True}
            )
            
            # Log it asynchronously
            success = await self.db_logger.log_event_async(event)
            
            # Small delay to simulate real work
            await asyncio.sleep(0.1)
            
            if not success:
                logger.error(f"Failed to log event {i+1}")
        
        logger.info(f"Finished processing {event_count} events asynchronously")
    
    async def query_recent_events(self, limit: int = 5) -> None:
        """Query and display recent events"""
        logger.info(f"Querying {limit} most recent events")
        
        events = await self.db_logger.get_events_async(limit=limit)
        
        print(f"\nRecent Events (count: {len(events)}):")
        print("-" * 70)
        
        for event in events:
            # Format timestamp
            from datetime import datetime
            timestamp = datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            # Print event details
            print(f"[{timestamp}] {event.type.name} - {event.severity.name}")
            print(f"Source: {event.source}")
            print(f"Message: {event.message}")
            
            # Print metadata if any
            if event.metadata:
                print("Metadata:")
                for key, value in event.metadata.items():
                    print(f"  {key}: {value}")
            
            print("-" * 70)
    
    def close(self) -> None:
        """Clean up resources"""
        self.db_logger.close()
        logger.info("Example component cleaned up")


async def main():
    """Main function demonstrating logger usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='BlockWave-Ransom Logger Example')
    parser.add_argument('--config', type=str, default='blockwave/config/config.yaml', 
                        help='Path to configuration file')
    args = parser.parse_args()
    
    # Initialize the example component
    component = ExampleComponent(args.config)
    
    try:
        # Example 1: Log file activity
        component.log_file_activity("/home/user/important.docx", "modified")
        component.log_file_activity("/home/user/secret.pdf", "accessed")
        component.log_file_activity("/var/www/html/index.php", "deleted")
        
        # Example 2: Handle a detection
        component.handle_detection(
            detection_type="encryption_pattern",
            confidence=0.92,
            details={
                "files_affected": 37,
                "process_id": 1234,
                "process_name": "suspicious.exe",
                "pattern": "open-write-rename"
            }
        )
        
        # Example 3: Async event processing
        await component.process_events_async(5)
        
        # Example 4: Query recent events
        await component.query_recent_events(10)
        
    finally:
        # Clean up
        component.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting due to keyboard interrupt")
        sys.exit(0) 
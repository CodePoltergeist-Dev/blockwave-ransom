#!/usr/bin/env python3
"""
YARA Scanner Module

This module loads YARA rules, scans files and processes for matches,
and emits match events with detailed rule metadata.
"""

import asyncio
import concurrent.futures
import json
import logging
import os
import psutil
import re
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple, Union, Callable

import yaml
try:
    import yara
except ImportError:
    print("Error: YARA Python bindings are required. Please install them first.")
    print("pip install yara-python")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("yara_scanner")


@dataclass
class YaraRule:
    """Represents a compiled YARA rule with metadata"""
    identifier: str
    tags: List[str]
    meta: Dict[str, Any]
    sources: Dict[str, str]

    @classmethod
    def from_yara_rule(cls, rule):
        """Create YaraRule from a yara-python rule object"""
        return cls(
            identifier=rule.identifier,
            tags=rule.tags,
            meta=rule.meta,
            sources={namespace: filepath for namespace, filepath in rule.namespace_iterator()}
        )


@dataclass
class YaraMatch:
    """Represents a YARA rule match on a specific file or process"""
    rule: YaraRule
    file_path: Optional[str] = None
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    strings: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    scan_type: str = "file"  # "file" or "process"

    def to_dict(self) -> Dict[str, Any]:
        """Convert match to dictionary"""
        result = {
            "timestamp": self.timestamp,
            "rule_id": self.rule.identifier,
            "tags": self.rule.tags,
            "meta": self.rule.meta,
            "strings": self.strings,
            "scan_type": self.scan_type,
        }

        if self.file_path:
            result["file_path"] = self.file_path
            try:
                result["file_size"] = os.path.getsize(self.file_path)
            except (OSError, IOError):
                pass

        if self.process_id:
            result["process_id"] = self.process_id
            result["process_name"] = self.process_name or "unknown"

        return result


@dataclass
class YaraMatchBatch:
    """Container for a batch of YARA match events"""
    timestamp: float = field(default_factory=time.time)
    matches: List[Dict[str, Any]] = field(default_factory=list)

    def add_match(self, match: YaraMatch) -> None:
        """Add a match to the batch"""
        self.matches.append(match.to_dict())

    def to_json(self) -> str:
        """Convert batch to JSON string"""
        batch_dict = {
            "source": "yara_scanner",
            "batch_timestamp": self.timestamp,
            "batch_size": len(self.matches),
            "matches": self.matches
        }
        return json.dumps(batch_dict)

    def is_empty(self) -> bool:
        """Check if batch is empty"""
        return len(self.matches) == 0


class YaraScanner:
    """
    YARA scanner that loads rules, scans files and processes,
    and emits match events through an asyncio queue.
    """

    def __init__(self, config_path: str = "config/config.yaml", rules_path: Optional[str] = None):
        """Initialize the YARA scanner"""
        self.config = self._load_config(config_path)
        self._setup_logging()

        # Set up event queue
        queue_size = self.config.get('yara_scanner', {}).get('queue_size', 1000)
        self.event_queue = asyncio.Queue(maxsize=queue_size)

        # Set up thread pool
        max_workers = self.config.get('yara_scanner', {}).get('threads', 4)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

        # Path to rules
        self.rules_path = rules_path or self.config.get('yara_scanner', {}).get('rules_dir', './rules')
        if not os.path.exists(self.rules_path) and os.path.isfile(self.rules_path):
            # If rules_path is a specific file, use that
            self.rules_files = [self.rules_path]
        else:
            # Otherwise, load all .yar files from the directory
            self.rules_files = self._find_rule_files()

        # Default timeout in seconds
        self.timeout = self.config.get('yara_scanner', {}).get('timeout_sec', 10)

        # Compiled rules
        self.rules = None
        self.rule_objs = {}

        # Scan settings
        self.max_file_size = self.config.get('yara_scanner', {}).get('max_file_size_mb', 10) * 1024 * 1024

        # State tracking
        self.is_running = False
        self.scan_task = None

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        config_path = Path(config_path)

        if not config_path.exists():
            logger.error(f"Configuration file {config_path} not found.")
            default_config = {
                'yara_scanner': {
                    'enabled': True,
                    'queue_size': 1000,
                    'rules_dir': './rules',
                    'timeout_sec': 10,
                    'threads': 4,
                    'max_file_size_mb': 10,
                    'scan_new_files': True,
                    'scan_modified_files': True,
                    'scan_processes': False,
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
        log_config = self.config.get('yara_scanner', {}).get('logging', {})
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

    def _find_rule_files(self) -> List[str]:
        """Find YARA rule files in the rules directory"""
        rule_files = []

        if os.path.isfile(self.rules_path):
            # If rules_path is a specific file, use that
            return [self.rules_path]

        if not os.path.isdir(self.rules_path):
            logger.warning(f"Rules directory {self.rules_path} not found")
            return rule_files

        # Look for .yar and .yara files in the rules directory
        for root, _, files in os.walk(self.rules_path):
            for filename in files:
                if filename.endswith('.yar') or filename.endswith('.yara'):
                    rule_files.append(os.path.join(root, filename))

        if not rule_files:
            logger.warning(f"No YARA rule files found in {self.rules_path}")

        return rule_files

    def _process_match_callback(self, data: Dict[str, Any]) -> None:
        """Process YARA match callback results and create YaraMatch objects"""
        # Extract match data
        rule_obj = self.rule_objs.get(data['rule'])
        if not rule_obj:
            # This shouldn't happen but let's handle it anyway
            rule_obj = YaraRule(
                identifier=data['rule'],
                tags=data.get('tags', []),
                meta=data.get('meta', {}),
                sources={}
            )

        # Create YaraMatch object
        match = YaraMatch(
            rule=rule_obj,
            file_path=data.get('file_path'),
            process_id=data.get('process_id'),
            process_name=data.get('process_name'),
            strings=data.get('strings', []),
            scan_type=data.get('scan_type', 'file')
        )

        # Create batch and add to queue
        batch = YaraMatchBatch()
        batch.add_match(match)
        batch_json = batch.to_json()

        # Schedule sending batch to queue
        asyncio.run_coroutine_threadsafe(
            self._send_batch_to_queue(batch_json),
            asyncio.get_event_loop()
        )

    async def _send_batch_to_queue(self, batch_json: str) -> None:
        """Send batch to the queue"""
        try:
            await self.event_queue.put(batch_json)
            logger.debug("Sent match batch to queue")
        except Exception as e:
            logger.error(f"Error sending batch to queue: {e}")

    def _extract_match_strings(self, yara_match) -> List[Dict[str, Any]]:
        """Extract match strings from a YARA match object"""
        strings = []
        try:
            for string_id, instances in yara_match.strings:
                for offset, matched_data in instances:
                    try:
                        # Try to decode as UTF-8, fallback to hex
                        string_value = matched_data.decode('utf-8')
                    except UnicodeDecodeError:
                        string_value = matched_data.hex()

                    strings.append({
                        'identifier': string_id.decode('utf-8') if isinstance(string_id, bytes) else string_id,
                        'offset': offset,
                        'value': string_value
                    })
        except Exception as e:
            logger.error(f"Error extracting match strings: {e}")
        return strings

    def _load_rules(self) -> bool:
        """Load and compile YARA rules"""
        logger.info("Loading YARA rules...")
        self.rule_objs = {}

        try:
            # First, compile rules
            self.rules = yara.compile(filepaths={
                os.path.basename(rulefile): rulefile
                for rulefile in self.rules_files
            })

            # Now, try to get metadata for each rule
            for rulefile in self.rules_files:
                try:
                    # Compile each file separately to access rule objects
                    rule_obj = yara.compile(filepath=rulefile)
                    for rule in rule_obj.get_rules():
                        yara_rule = YaraRule.from_yara_rule(rule)
                        self.rule_objs[rule.identifier] = yara_rule
                except Exception as e:
                    logger.error(f"Error loading rule metadata from {rulefile}: {e}")

            logger.info(f"Loaded {len(self.rule_objs)} YARA rules successfully")
            return True
        except Exception as e:
            logger.error(f"Error compiling YARA rules: {e}")
            self.rules = None
            return False

    def _scan_file(self, file_path: str, timeout: Optional[int] = None) -> List[YaraMatch]:
        """Scan a file with YARA rules"""
        if not self.rules:
            logger.error("No YARA rules loaded")
            return []

        # Check if file exists and is accessible
        if not os.path.isfile(file_path):
            logger.warning(f"File {file_path} does not exist or is not accessible")
            return []

        # Check file size
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                logger.warning(f"File {file_path} exceeds maximum size limit ({file_size} > {self.max_file_size})")
                return []
        except OSError as e:
            logger.warning(f"Error checking file size for {file_path}: {e}")
            return []

        # Perform the scan
        matches = []
        try:
            timeout_sec = timeout or self.timeout
            scan_results = self.rules.match(file_path, timeout=timeout_sec)

            for match in scan_results:
                rule_obj = self.rule_objs.get(match.rule)
                if not rule_obj:
                    # If we don't have metadata, create a minimal rule object
                    rule_obj = YaraRule(
                        identifier=match.rule,
                        tags=match.tags,
                        meta=match.meta,
                        sources={}
                    )

                # Extract match strings
                strings = self._extract_match_strings(match)

                # Create YaraMatch object
                yara_match = YaraMatch(
                    rule=rule_obj,
                    file_path=file_path,
                    strings=strings,
                    scan_type="file"
                )
                matches.append(yara_match)

            if matches:
                logger.info(f"Found {len(matches)} YARA matches in file {file_path}")

            return matches
        except yara.TimeoutError:
            logger.warning(f"YARA scan timed out for file {file_path}")
            return []
        except yara.Error as e:
            logger.error(f"YARA error scanning file {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []

    def _scan_process(self, pid: int, timeout: Optional[int] = None) -> List[YaraMatch]:
        """Scan a process with YARA rules"""
        if not self.rules:
            logger.error("No YARA rules loaded")
            return []

        # Check if process exists
        process_name = "unknown"
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            # Skip if process no longer exists
            if not process.is_running():
                logger.warning(f"Process {pid} is no longer running")
                return []
        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} does not exist")
            return []
        except Exception as e:
            logger.error(f"Error checking process {pid}: {e}")
            return []

        # Perform the scan
        matches = []
        try:
            timeout_sec = timeout or self.timeout
            scan_results = self.rules.match(pid=pid, timeout=timeout_sec)

            for match in scan_results:
                rule_obj = self.rule_objs.get(match.rule)
                if not rule_obj:
                    # If we don't have metadata, create a minimal rule object
                    rule_obj = YaraRule(
                        identifier=match.rule,
                        tags=match.tags,
                        meta=match.meta,
                        sources={}
                    )

                # Extract match strings
                strings = self._extract_match_strings(match)

                # Create YaraMatch object
                yara_match = YaraMatch(
                    rule=rule_obj,
                    process_id=pid,
                    process_name=process_name,
                    strings=strings,
                    scan_type="process"
                )
                matches.append(yara_match)

            if matches:
                logger.info(f"Found {len(matches)} YARA matches in process {pid} ({process_name})")

            return matches
        except yara.TimeoutError:
            logger.warning(f"YARA scan timed out for process {pid}")
            return []
        except yara.Error as e:
            logger.error(f"YARA error scanning process {pid}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error scanning process {pid}: {e}")
            return []

    async def scan_file_async(self, file_path: str, timeout: Optional[int] = None) -> List[YaraMatch]:
        """Scan a file with YARA rules asynchronously"""
        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(
            self.executor,
            lambda: self._scan_file(file_path, timeout)
        )

        # Generate events for matches
        for match in matches:
            batch = YaraMatchBatch()
            batch.add_match(match)
            await self.event_queue.put(batch.to_json())

        return matches

    async def scan_process_async(self, pid: int, timeout: Optional[int] = None) -> List[YaraMatch]:
        """Scan a process with YARA rules asynchronously"""
        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(
            self.executor,
            lambda: self._scan_process(pid, timeout)
        )

        # Generate events for matches
        for match in matches:
            batch = YaraMatchBatch()
            batch.add_match(match)
            await self.event_queue.put(batch.to_json())

        return matches

    async def scan_all_processes_async(self, timeout: Optional[int] = None) -> List[YaraMatch]:
        """Scan all running processes with YARA rules asynchronously"""
        all_matches = []
        try:
            # Get all running processes
            processes = psutil.process_iter(['pid', 'name'])
            pids = [p.info['pid'] for p in processes]

            # Scan each process concurrently
            tasks = []
            for pid in pids:
                task = asyncio.create_task(self.scan_process_async(pid, timeout))
                tasks.append(task)

            # Gather results
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, List) and result:
                    all_matches.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Error in process scan: {result}")

            return all_matches
        except Exception as e:
            logger.error(f"Error scanning all processes: {e}")
            return []

    async def start(self) -> None:
        """Start the YARA scanner"""
        if self.is_running:
            logger.warning("YARA scanner is already running")
            return

        logger.info("Starting YARA scanner...")

        # Load rules
        if not self._load_rules():
            logger.error("Failed to load YARA rules, scanner not started")
            return

        self.is_running = True
        logger.info("YARA scanner started successfully")

    async def stop(self) -> None:
        """Stop the YARA scanner"""
        if not self.is_running:
            logger.warning("YARA scanner is not running")
            return

        logger.info("Stopping YARA scanner...")

        # Cancel any running scan task
        if self.scan_task:
            self.scan_task.cancel()
            try:
                await self.scan_task
            except asyncio.CancelledError:
                pass

        # Shutdown thread pool
        self.executor.shutdown(wait=False)

        self.is_running = False
        logger.info("YARA scanner stopped")

    async def get_events(self) -> str:
        """Get the next batch of events from the queue"""
        return await self.event_queue.get()


async def main():
    """Main entry point for testing"""
    import argparse
    parser = argparse.ArgumentParser(description='YARA Scanner')
    parser.add_argument('--file', '-f', help='File to scan')
    parser.add_argument('--process', '-p', type=int, help='Process ID to scan')
    parser.add_argument('--all-processes', '-a', action='store_true', help='Scan all processes')
    parser.add_argument('--rules', '-r', help='Path to YARA rules file or directory')
    args = parser.parse_args()

    scanner = YaraScanner(rules_path=args.rules)

    # Set up signal handling
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(scanner, loop)))

    async def consumer():
        while True:
            batch = await scanner.get_events()
            print(f"Received batch: {batch}")

    await scanner.start()
    consumer_task = asyncio.create_task(consumer())

    try:
        if args.file:
            await scanner.scan_file_async(args.file)
        elif args.process:
            await scanner.scan_process_async(args.process)
        elif args.all_processes:
            await scanner.scan_all_processes_async()
        else:
            print("No scan target specified. Use --file, --process, or --all-processes")
            await scanner.stop()
            return

        # Wait a bit for any remaining events
        await asyncio.sleep(1)
    finally:
        consumer_task.cancel()
        await scanner.stop()


async def shutdown(scanner: YaraScanner, loop: asyncio.AbstractEventLoop):
    """Handle graceful shutdown"""
    logger.info("Shutting down...")
    await scanner.stop()
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
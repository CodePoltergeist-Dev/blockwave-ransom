#!/usr/bin/env python3
"""
BlockWave-Ransom - Main entry point

This is the main entry point for the BlockWave-Ransom ransomware detection
and mitigation framework. It initializes and starts the detection orchestrator.
"""

import os
import sys
import asyncio
import argparse
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("main")

# Import the detection orchestrator
from detection_orchestrator import DetectionOrchestrator


def get_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='BlockWave-Ransom - Ransomware Detection and Mitigation Framework'
    )
    parser.add_argument(
        '--config', '-c',
        type=str,
        default='config/config.yaml',
        help='Path to configuration file (default: config/config.yaml)'
    )
    parser.add_argument(
        '--log-level', '-l',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set the logging level (default: INFO)'
    )
    parser.add_argument(
        '--version', '-v',
        action='store_true',
        help='Show version information and exit'
    )
    return parser.parse_args()


async def main():
    """Main entry point"""
    args = get_args()
    
    # Set log level
    log_level = getattr(logging, args.log_level)
    logging.getLogger().setLevel(log_level)
    
    # Print version and exit if requested
    if args.version:
        from pathlib import Path
        import yaml
        
        # Get version from config file
        try:
            config_path = Path(__file__).parent / 'config/config.yaml'
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                version = config.get('app', {}).get('version', 'Unknown')
                name = config.get('app', {}).get('name', 'BlockWave-Ransom')
            
            print(f"{name} version {version}")
        except Exception as e:
            print(f"BlockWave-Ransom version unknown: {e}")
        
        sys.exit(0)
    
    # Get absolute config path
    config_path = args.config
    if not os.path.isabs(config_path):
        config_path = str(Path(__file__).parent / config_path)
    
    if not os.path.exists(config_path):
        logger.error(f"Configuration file not found: {config_path}")
        sys.exit(1)
    
    logger.info(f"Starting BlockWave-Ransom with config: {config_path}")
    
    try:
        # Initialize and start the detection orchestrator
        orchestrator = DetectionOrchestrator(config_path)
        await orchestrator.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, exiting...")
    except Exception as e:
        logger.error(f"Error running BlockWave-Ransom: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Keyboard interrupt received, exiting")
        sys.exit(0) 
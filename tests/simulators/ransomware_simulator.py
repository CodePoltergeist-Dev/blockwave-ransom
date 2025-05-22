#!/usr/bin/env python3
"""
Ransomware Simulator for BlockWave-Ransom Testing

This script simulates ransomware behavior for testing detection mechanisms.
It's designed to trigger BlockWave-Ransom detection without causing actual harm.

IMPORTANT: This is for testing purposes only and should not be run on production systems.
"""

import os
import sys
import time
import argparse
import random
import string
import logging
import concurrent.futures
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("RansomwareSimulator")

# Simulation behaviors
SIMULATION_BEHAVIORS = {
    'file_encryption': True,      # Encrypt files
    'ransom_notes': True,         # Create ransom notes
    'filename_change': True,      # Change file extensions
    'rapid_io': True,             # Perform rapid file I/O operations
    'process_injection': False,   # Simulate process injection (not implemented)
    'registry_changes': False,    # Simulate registry changes (not implemented)
    'network_activity': False,    # Simulate C2 communication (not implemented)
}

# Extensions targeted by ransomware
TARGET_EXTENSIONS = ['.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.jpg', '.png']

# Ransom note content (used for detection)
RANSOM_NOTE_CONTENT = """
!!! YOUR FILES HAVE BEEN ENCRYPTED !!!

All your important documents, photos, and files have been encrypted with 
military-grade AES-256 encryption.

To decrypt your files, you will need to pay 0.5 Bitcoin to the following address:
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

After payment, contact us at not-real-ransomware@example.com with your payment transaction ID.

DO NOT attempt to decrypt the files yourself or they will be permanently lost.
DO NOT contact law enforcement or your files will be deleted.

This is a SIMULATION and NO ACTUAL ENCRYPTION has occurred. This note is for testing purposes only.
"""

class RansomwareSimulator:
    """Simulates ransomware behavior for testing detection mechanisms."""
    
    def __init__(self, target_dir, intensity=5, cleanup=True, only_extensions=None):
        """
        Initialize the ransomware simulator.
        
        Args:
            target_dir (str): Directory to target for simulation
            intensity (int): Simulation intensity (1-10)
            cleanup (bool): Whether to clean up after simulation
            only_extensions (list): Only target specific extensions
        """
        self.target_dir = Path(target_dir)
        self.intensity = max(1, min(10, intensity))  # Clamp between 1-10
        self.cleanup = cleanup
        self.extensions = only_extensions or TARGET_EXTENSIONS
        self.affected_files = []
        self.encryption_key = self._generate_key()
        self.fernet = Fernet(self.encryption_key)
        
        if not self.target_dir.exists():
            raise FileNotFoundError(f"Target directory {target_dir} does not exist")
        
        if not self.target_dir.is_dir():
            raise NotADirectoryError(f"{target_dir} is not a directory")
    
    def _generate_key(self):
        """Generate an encryption key."""
        salt = os.urandom(16)
        password = "simulation_password".encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _scan_files(self):
        """Scan for files to target."""
        logger.info(f"Scanning {self.target_dir} for files with extensions: {', '.join(self.extensions)}")
        files = []
        for ext in self.extensions:
            files.extend(list(self.target_dir.glob(f"**/*{ext}")))
        
        # Limit files based on intensity
        max_files = 10 * self.intensity
        if len(files) > max_files:
            files = random.sample(files, max_files)
        
        return files
    
    def _simulate_encryption(self, file_path):
        """Simulate encrypting a file."""
        try:
            # We'll only encrypt the first 1KB to avoid actual damage
            original_content = file_path.read_bytes()
            
            # Only encrypt a small portion to avoid actual damage
            encrypted_content = self.fernet.encrypt(original_content[:1024])
            
            # Create a copy with .encrypted extension
            new_path = file_path.with_suffix(file_path.suffix + ".encrypted")
            
            # Write a new file with encrypted header and original content
            with open(new_path, 'wb') as f:
                f.write(encrypted_content)
                if len(original_content) > 1024:
                    f.write(original_content[1024:])
            
            self.affected_files.append((file_path, new_path))
            logger.debug(f"Simulated encryption of {file_path}")
            
            # Sleep to avoid triggering CPU-based detection too easily
            time.sleep(random.uniform(0.01, 0.1))
            
            return True
        except Exception as e:
            logger.error(f"Failed to simulate encryption on {file_path}: {e}")
            return False
    
    def _create_ransom_note(self, directory):
        """Create a ransom note in the given directory."""
        note_names = ["README_RANSOM.txt", "HOW_TO_DECRYPT.txt", "IMPORTANT_READ_ME.txt"]
        note_path = directory / random.choice(note_names)
        note_path.write_text(RANSOM_NOTE_CONTENT)
        logger.debug(f"Created ransom note at {note_path}")
        self.affected_files.append((note_path, None))
    
    def _simulate_rapid_io(self):
        """Simulate rapid file I/O operations."""
        logger.info("Simulating rapid file I/O operations")
        
        # Create temporary files with random content
        temp_dir = self.target_dir / "temp_ransomware_sim"
        temp_dir.mkdir(exist_ok=True)
        
        # Track created files for cleanup
        temp_files = []
        
        try:
            # Create multiple files rapidly
            for i in range(20 * self.intensity):
                content = ''.join(random.choice(string.ascii_letters) for _ in range(1024))
                temp_file = temp_dir / f"temp_{i}.dat"
                temp_file.write_text(content)
                temp_files.append(temp_file)
                time.sleep(0.05)  # Small delay
            
            # Read files rapidly
            for file in temp_files:
                file.read_text()
                time.sleep(0.01)
        
        except Exception as e:
            logger.error(f"Error during rapid I/O simulation: {e}")
        
        # Add to affected files for cleanup
        for file in temp_files:
            self.affected_files.append((file, None))
        
        # Add temp directory for cleanup
        self.affected_files.append((temp_dir, None))
    
    def simulate(self):
        """Run the ransomware simulation."""
        logger.info(f"Starting ransomware simulation with intensity {self.intensity}")
        
        # Scan for target files
        target_files = self._scan_files()
        logger.info(f"Found {len(target_files)} files to target")
        
        if not target_files:
            logger.warning("No suitable files found for simulation")
            return
        
        # Create ransom notes in main directory and subdirectories
        if SIMULATION_BEHAVIORS['ransom_notes']:
            self._create_ransom_note(self.target_dir)
            
            # Add notes to some subdirectories
            subdirs = set(f.parent for f in target_files)
            for subdir in random.sample(list(subdirs), min(3, len(subdirs))):
                self._create_ransom_note(subdir)
        
        # Simulate rapid file I/O if enabled
        if SIMULATION_BEHAVIORS['rapid_io']:
            self._simulate_rapid_io()
        
        # Simulate file encryption
        if SIMULATION_BEHAVIORS['file_encryption']:
            logger.info("Starting file encryption simulation")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(self._simulate_encryption, file) for file in target_files]
                
                # Wait for all encryption tasks to complete
                results = []
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())
            
            encrypted_count = sum(1 for r in results if r)
            logger.info(f"Successfully simulated encryption on {encrypted_count}/{len(target_files)} files")
        
        logger.info("Ransomware simulation completed")
    
    def cleanup_simulation(self):
        """Clean up after simulation."""
        if not self.cleanup:
            logger.info("Cleanup disabled, leaving simulated ransomware artifacts")
            return
        
        logger.info("Cleaning up ransomware simulation artifacts")
        
        # Process in reverse to handle directories last
        for original, encrypted in reversed(self.affected_files):
            try:
                if encrypted and encrypted.exists():
                    encrypted.unlink()
                
                # If original is a directory, remove it if empty
                if original.is_dir() and original.exists():
                    if not list(original.iterdir()):
                        original.rmdir()
                # If original is a file (like a ransom note) that we created, remove it
                elif original.exists() and not encrypted:
                    original.unlink()
            except Exception as e:
                logger.error(f"Error during cleanup: {e}")
        
        logger.info("Cleanup completed")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Ransomware Simulator for BlockWave-Ransom Testing")
    parser.add_argument("target_dir", help="Directory to target for simulation")
    parser.add_argument("-i", "--intensity", type=int, default=5, choices=range(1, 11),
                        help="Simulation intensity (1-10)")
    parser.add_argument("--no-cleanup", action="store_true", help="Don't clean up after simulation")
    parser.add_argument("-e", "--extensions", nargs="+", help="Only target specific extensions")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Warn users that this is a simulation
    logger.warning("=" * 80)
    logger.warning("THIS IS A RANSOMWARE SIMULATION FOR TESTING PURPOSES ONLY")
    logger.warning("No actual files will be permanently encrypted or deleted")
    logger.warning("=" * 80)
    time.sleep(2)  # Give users time to read warning
    
    simulator = RansomwareSimulator(
        args.target_dir,
        intensity=args.intensity,
        cleanup=not args.no_cleanup,
        only_extensions=args.extensions
    )
    
    try:
        simulator.simulate()
    except KeyboardInterrupt:
        logger.info("Simulation interrupted by user")
    finally:
        simulator.cleanup_simulation()


if __name__ == "__main__":
    main() 
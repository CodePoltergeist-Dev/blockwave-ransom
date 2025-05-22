"""
Fuzzing tests for YARA rules using Hypothesis.

These tests generate random file content to test the robustness
of YARA rule detection for ransomware patterns.
"""

import os
import pytest
import tempfile
import random
import string
from pathlib import Path
from hypothesis import given, settings, strategies as st

# Try to import yara
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

# Skip tests if YARA is not available
pytestmark = pytest.mark.skipif(not HAS_YARA, reason="YARA Python not installed")


@pytest.fixture(scope="module")
def yara_rules():
    """Load and compile YARA rules for testing."""
    rules_dir = Path(__file__).parent.parent / "testdata" / "yara_rules"
    rules_dir.mkdir(exist_ok=True, parents=True)
    
    # Basic ransomware detection rule
    basic_rule = rules_dir / "ransomware_basic.yar"
    if not basic_rule.exists():
        basic_rule.write_text("""
        rule RansomwareBasic {
            strings:
                $encrypted = "ENCRYPTED" nocase
                $bitcoin = "BITCOIN" nocase
                $ransom = "RANSOM" nocase
                $payment = "PAYMENT" nocase
                $locked = "FILES LOCKED" nocase
                $unlock = "UNLOCK" nocase
                $decrypt = "DECRYPT" nocase
                $extension1 = ".locked" nocase
                $extension2 = ".encrypted" nocase
                $extension3 = ".crypted" nocase
                $extension4 = ".crypt" nocase
            condition:
                2 of them
        }
        """)
    
    # Compile rules
    compiled_rules = yara.compile(filepath=str(basic_rule))
    return compiled_rules


@given(st.text(min_size=10, max_size=10000))
@settings(max_examples=100, deadline=None)
def test_random_content(yara_rules, content):
    """Test YARA rules against completely random content."""
    # Create a temporary file with the random content
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(content.encode('utf-8', errors='ignore'))
        tmp_path = tmp.name
    
    try:
        # Scan the file with YARA rules
        matches = yara_rules.match(tmp_path)
        
        # We don't assert anything specific here since this is fuzzing
        # Just make sure the scanning process doesn't crash
    finally:
        # Clean up
        os.unlink(tmp_path)


@given(
    st.lists(
        st.sampled_from([
            "YOUR FILES HAVE BEEN ENCRYPTED",
            "PAY BITCOIN TO UNLOCK",
            "SEND 0.5 BTC TO ADDRESS",
            "YOUR PERSONAL FILES ARE LOCKED",
            "PAYMENT INSTRUCTIONS",
            "YOU HAVE 72 HOURS TO PAY",
            "ALL YOUR DOCUMENTS PHOTOS DATABASES ARE ENCRYPTED",
            "DECRYPTION KEY WILL BE DESTROYED",
            "DO NOT MODIFY ENCRYPTED FILES",
            "",  # Empty string to add random content
        ]),
        min_size=1,
        max_size=10
    ),
    st.integers(min_value=0, max_value=100)
)
@settings(max_examples=100, deadline=None)
def test_ransomware_note_detection(yara_rules, ransom_lines, noise_pct):
    """Test YARA rules against content resembling ransomware notes."""
    # Add random noise between ransom lines
    content_lines = []
    for line in ransom_lines:
        content_lines.append(line)
        
        # Add noise with probability based on noise_pct
        if random.randint(0, 100) < noise_pct:
            noise = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, 
                                           k=random.randint(10, 100)))
            content_lines.append(noise)
    
    # Join lines into content
    content = '\n'.join(content_lines)
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(content.encode('utf-8', errors='ignore'))
        tmp_path = tmp.name
    
    try:
        # Scan with YARA
        matches = yara_rules.match(tmp_path)
        
        # Check if the known ransomware patterns trigger detection
        has_ransomware_patterns = any(
            pattern in content.upper() 
            for pattern in ["ENCRYPTED", "BITCOIN", "RANSOM", "LOCKED", "DECRYPT"]
        )
        
        # Log for debugging
        if has_ransomware_patterns and not matches:
            # This is a "false negative" - we have ransomware patterns but no detection
            print(f"POTENTIAL FALSE NEGATIVE: {content[:100]}...")
            print(f"Has ransomware patterns but no detection")
        
        # We don't assert anything here as false positives/negatives are expected
        # in fuzzing tests. We're testing rule robustness, not accuracy.
    finally:
        # Clean up
        os.unlink(tmp_path)


@given(
    st.integers(min_value=1, max_value=20),  # Number of files to create
    st.integers(min_value=0, max_value=100)  # Percentage with ransomware extensions
)
@settings(max_examples=50, deadline=None)
def test_file_extension_patterns(yara_rules, num_files, ransomware_ext_pct):
    """Test YARA rules against files with ransomware-like extensions."""
    # Ransomware extensions
    ransomware_extensions = [
        ".locked", ".encrypted", ".crypted", ".crypt", ".enc", ".pay",
        ".ransom", ".wallet", ".btc", ".decrypt"
    ]
    
    # Regular extensions
    regular_extensions = [
        ".txt", ".doc", ".pdf", ".jpg", ".png", ".mp3", ".mp4", ".zip", ".exe"
    ]
    
    # Create temporary directory
    temp_dir = tempfile.mkdtemp()
    temp_paths = []
    
    try:
        # Create files
        for i in range(num_files):
            if random.randint(0, 100) < ransomware_ext_pct:
                # Create file with ransomware extension
                ext = random.choice(ransomware_extensions)
                basename = ''.join(random.choices(string.ascii_lowercase, k=8))
                original_ext = random.choice(regular_extensions)
                filename = f"{basename}{original_ext}{ext}"
            else:
                # Create file with regular extension
                ext = random.choice(regular_extensions)
                basename = ''.join(random.choices(string.ascii_lowercase, k=8))
                filename = f"{basename}{ext}"
            
            # Create file with random content
            content = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
            file_path = os.path.join(temp_dir, filename)
            with open(file_path, 'w') as f:
                f.write(content)
            
            temp_paths.append(file_path)
        
        # Check each file with YARA
        for file_path in temp_paths:
            matches = yara_rules.match(file_path)
            
            # Determine if the file should be detected (has ransomware extension)
            should_detect = any(
                file_path.endswith(ext) for ext in ransomware_extensions
            )
            
            # Again, we just log issues but don't assert, as we're testing robustness
            if should_detect and not matches:
                print(f"POTENTIAL FALSE NEGATIVE: {file_path}")
            elif not should_detect and matches:
                print(f"POTENTIAL FALSE POSITIVE: {file_path}")
    
    finally:
        # Clean up
        for path in temp_paths:
            try:
                os.unlink(path)
            except:
                pass
        try:
            os.rmdir(temp_dir)
        except:
            pass 
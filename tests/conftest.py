import os
import time
import pytest
import socket
import subprocess
import docker
from pathlib import Path
import requests
import tempfile
import random
import string


@pytest.fixture(scope="session")
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield Path(tmpdirname)


@pytest.fixture(scope="session")
def docker_client():
    """Create a Docker client for container operations."""
    try:
        client = docker.from_env()
        # Check connection
        client.ping()
        return client
    except Exception as e:
        pytest.skip(f"Docker not available: {e}")


@pytest.fixture(scope="session")
def backend_service(docker_client):
    """Start the backend service in a Docker container."""
    container = docker_client.containers.run(
        "blockwave-backend:test",
        detach=True,
        ports={'8000/tcp': 8000},
        environment={
            "LOG_LEVEL": "DEBUG",
            "QUARANTINE_DIR": "/data/quarantine",
            "CONFIG_DIR": "/data/config",
            "LOG_DIR": "/var/log/blockwave"
        },
        volumes={
            'blockwave-test-config': {'bind': '/data/config', 'mode': 'rw'},
            'blockwave-test-quarantine': {'bind': '/data/quarantine', 'mode': 'rw'},
        },
        name="test-backend"
    )
    
    # Wait for service to be ready
    for _ in range(30):  # 30 seconds timeout
        try:
            response = requests.get("http://localhost:8000/health")
            if response.status_code == 200:
                break
        except requests.RequestException:
            pass
        time.sleep(1)
    else:
        container.remove(force=True)
        pytest.fail("Backend service failed to start")

    yield container
    
    # Cleanup
    container.remove(force=True)


@pytest.fixture(scope="session")
def ebpf_service(docker_client, backend_service):
    """Start the eBPF service in a Docker container with privileges."""
    container = docker_client.containers.run(
        "blockwave-ebpf:test",
        detach=True,
        privileged=True,
        ports={'8001/tcp': 8001},
        environment={
            "LOG_LEVEL": "DEBUG",
            "EBPF_DATA_DIR": "/data/ebpf",
            "LOG_DIR": "/var/log/blockwave",
            "BACKEND_URL": "http://test-backend:8000"
        },
        volumes={
            'blockwave-test-ebpf': {'bind': '/data/ebpf', 'mode': 'rw'},
            '/sys/kernel/debug': {'bind': '/sys/kernel/debug', 'mode': 'ro'},
            '/lib/modules': {'bind': '/lib/modules', 'mode': 'ro'},
            '/usr/src': {'bind': '/usr/src', 'mode': 'ro'},
        },
        cap_add=['SYS_ADMIN', 'SYS_RESOURCE', 'SYS_PTRACE'],
        name="test-ebpf"
    )
    
    # Wait for service to be ready
    for _ in range(30):  # 30 seconds timeout
        try:
            response = requests.get("http://localhost:8001/health")
            if response.status_code == 200:
                break
        except requests.RequestException:
            pass
        time.sleep(1)
    else:
        container.remove(force=True)
        pytest.fail("eBPF service failed to start")

    yield container
    
    # Cleanup
    container.remove(force=True)


@pytest.fixture(scope="function")
def test_files(temp_dir):
    """Create test files for simulation."""
    # Create a set of test files with random content
    file_paths = []
    for i in range(10):
        content = ''.join(random.choice(string.ascii_letters) for _ in range(1024))
        file_path = temp_dir / f"test_file_{i}.txt"
        file_path.write_text(content)
        file_paths.append(file_path)
    
    yield file_paths
    
    # Cleanup
    for path in file_paths:
        if path.exists():
            path.unlink()


@pytest.fixture(scope="function")
def get_free_port():
    """Get a free port for testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 0))
        return s.getsockname()[1]


@pytest.fixture
def ml_classifier_mock():
    """Mock the ML classifier for testing."""
    class MockClassifier:
        def __init__(self):
            self.calls = []
        
        def predict(self, features):
            self.calls.append(features)
            # Return random classification (0: benign, 1: malicious)
            return [random.choice([0, 1]) for _ in range(len(features))]
        
        def predict_proba(self, features):
            self.calls.append(features)
            # Return random probabilities
            return [[random.random(), random.random()] for _ in range(len(features))]
    
    return MockClassifier()


@pytest.fixture
def yara_rule_engine():
    """Setup YARA rule engine for testing."""
    try:
        import yara
        rules_dir = Path(__file__).parent / "testdata" / "yara_rules"
        # Ensure rules directory exists
        rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Create test rule
        test_rule = rules_dir / "test_rule.yar"
        test_rule.write_text("""
        rule TestRansomware {
            strings:
                $s1 = "ENCRYPTED" nocase
                $s2 = "PAY BITCOIN" nocase
                $s3 = ".locked" nocase
                $s4 = "AES-256" nocase
            condition:
                any of them
        }
        """)
        
        # Compile rules
        rules = yara.compile(filepaths={'test': str(test_rule)})
        return rules
    except ImportError:
        pytest.skip("YARA not installed") 
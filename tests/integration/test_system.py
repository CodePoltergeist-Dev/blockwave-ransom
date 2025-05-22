"""
Integration tests for the complete BlockWave-Ransom system.
Tests the interactions between backend, eBPF, and ransomware detection.
"""

import os
import time
import pytest
import requests
import json
import logging
import socket
import subprocess
from pathlib import Path
from ..simulators.ransomware_simulator import RansomwareSimulator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("integration-tests")


@pytest.fixture(scope="module")
def backend_url():
    """Get the backend URL from environment or use default."""
    return os.environ.get("BACKEND_URL", "http://localhost:8000")


@pytest.fixture(scope="module")
def ebpf_url():
    """Get the eBPF service URL from environment or use default."""
    return os.environ.get("EBPF_URL", "http://localhost:8001")


@pytest.fixture(scope="module")
def test_target_dir():
    """Get the target directory for test files."""
    target_dir = os.environ.get("TEST_TARGET_DIR", "/tmp/blockwave-test")
    
    # Create directory if it doesn't exist
    os.makedirs(target_dir, exist_ok=True)
    
    # Create some test files
    for i in range(10):
        with open(os.path.join(target_dir, f"test_file_{i}.txt"), "w") as f:
            f.write(f"Test file {i} content\n" * 10)
    
    return target_dir


@pytest.fixture(scope="module")
def websocket_client(backend_url):
    """Create a WebSocket client to receive events."""
    import websocket
    ws_url = backend_url.replace("http", "ws") + "/events/stream"
    
    ws = websocket.WebSocketApp(
        ws_url,
        on_open=lambda ws: logger.info("WebSocket connected"),
        on_error=lambda ws, error: logger.error(f"WebSocket error: {error}"),
        on_close=lambda ws, close_status_code, close_reason: logger.info("WebSocket closed")
    )
    
    # Store received messages
    ws.received_messages = []
    ws.original_on_message = ws.on_message
    
    def on_message(ws, message):
        logger.info(f"WebSocket message: {message}")
        ws.received_messages.append(message)
        if ws.original_on_message:
            ws.original_on_message(ws, message)
    
    ws.on_message = on_message
    
    # Start WebSocket connection in background
    import threading
    ws_thread = threading.Thread(target=ws.run_forever)
    ws_thread.daemon = True
    ws_thread.start()
    
    # Wait for connection
    time.sleep(2)
    
    yield ws
    
    # Cleanup
    ws.close()
    time.sleep(1)  # Allow time for closure


@pytest.fixture(scope="function")
def cleanup_events(backend_url):
    """Clear events before and after tests."""
    # Before test: Clear events
    try:
        requests.post(f"{backend_url}/admin/clear_events")
    except requests.RequestException:
        logger.warning("Failed to clear events before test")
    
    yield
    
    # After test: Clear events again
    try:
        requests.post(f"{backend_url}/admin/clear_events")
    except requests.RequestException:
        logger.warning("Failed to clear events after test")


def test_services_health(backend_url, ebpf_url):
    """Test that both services are healthy."""
    # Check backend health
    response = requests.get(f"{backend_url}/health")
    assert response.status_code == 200
    
    # Check eBPF service health
    response = requests.get(f"{ebpf_url}/health")
    assert response.status_code == 200


def test_ransomware_detection(backend_url, ebpf_url, test_target_dir, websocket_client, cleanup_events):
    """Test that the system detects simulated ransomware activity."""
    # Get initial event count
    response = requests.get(f"{backend_url}/events")
    initial_events = response.json()
    initial_count = len(initial_events)
    
    # Run ransomware simulator
    simulator = RansomwareSimulator(
        test_target_dir,
        intensity=3,  # Lower intensity for faster tests
        cleanup=True
    )
    
    try:
        simulator.simulate()
        
        # Wait for detection events
        time.sleep(10)
        
        # Get events after simulation
        response = requests.get(f"{backend_url}/events")
        new_events = response.json()
        
        # Check that new events were generated
        assert len(new_events) > initial_count, "No new events were generated"
        
        # Check for detection events in WebSocket messages
        detection_events = [msg for msg in websocket_client.received_messages 
                           if isinstance(msg, str) and "detection" in msg.lower()]
        
        assert len(detection_events) > 0, "No detection events received via WebSocket"
        
        # Check that at least one critical event was generated
        critical_events = [event for event in new_events 
                          if event.get("severity", "").upper() == "CRITICAL"]
        
        assert len(critical_events) > 0, "No critical events were generated"
        
    finally:
        # Ensure cleanup
        simulator.cleanup_simulation()


def test_quarantine_functionality(backend_url, ebpf_url, test_target_dir, cleanup_events):
    """Test quarantine functionality by simulating a detection and checking quarantine."""
    # Create a suspicious file
    suspicious_file = os.path.join(test_target_dir, "SUSPICIOUS_FILE.exe")
    with open(suspicious_file, "w") as f:
        f.write("This is a suspicious file\n" * 10)
        f.write("ENCRYPTED\n")  # Trigger YARA detection
        f.write("PAY BITCOIN\n")  # Trigger YARA detection
    
    try:
        # Trigger manual scanning
        response = requests.post(
            f"{backend_url}/admin/scan",
            json={"path": suspicious_file}
        )
        assert response.status_code == 200
        
        # Wait for scanning to complete
        time.sleep(5)
        
        # Check quarantine status
        response = requests.get(f"{backend_url}/quarantine")
        quarantine_items = response.json()
        
        # Find our file in quarantine
        quarantined = False
        for item in quarantine_items:
            if suspicious_file in item.get("originalPath", ""):
                quarantined = True
                break
        
        assert quarantined, f"File {suspicious_file} was not quarantined"
        
    finally:
        # Cleanup
        if os.path.exists(suspicious_file):
            os.unlink(suspicious_file)


def test_rule_configuration(backend_url):
    """Test rule configuration functionality."""
    # Get current rules
    response = requests.get(f"{backend_url}/rules")
    assert response.status_code == 200
    initial_rules = response.json()
    
    # Create a test rule
    test_rule = {
        "name": "Test Integration Rule",
        "description": "Rule created by integration test",
        "enabled": True,
        "severity": "medium",
        "conditions": [
            {"type": "file_pattern", "pattern": "test_integration_*.tmp"}
        ],
        "actions": ["alert", "log"]
    }
    
    # Add the rule
    response = requests.post(
        f"{backend_url}/rules",
        json=test_rule
    )
    assert response.status_code in (200, 201)
    
    # Verify rule was added
    response = requests.get(f"{backend_url}/rules")
    updated_rules = response.json()
    assert len(updated_rules) > len(initial_rules)
    
    # Find our rule and get its ID
    rule_id = None
    for rule in updated_rules:
        if rule.get("name") == test_rule["name"]:
            rule_id = rule.get("id")
            break
    
    assert rule_id, "Added rule not found"
    
    # Disable the rule
    response = requests.patch(
        f"{backend_url}/rules/{rule_id}",
        json={"enabled": False}
    )
    assert response.status_code == 200
    
    # Verify rule was disabled
    response = requests.get(f"{backend_url}/rules/{rule_id}")
    rule_data = response.json()
    assert rule_data.get("enabled") is False
    
    # Delete the rule
    response = requests.delete(f"{backend_url}/rules/{rule_id}")
    assert response.status_code in (200, 204) 
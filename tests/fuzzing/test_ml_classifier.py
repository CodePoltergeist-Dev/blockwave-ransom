"""
Fuzzing tests for the machine learning classifier used in ransomware detection.

These tests use Hypothesis to generate random input features to test
the ML classifier's robustness against unexpected inputs.
"""

import pytest
import numpy as np
import tempfile
import os
import json
from hypothesis import given, settings, strategies as st

# Check if we have the classifier module
try:
    from blockwave_ransom.ml.classifier import RansomwareClassifier
    HAS_ML_CLASSIFIER = True
except ImportError:
    HAS_ML_CLASSIFIER = False
    # Mock classifier for testing
    class RansomwareClassifier:
        def __init__(self, model_path=None):
            self.model_path = model_path
            # If model_path, load the model, otherwise use a dummy model
            if model_path and os.path.exists(model_path):
                self.model = self._load_model(model_path)
            else:
                self.model = None

        def _load_model(self, model_path):
            # Dummy model loading
            return "dummy_model"

        def predict(self, features):
            # Dummy prediction - 1 is malicious, 0 is benign
            if isinstance(features, np.ndarray):
                # Return 1 (malicious) for every 5th sample
                return np.array([1 if i % 5 == 0 else 0 for i in range(len(features))])
            return [0]  # Default benign
        
        def predict_proba(self, features):
            # Dummy probability prediction
            if isinstance(features, np.ndarray):
                result = []
                for i in range(len(features)):
                    if i % 5 == 0:
                        result.append([0.2, 0.8])  # 80% chance malicious
                    else:
                        result.append([0.9, 0.1])  # 10% chance malicious
                return np.array(result)
            return np.array([[0.9, 0.1]])  # Default 10% chance malicious


# Strategies for generating random values for each feature type
feature_strategies = {
    # File metadata features
    'file_size': st.integers(min_value=0, max_value=10_000_000),
    'entropy': st.floats(min_value=0.0, max_value=8.0),
    'has_executable_extension': st.booleans(),
    'has_suspicious_name': st.booleans(),
    
    # File operation features
    'op_count': st.integers(min_value=0, max_value=1000),
    'op_rate': st.floats(min_value=0.0, max_value=100.0),
    'write_ratio': st.floats(min_value=0.0, max_value=1.0),
    'unique_extensions': st.integers(min_value=0, max_value=50),
    
    # Process features
    'cpu_usage': st.floats(min_value=0.0, max_value=100.0),
    'memory_usage': st.integers(min_value=0, max_value=8_000_000_000),
    'thread_count': st.integers(min_value=1, max_value=100),
    'child_processes': st.integers(min_value=0, max_value=20),
    
    # Network features
    'connection_count': st.integers(min_value=0, max_value=100),
    'dns_queries': st.integers(min_value=0, max_value=50),
    'data_sent': st.integers(min_value=0, max_value=10_000_000),
    'data_received': st.integers(min_value=0, max_value=10_000_000),
}

# Skip tests if ML classifier is not available
pytestmark = pytest.mark.skipif(not HAS_ML_CLASSIFIER, reason="ML classifier not available")


@pytest.fixture(scope="module")
def classifier():
    """Create classifier instance for testing."""
    # Check if we have a test model file
    model_dir = os.path.join(tempfile.gettempdir(), "blockwave_test_models")
    os.makedirs(model_dir, exist_ok=True)
    
    model_path = os.path.join(model_dir, "test_classifier.joblib")
    
    # Create a dummy model file if it doesn't exist (for testing)
    if not os.path.exists(model_path):
        with open(model_path, 'w') as f:
            f.write("dummy_model_data")
    
    # Initialize classifier
    clf = RansomwareClassifier(model_path=model_path)
    return clf


@given(st.lists(
    st.fixed_dictionaries({
        key: strategy for key, strategy in feature_strategies.items()
    }),
    min_size=1,
    max_size=100
))
@settings(max_examples=100, deadline=None)
def test_classifier_robustness(classifier, feature_dicts):
    """Test ML classifier with randomly generated feature dictionaries."""
    # Convert dictionaries to feature array
    features = []
    for feature_dict in feature_dicts:
        # Extract features in a consistent order
        feature_array = [
            feature_dict['file_size'],
            feature_dict['entropy'],
            int(feature_dict['has_executable_extension']),
            int(feature_dict['has_suspicious_name']),
            feature_dict['op_count'],
            feature_dict['op_rate'],
            feature_dict['write_ratio'],
            feature_dict['unique_extensions'],
            feature_dict['cpu_usage'],
            feature_dict['memory_usage'],
            feature_dict['thread_count'],
            feature_dict['child_processes'],
            feature_dict['connection_count'],
            feature_dict['dns_queries'],
            feature_dict['data_sent'],
            feature_dict['data_received'],
        ]
        features.append(feature_array)
    
    # Convert to numpy array
    features_array = np.array(features, dtype=float)
    
    try:
        # Perform classification
        predictions = classifier.predict(features_array)
        
        # Make sure we get the right number of predictions
        assert len(predictions) == len(features_array)
        
        # Check that predictions are either 0 or 1
        assert all(p == 0 or p == 1 for p in predictions)
        
        # Test predict_proba
        probabilities = classifier.predict_proba(features_array)
        
        # Make sure we get the right shape for probabilities
        assert probabilities.shape == (len(features_array), 2)
        
        # Check that probabilities sum to approximately 1
        for prob in probabilities:
            assert np.isclose(np.sum(prob), 1.0, rtol=1e-5)
            
    except Exception as e:
        # Log feature data for debugging
        print(f"Error with features: {features}")
        # Include failed feature information in the assertion message
        pytest.fail(f"Classifier failed with features: {features[:2]}... - Error: {str(e)}")


# Test with feature arrays containing extreme values
@given(st.integers(min_value=1, max_value=10))  # Number of samples
@settings(max_examples=20, deadline=None)
def test_classifier_extremes(classifier, num_samples):
    """Test the classifier with extreme feature values."""
    # Create extreme values
    extreme_values = [
        np.zeros((num_samples, 16)),  # All zeros
        np.ones((num_samples, 16)),   # All ones
        np.full((num_samples, 16), -1),  # All negative
        np.full((num_samples, 16), 1e6),  # Very large values
        np.full((num_samples, 16), 1e-6),  # Very small values
        np.random.randn(num_samples, 16),  # Random normal values
    ]
    
    for values in extreme_values:
        try:
            predictions = classifier.predict(values)
            assert len(predictions) == num_samples
            
            # Try probabilities too
            probabilities = classifier.predict_proba(values)
            assert probabilities.shape == (num_samples, 2)
            
        except Exception as e:
            pytest.fail(f"Classifier failed with extreme values: {values[:2]}... - Error: {str(e)}")


# Test with invalid input shapes
@given(
    st.integers(min_value=1, max_value=10),  # num_samples
    st.integers(min_value=1, max_value=30).filter(lambda x: x != 16)  # num_features != expected
)
@settings(max_examples=20, deadline=None)
def test_classifier_invalid_shapes(classifier, num_samples, num_features):
    """Test classifier with invalid feature shapes."""
    # Create array with wrong number of features
    invalid_shape = np.random.random((num_samples, num_features))
    
    # The classifier should either:
    # 1. Handle the wrong shape gracefully (best case)
    # 2. Raise a meaningful error (acceptable)
    try:
        classifier.predict(invalid_shape)
    except Exception as e:
        # We expect an error, so this is fine
        assert "shape" in str(e).lower() or "dimension" in str(e).lower() or "feature" in str(e).lower()


@given(st.one_of(
    st.just(None),
    st.just([]),
    st.just({}),
    st.just("string_input"),
    st.just(123),
    st.lists(st.integers(), min_size=1, max_size=10)
))
@settings(max_examples=20, deadline=None)
def test_classifier_invalid_types(classifier, invalid_input):
    """Test classifier with completely invalid input types."""
    # The classifier should handle these invalid inputs gracefully or with meaningful errors
    try:
        result = classifier.predict(invalid_input)
        # If it doesn't error, it should return a reasonable result type
        assert isinstance(result, (np.ndarray, list))
    except Exception as e:
        # Error is expected, but should be meaningful
        assert "type" in str(e).lower() or "shape" in str(e).lower() or "array" in str(e).lower() 
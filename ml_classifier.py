#!/usr/bin/env python3
"""
Machine Learning Classifier Module

This module loads a pre-trained Random Forest model and provides
classification of potential ransomware based on features extracted
from file metadata and process behavior metrics.
"""

import logging
import os
import sys
import yaml
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from enum import Enum

# For model loading
try:
    import joblib
except ImportError:
    print("Error: joblib is required. Please install it first.")
    print("pip install joblib")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ml_classifier")


class MalwareClassification(Enum):
    """Classification categories for the ML classifier"""
    BENIGN = 0
    SUSPICIOUS = 1
    LIKELY_MALWARE = 2
    MALWARE = 3


@dataclass
class ClassificationResult:
    """Result of a malware classification"""
    sample_id: str
    classification: MalwareClassification
    confidence_score: float
    prediction_time: datetime = datetime.now()
    feature_importance: Dict[str, float] = None
    threshold_used: float = 0.5
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization"""
        return {
            "sample_id": self.sample_id,
            "classification": self.classification.name,
            "confidence_score": self.confidence_score,
            "prediction_time": self.prediction_time.isoformat(),
            "feature_importance": self.feature_importance,
            "threshold_used": self.threshold_used
        }


class MLClassifier:
    """
    Machine Learning Classifier for ransomware detection.
    
    This class:
    1. Loads a pre-trained Random Forest model
    2. Extracts features from file metadata and process behavior
    3. Classifies samples and returns malware likelihood scores
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize the ML classifier with configuration"""
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Model and feature configuration
        self.model = None
        self.feature_names = []
        self.model_path = self._get_model_path()
        
        # Classification thresholds
        threshold_config = self.config.get("ml_classifier", {}).get("thresholds", {})
        self.suspicious_threshold = threshold_config.get("suspicious", 0.5)
        self.likely_malware_threshold = threshold_config.get("likely_malware", 0.7)
        self.malware_threshold = threshold_config.get("malware", 0.9)
        
        # Load the model
        self._load_model()
        
        logger.info("ML Classifier initialized")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            # Add default ML classifier config if not present
            if "ml_classifier" not in config:
                config["ml_classifier"] = {
                    "model_path": "models/malwareclassifier-V2.pkl",
                    "thresholds": {
                        "suspicious": 0.5,
                        "likely_malware": 0.7, 
                        "malware": 0.9
                    },
                    "feature_extraction": {
                        "use_file_metadata": True,
                        "use_process_behavior": True,
                        "use_network_activity": False
                    },
                    "logging": {
                        "level": "INFO",
                        "file": "/var/log/blockwave/ml_classifier.log"
                    }
                }
            return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)
    
    def _setup_logging(self) -> None:
        """Configure logging based on configuration"""
        log_config = self.config.get("ml_classifier", {}).get("logging", {})
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
    
    def _get_model_path(self) -> str:
        """Get the absolute path to the model file"""
        model_path = self.config.get("ml_classifier", {}).get("model_path", "models/malwareclassifier-V2.pkl")
        
        # If path is not absolute, make it relative to the module directory
        if not os.path.isabs(model_path):
            model_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                model_path
            )
        
        return model_path
    
    def _load_model(self) -> None:
        """Load the pre-trained Random Forest model"""
        try:
            if not os.path.exists(self.model_path):
                logger.error(f"Model file not found: {self.model_path}")
                raise FileNotFoundError(f"Model file not found: {self.model_path}")
            
            # Load the model from file
            model_data = joblib.load(self.model_path)
            
            # Model can be stored directly or within a dict with metadata
            if isinstance(model_data, dict) and "model" in model_data:
                self.model = model_data["model"]
                self.feature_names = model_data.get("feature_names", [])
            else:
                self.model = model_data
            
            # Get feature names if available
            if hasattr(self.model, "feature_names_in_"):
                self.feature_names = self.model.feature_names_in_
            
            if not self.feature_names:
                logger.warning("No feature names found in model, using default feature set")
                self.feature_names = self._get_default_feature_names()
            
            logger.info(f"Model loaded successfully from {self.model_path}")
            logger.debug(f"Model features: {self.feature_names}")
        
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise
    
    def _get_default_feature_names(self) -> List[str]:
        """Get default feature names if not available in the model"""
        # These should match the features used to train the model
        return [
            # File metadata features
            "file_size_bytes", "file_extension_is_executable", "file_entropy",
            "file_has_signature", "file_creation_time_hour", "file_is_hidden",
            
            # Process behavior features
            "process_cpu_percent", "process_memory_percent", "process_open_files_count",
            "process_file_write_count", "process_file_read_count", "process_file_delete_count",
            "process_file_encrypt_count", "process_network_connections_count",
            "process_child_processes_count", "process_file_ops_per_second",
            
            # Additional features
            "file_access_pattern_score", "file_extension_change_count",
            "suspicious_api_calls_count", "file_content_entropy_increase"
        ]
    
    def extract_features_from_file_metadata(self, file_path: str) -> Dict[str, float]:
        """Extract features from file metadata"""
        features = {}
        
        try:
            file_stats = os.stat(file_path)
            
            # Basic file metadata
            features["file_size_bytes"] = file_stats.st_size
            features["file_is_hidden"] = os.path.basename(file_path).startswith(".")
            
            # File extension
            _, ext = os.path.splitext(file_path)
            executable_extensions = [".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".com"]
            features["file_extension_is_executable"] = 1.0 if ext.lower() in executable_extensions else 0.0
            
            # File times
            features["file_creation_time_hour"] = datetime.fromtimestamp(file_stats.st_ctime).hour
            
            # File signature and entropy would require more complex analysis
            # Placeholder values for demonstration
            features["file_has_signature"] = 0.0
            features["file_entropy"] = 0.5
            
            # Additional features would be added here based on more complex file analysis
            features["file_content_entropy_increase"] = 0.0
            
        except Exception as e:
            logger.error(f"Error extracting file metadata features from {file_path}: {e}")
            # Set default values for missing features
            features = {name: 0.0 for name in self.feature_names if name.startswith("file_")}
        
        return features
    
    def extract_features_from_process_behavior(self, process_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from process behavior data"""
        features = {}
        
        try:
            # Process resource usage
            features["process_cpu_percent"] = process_data.get("cpu_percent", 0.0)
            features["process_memory_percent"] = process_data.get("memory_percent", 0.0)
            
            # File operations
            features["process_open_files_count"] = len(process_data.get("open_files", []))
            features["process_file_write_count"] = process_data.get("file_write_count", 0)
            features["process_file_read_count"] = process_data.get("file_read_count", 0)
            features["process_file_delete_count"] = process_data.get("file_delete_count", 0) 
            features["process_file_encrypt_count"] = process_data.get("file_encrypt_count", 0)
            
            # Calculate file operations per second
            duration = process_data.get("duration_seconds", 1)  # Avoid division by zero
            total_ops = (features["process_file_write_count"] + 
                         features["process_file_read_count"] + 
                         features["process_file_delete_count"])
            features["process_file_ops_per_second"] = total_ops / max(duration, 1)
            
            # Process relationships
            features["process_child_processes_count"] = len(process_data.get("children", []))
            
            # Network activity
            features["process_network_connections_count"] = len(process_data.get("connections", []))
            
            # Suspicious API calls
            features["suspicious_api_calls_count"] = process_data.get("suspicious_api_calls_count", 0)
            
            # File modification patterns
            features["file_extension_change_count"] = process_data.get("extension_change_count", 0)
            features["file_access_pattern_score"] = process_data.get("file_access_pattern_score", 0.0)
            
        except Exception as e:
            logger.error(f"Error extracting process behavior features: {e}")
            # Set default values for missing features
            features = {name: 0.0 for name in self.feature_names if name.startswith("process_")}
        
        return features
    
    def extract_all_features(self, file_path: str = None, process_data: Dict[str, Any] = None) -> Dict[str, float]:
        """Extract all required features for classification"""
        all_features = {}
        
        # Extract file features if path provided and enabled in config
        if (file_path and 
            self.config.get("ml_classifier", {}).get("feature_extraction", {}).get("use_file_metadata", True)):
            file_features = self.extract_features_from_file_metadata(file_path)
            all_features.update(file_features)
        
        # Extract process features if data provided and enabled in config
        if (process_data and 
            self.config.get("ml_classifier", {}).get("feature_extraction", {}).get("use_process_behavior", True)):
            process_features = self.extract_features_from_process_behavior(process_data)
            all_features.update(process_features)
        
        # Check if we have all required features
        for feature in self.feature_names:
            if feature not in all_features:
                logger.warning(f"Missing feature: {feature}, setting to 0")
                all_features[feature] = 0.0
        
        return all_features
    
    def get_feature_importance(self, features: Dict[str, float]) -> Dict[str, float]:
        """Get feature importance for the prediction"""
        # Check if model supports feature importance
        if not hasattr(self.model, "feature_importances_"):
            return None
        
        # Create feature importance dict
        importance_dict = {}
        try:
            # Get raw importances
            importances = self.model.feature_importances_
            
            # Map importances to feature names
            for i, feature in enumerate(self.feature_names):
                if i < len(importances):
                    importance_dict[feature] = float(importances[i])
                    
            # Apply feature values to get actual contribution
            for feature, importance in importance_dict.items():
                if feature in features:
                    importance_dict[feature] = importance * features[feature]
            
            # Get top features by importance
            top_features = dict(sorted(
                importance_dict.items(), 
                key=lambda x: abs(x[1]), 
                reverse=True
            )[:10])  # Return top 10 features
            
            return top_features
            
        except Exception as e:
            logger.error(f"Error calculating feature importance: {e}")
            return None
    
    def classify(self, sample_id: str, file_path: str = None, process_data: Dict[str, Any] = None) -> ClassificationResult:
        """
        Classify a sample based on file metadata and/or process behavior
        
        Args:
            sample_id: Unique identifier for the sample
            file_path: Path to the file to analyze (optional)
            process_data: Dictionary containing process behavior data (optional)
            
        Returns:
            ClassificationResult with malware likelihood score and classification
        """
        if not self.model:
            error_msg = "Model not loaded. Cannot perform classification."
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        if not file_path and not process_data:
            error_msg = "Either file_path or process_data must be provided for classification."
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        try:
            # Extract features
            features = self.extract_all_features(file_path, process_data)
            
            # Prepare features for model input
            X = pd.DataFrame([features])
            
            # Ensure correct order of features
            if self.feature_names:
                missing_features = set(self.feature_names) - set(X.columns)
                for feature in missing_features:
                    X[feature] = 0.0
                X = X[self.feature_names]
            
            # Get prediction probability
            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba(X)
                # Assuming binary classification with malware as the positive class (index 1)
                confidence_score = float(proba[0][1]) if proba.shape[1] > 1 else float(proba[0][0])
            else:
                # Fallback to raw prediction
                confidence_score = float(self.model.predict(X)[0])
            
            # Determine classification based on thresholds
            if confidence_score >= self.malware_threshold:
                classification = MalwareClassification.MALWARE
                threshold_used = self.malware_threshold
            elif confidence_score >= self.likely_malware_threshold:
                classification = MalwareClassification.LIKELY_MALWARE
                threshold_used = self.likely_malware_threshold
            elif confidence_score >= self.suspicious_threshold:
                classification = MalwareClassification.SUSPICIOUS
                threshold_used = self.suspicious_threshold
            else:
                classification = MalwareClassification.BENIGN
                threshold_used = self.suspicious_threshold
            
            # Get feature importance
            feature_importance = self.get_feature_importance(features)
            
            # Create and return result
            result = ClassificationResult(
                sample_id=sample_id,
                classification=classification,
                confidence_score=confidence_score,
                prediction_time=datetime.now(),
                feature_importance=feature_importance,
                threshold_used=threshold_used
            )
            
            logger.info(f"Sample {sample_id} classified as {classification.name} with score {confidence_score:.4f}")
            return result
            
        except Exception as e:
            logger.error(f"Error during classification: {e}")
            raise
    
    def batch_classify(self, samples: List[Dict[str, Any]]) -> List[ClassificationResult]:
        """
        Classify multiple samples in a batch
        
        Args:
            samples: List of dictionaries with sample_id and either file_path or process_data
            
        Returns:
            List of ClassificationResults
        """
        results = []
        
        for sample in samples:
            sample_id = sample.get("sample_id", str(id(sample)))
            file_path = sample.get("file_path")
            process_data = sample.get("process_data")
            
            try:
                result = self.classify(sample_id, file_path, process_data)
                results.append(result)
            except Exception as e:
                logger.error(f"Error classifying sample {sample_id}: {e}")
                continue
        
        return results


def main():
    """Main entry point for testing the classifier"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Machine Learning Classifier for Ransomware Detection')
    parser.add_argument('--config', type=str, default='config/config.yaml', help='Path to config file')
    parser.add_argument('--file', type=str, help='Path to file to analyze')
    parser.add_argument('--pid', type=int, help='Process ID to analyze')
    args = parser.parse_args()
    
    try:
        # Initialize classifier
        classifier = MLClassifier(args.config)
        
        if args.file:
            # Classify file
            result = classifier.classify("test_file", file_path=args.file)
            print(f"Classification result: {result.classification.name}")
            print(f"Confidence score: {result.confidence_score:.4f}")
            if result.feature_importance:
                print("Top features:")
                for feature, importance in result.feature_importance.items():
                    print(f"  {feature}: {importance:.4f}")
        
        elif args.pid:
            # This would require access to process data
            print(f"Process analysis not implemented in standalone mode.")
        
        else:
            print("Please provide either --file or --pid argument.")
            sys.exit(1)
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 
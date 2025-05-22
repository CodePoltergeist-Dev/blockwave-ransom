# Machine Learning Models

This directory contains the pre-trained machine learning models used by BlockWave-Ransom.

## Model Files

- `malwareclassifier-V2.pkl`: Pre-trained Random Forest model for ransomware detection

## Model Format

The model file should be a serialized scikit-learn model or a dictionary with the following structure:

```python
{
    "model": trained_model_object,  # The actual model object (e.g., RandomForestClassifier)
    "feature_names": ["feature1", "feature2", ...],  # List of feature names
    "metadata": {  # Optional metadata
        "version": "2.0",
        "training_date": "2023-10-15",
        "accuracy": 0.98,
        "description": "Random Forest model trained on ransomware dataset"
    }
}
```

## Training a New Model

To train a new model, you can use the `train_model.py` script in the `machinelearning` directory:

```bash
python machinelearning/train_model.py --data-path /path/to/data --output models/my_new_model.pkl
```

## Using a Different Model

To use a different model, update the `model_path` in the `config/config.yaml` file:

```yaml
ml_classifier:
  model_path: "models/my_new_model.pkl"
  # Other settings...
```

## Features Used

The default model uses the following features:

### File Metadata Features
- `file_size_bytes`: Size of the file in bytes
- `file_extension_is_executable`: Whether the file has an executable extension
- `file_entropy`: Shannon entropy of the file content
- `file_has_signature`: Whether the file has a valid signature
- `file_creation_time_hour`: Hour of the day when the file was created
- `file_is_hidden`: Whether the file is hidden

### Process Behavior Features
- `process_cpu_percent`: CPU usage percentage
- `process_memory_percent`: Memory usage percentage
- `process_open_files_count`: Number of open files
- `process_file_write_count`: Number of file write operations
- `process_file_read_count`: Number of file read operations
- `process_file_delete_count`: Number of file delete operations
- `process_file_encrypt_count`: Number of potential encryption operations
- `process_network_connections_count`: Number of network connections
- `process_child_processes_count`: Number of child processes
- `process_file_ops_per_second`: Rate of file operations

### Additional Features
- `file_access_pattern_score`: Score representing suspicious file access patterns
- `file_extension_change_count`: Number of file extension changes
- `suspicious_api_calls_count`: Number of calls to potentially suspicious APIs
- `file_content_entropy_increase`: Increase in file entropy after modification 
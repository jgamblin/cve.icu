"""
Unit tests for CVE Data Processor module.
"""

import pytest
import pandas as pd
import numpy as np
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from cve_analyzer.data_processor import CVEDataProcessor


class TestCVEDataProcessor:
    """Test suite for CVEDataProcessor class."""
    
    @pytest.fixture
    def sample_cve_data(self):
        """Sample CVE data for testing."""
        return [
            {
                "cve": {
                    "id": "CVE-2023-0001",
                    "published": "2023-01-01T00:00:00.000Z",
                    "descriptions": [{"value": "Test vulnerability"}],
                    "sourceIdentifier": "test@example.com",
                    "vulnStatus": "Analyzed",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 5.9
                        }]
                    },
                    "weaknesses": [{
                        "description": [{"value": "CWE-78"}]
                    }]
                }
            },
            {
                "cve": {
                    "id": "CVE-2023-0002",
                    "published": "2023-01-02T00:00:00.000Z",
                    "descriptions": [{"value": "Another test vulnerability"}],
                    "sourceIdentifier": "test2@example.com",
                    "vulnStatus": "Rejected",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "attackVector": "LOCAL",
                                "attackComplexity": "HIGH",
                                "privilegesRequired": "HIGH",
                                "userInteraction": "REQUIRED",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "LOW",
                                "integrityImpact": "LOW",
                                "availabilityImpact": "LOW",
                                "baseScore": 2.5,
                                "baseSeverity": "LOW"
                            },
                            "exploitabilityScore": 0.8,
                            "impactScore": 1.4
                        }]
                    },
                    "weaknesses": [{
                        "description": [{"value": "CWE-79"}]
                    }]
                }
            }
        ]
    
    @pytest.fixture
    def processor(self):
        """Create a CVEDataProcessor instance."""
        return CVEDataProcessor("test.jsonl")
    
    def test_init(self):
        """Test CVEDataProcessor initialization."""
        processor = CVEDataProcessor("test_path.jsonl")
        assert processor.data_path == "test_path.jsonl"
        assert processor.raw_data == []
        assert processor.processed_data is None
    
    def test_get_nested_value_success(self, processor):
        """Test successful nested value extraction."""
        test_dict = {
            "level1": {
                "level2": {
                    "level3": "value"
                }
            }
        }
        
        result = processor.get_nested_value(test_dict, ["level1", "level2", "level3"])
        assert result == "value"
    
    def test_get_nested_value_missing_key(self, processor):
        """Test nested value extraction with missing key."""
        test_dict = {"level1": {"level2": {}}}
        
        result = processor.get_nested_value(test_dict, ["level1", "level2", "missing"])
        assert result == "Missing_Data"
    
    def test_get_nested_value_custom_default(self, processor):
        """Test nested value extraction with custom default."""
        test_dict = {}
        
        result = processor.get_nested_value(test_dict, ["missing"], default="custom_default")
        assert result == "custom_default"
    
    def test_extract_cve_features(self, processor, sample_cve_data):
        """Test CVE feature extraction."""
        cve_entry = sample_cve_data[0]
        
        features = processor.extract_cve_features(cve_entry)
        
        assert features["CVE"] == "CVE-2023-0001"
        assert features["Published"] == "2023-01-01T00:00:00.000Z"
        assert features["AttackVector"] == "NETWORK"
        assert features["BaseScore"] == 9.8
        assert features["BaseSeverity"] == "CRITICAL"
        assert features["CWE"] == "CWE-78"
        assert features["Status"] == "Analyzed"
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('glob.glob')
    @patch('json.load')
    def test_load_raw_data(self, mock_json_load, mock_glob, mock_file, processor, sample_cve_data):
        """Test loading raw CVE data from files."""
        # Setup mocks
        mock_glob.return_value = ["test.jsonl"]
        mock_json_load.return_value = sample_cve_data
        
        # Test the method
        result = processor.load_raw_data()
        
        # Assertions
        assert len(result) == 2
        assert result == sample_cve_data
        assert processor.raw_data == sample_cve_data
        mock_glob.assert_called_once_with("test.jsonl")
        mock_file.assert_called_once_with("test.jsonl", 'r', encoding='utf-8')
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('glob.glob')
    def test_load_raw_data_file_not_found(self, mock_glob, mock_file, processor):
        """Test handling of missing data files."""
        mock_glob.return_value = []
        
        result = processor.load_raw_data()
        
        assert result == []
        assert processor.raw_data == []
    
    def test_process_data(self, processor, sample_cve_data):
        """Test complete data processing pipeline."""
        # Mock the load_raw_data method
        processor.raw_data = sample_cve_data
        
        result = processor.process_data()
        
        # Check that we get a DataFrame
        assert isinstance(result, pd.DataFrame)
        
        # Check that rejected CVEs are filtered out
        assert len(result) == 1  # Only one non-rejected CVE
        assert result.iloc[0]["CVE"] == "CVE-2023-0001"
        
        # Check data types
        assert pd.api.types.is_datetime64_any_dtype(result["Published"])
        assert pd.api.types.is_numeric_dtype(result["BaseScore"])
    
    def test_process_empty_data(self, processor):
        """Test processing with no data."""
        processor.raw_data = []
        
        result = processor.process_data()
        
        assert isinstance(result, pd.DataFrame)
        assert len(result) == 0
    
    def test_filter_by_year(self, processor):
        """Test filtering data by year."""
        # Create test DataFrame
        test_data = pd.DataFrame({
            "CVE": ["CVE-2022-0001", "CVE-2023-0001", "CVE-2023-0002"],
            "Published": pd.to_datetime([
                "2022-12-31T23:59:59.000Z",
                "2023-01-01T00:00:00.000Z", 
                "2023-12-31T23:59:59.000Z"
            ])
        })
        
        result = processor.filter_by_year(test_data, 2023)
        
        assert len(result) == 2
        assert all(result["CVE"].str.contains("2023"))
    
    def test_get_statistics(self, processor):
        """Test statistics calculation."""
        # Create test DataFrame
        test_data = pd.DataFrame({
            "Published": pd.to_datetime([
                "2023-01-01T00:00:00.000Z",
                "2023-01-02T00:00:00.000Z"
            ]),
            "BaseScore": [9.8, 7.5]
        })
        
        processor.processed_data = test_data
        stats = processor.get_statistics()
        
        assert stats["total_cves"] == 2
        assert stats["unique_dates"] == 2
        assert stats["avg_cvss_score"] == 8.65
        assert "date_range" in stats
    
    def test_get_statistics_empty_data(self, processor):
        """Test statistics with empty data."""
        processor.processed_data = pd.DataFrame()
        
        stats = processor.get_statistics()
        
        assert stats == {}
    
    def test_clean_dataframe_with_missing_columns(self, processor):
        """Test cleaning DataFrame with missing expected columns."""
        # Test with minimal DataFrame
        test_df = pd.DataFrame({"CVE": ["CVE-2023-0001"]})
        
        result = processor._clean_dataframe(test_df)
        
        # Should not raise errors and return the DataFrame as-is
        assert isinstance(result, pd.DataFrame)
        assert len(result) == 1
        assert "CVE" in result.columns
    
    @pytest.mark.parametrize("base_score,expected", [
        (0, np.nan),
        (0.0, np.nan),
        (7.5, 7.5),
        ("9.8", 9.8),
        ("invalid", np.nan)
    ])
    def test_base_score_processing(self, processor, base_score, expected):
        """Test BaseScore processing with various inputs."""
        test_df = pd.DataFrame({
            "BaseScore": [base_score],
            "Status": ["Analyzed"]
        })
        
        result = processor._clean_dataframe(test_df)
        
        if pd.isna(expected):
            assert pd.isna(result.iloc[0]["BaseScore"])
        else:
            assert result.iloc[0]["BaseScore"] == expected

"""
Unit tests for CVE Visualizer module.
"""

import pytest
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for testing
import matplotlib.pyplot as plt
from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile
import os

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from cve_analyzer.visualizer import CVEVisualizer


class TestCVEVisualizer:
    """Test suite for CVEVisualizer class."""
    
    @pytest.fixture
    def temp_output_dir(self):
        """Create a temporary output directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def visualizer(self, temp_output_dir):
        """Create a CVEVisualizer instance with temporary output directory."""
        return CVEVisualizer(temp_output_dir)
    
    @pytest.fixture
    def sample_data(self):
        """Sample CVE data for visualization testing."""
        return pd.DataFrame({
            "CVE": [
                "CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003",
                "CVE-2022-0001", "CVE-2022-0002"
            ],
            "Published": pd.to_datetime([
                "2023-01-15", "2023-02-20", "2023-03-10",
                "2022-11-05", "2022-12-25"
            ]),
            "BaseScore": [9.8, 7.5, 5.2, 8.1, 6.3],
            "BaseSeverity": ["CRITICAL", "HIGH", "MEDIUM", "HIGH", "MEDIUM"],
            "AttackVector": ["NETWORK", "NETWORK", "LOCAL", "NETWORK", "LOCAL"]
        })
    
    @pytest.fixture
    def yearly_data(self):
        """Sample yearly growth data."""
        return pd.DataFrame({
            "Published": ["2022", "2023"],
            "CVEs": [2, 3],
            "Percentage Of CVEs": [40.0, 60.0],
            "Growth YOY": [0.0, 50.0]
        })
    
    def test_init(self, temp_output_dir):
        """Test CVEVisualizer initialization."""
        visualizer = CVEVisualizer(temp_output_dir)
        
        assert visualizer.output_dir == Path(temp_output_dir)
        assert visualizer.output_dir.exists()
    
    def test_init_creates_output_directory(self):
        """Test that initialization creates output directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            non_existent_path = Path(temp_dir) / "plots"
            assert not non_existent_path.exists()
            
            visualizer = CVEVisualizer(str(non_existent_path))
            assert non_existent_path.exists()
    
    def test_plot_cvss_distribution(self, visualizer, sample_data):
        """Test CVSS distribution plot generation."""
        output_path = visualizer.plot_cvss_distribution(sample_data)
        
        # Check that file was created
        assert Path(output_path).exists()
        assert Path(output_path).suffix == ".png"
        
        # Check that it's in the expected location
        expected_path = visualizer.output_dir / "cvss_distribution.png"
        assert Path(output_path) == expected_path
    
    def test_plot_cvss_distribution_custom_path(self, visualizer, sample_data, temp_output_dir):
        """Test CVSS distribution plot with custom save path."""
        custom_path = Path(temp_output_dir) / "custom_cvss.png"
        output_path = visualizer.plot_cvss_distribution(sample_data, str(custom_path))
        
        assert Path(output_path) == custom_path
        assert custom_path.exists()
    
    def test_plot_cvss_distribution_missing_column(self, visualizer):
        """Test CVSS distribution plot with missing BaseScore column."""
        invalid_data = pd.DataFrame({"CVE": ["CVE-2023-0001"]})
        
        with pytest.raises(ValueError, match="Data must contain 'BaseScore' column"):
            visualizer.plot_cvss_distribution(invalid_data)
    
    def test_plot_yearly_growth(self, visualizer, yearly_data):
        """Test yearly growth plot generation."""
        output_path = visualizer.plot_yearly_growth(yearly_data)
        
        # Check that file was created
        assert Path(output_path).exists()
        assert Path(output_path).suffix == ".png"
        
        # Check default filename
        expected_path = visualizer.output_dir / "yearly_growth.png"
        assert Path(output_path) == expected_path
    
    @patch('matplotlib.pyplot.savefig')
    @patch('matplotlib.pyplot.close')
    def test_plot_generation_calls_matplotlib(self, mock_close, mock_savefig, visualizer, sample_data):
        """Test that plotting functions properly call matplotlib."""
        visualizer.plot_cvss_distribution(sample_data)
        
        # Check that savefig was called
        mock_savefig.assert_called_once()
        
        # Check that close was called to free memory
        mock_close.assert_called_once()
    
    def test_plot_with_empty_data(self, visualizer):
        """Test plotting with empty data."""
        empty_data = pd.DataFrame({"BaseScore": []})
        
        # Should handle empty data gracefully
        output_path = visualizer.plot_cvss_distribution(empty_data)
        assert Path(output_path).exists()
    
    def test_plot_with_nan_values(self, visualizer):
        """Test plotting with NaN values in data."""
        data_with_nans = pd.DataFrame({
            "BaseScore": [9.8, np.nan, 7.5, np.nan, 5.2]
        })
        
        # Should handle NaN values gracefully
        output_path = visualizer.plot_cvss_distribution(data_with_nans)
        assert Path(output_path).exists()
    
    def test_multiple_plots_same_visualizer(self, visualizer, sample_data, yearly_data):
        """Test creating multiple plots with the same visualizer instance."""
        # Create multiple plots
        cvss_path = visualizer.plot_cvss_distribution(sample_data)
        growth_path = visualizer.plot_yearly_growth(yearly_data)
        
        # Both should exist
        assert Path(cvss_path).exists()
        assert Path(growth_path).exists()
        
        # Should be different files
        assert cvss_path != growth_path
    
    @patch('matplotlib.pyplot.figtext')
    def test_watermark_added(self, mock_figtext, visualizer, sample_data):
        """Test that watermark is added to plots."""
        visualizer.plot_cvss_distribution(sample_data)
        
        # Check that figtext (watermark) was called
        mock_figtext.assert_called()
        
        # Check that watermark contains 'cve.icu'
        calls = mock_figtext.call_args_list
        watermark_calls = [call for call in calls if 'cve.icu' in str(call)]
        assert len(watermark_calls) > 0
    
    def test_file_naming_conventions(self, visualizer, sample_data, yearly_data):
        """Test that files are named according to conventions."""
        cvss_path = visualizer.plot_cvss_distribution(sample_data)
        growth_path = visualizer.plot_yearly_growth(yearly_data)
        
        # Check naming patterns
        assert "cvss_distribution" in Path(cvss_path).name
        assert "yearly_growth" in Path(growth_path).name
        
        # Check file extensions
        assert Path(cvss_path).suffix == ".png"
        assert Path(growth_path).suffix == ".png"
    
    def test_plot_quality_settings(self, visualizer, sample_data):
        """Test that plots are saved with appropriate quality settings."""
        with patch('matplotlib.pyplot.savefig') as mock_savefig:
            visualizer.plot_cvss_distribution(sample_data)
            
            # Check that savefig was called with quality settings
            mock_savefig.assert_called_once()
            args, kwargs = mock_savefig.call_args
            
            # Should have DPI setting for quality
            assert 'dpi' in kwargs
            assert kwargs['dpi'] >= 200  # Minimum quality
            
            # Should have bbox_inches for proper layout
            assert 'bbox_inches' in kwargs
            assert kwargs['bbox_inches'] == 'tight'
    
    @pytest.mark.parametrize("score_values,expected_valid", [
        ([9.8, 7.5, 5.2], True),
        ([0, 0, 0], True),  # Should handle zeros
        ([-1, 11, 5.5], True),  # Should handle out-of-range values
        ([], False),  # Empty data
    ])
    def test_cvss_score_handling(self, visualizer, score_values, expected_valid):
        """Test handling of various CVSS score values."""
        if score_values:
            data = pd.DataFrame({"BaseScore": score_values})
            output_path = visualizer.plot_cvss_distribution(data)
            
            if expected_valid:
                assert Path(output_path).exists()
            else:
                # For empty data, should still create a plot
                assert Path(output_path).exists()
        else:
            # Test with completely empty DataFrame
            empty_data = pd.DataFrame({"BaseScore": []})
            output_path = visualizer.plot_cvss_distribution(empty_data)
            assert Path(output_path).exists()
    
    def test_concurrent_plot_generation(self, temp_output_dir, sample_data, yearly_data):
        """Test that multiple visualizer instances don't interfere."""
        # Create multiple visualizers
        viz1 = CVEVisualizer(temp_output_dir + "/viz1")
        viz2 = CVEVisualizer(temp_output_dir + "/viz2")
        
        # Generate plots simultaneously
        path1 = viz1.plot_cvss_distribution(sample_data)
        path2 = viz2.plot_yearly_growth(yearly_data)
        
        # Both should succeed
        assert Path(path1).exists()
        assert Path(path2).exists()
        
        # Should be in different directories
        assert Path(path1).parent != Path(path2).parent
    
    def test_output_directory_permissions(self, visualizer, sample_data):
        """Test that output directory has correct permissions."""
        output_path = visualizer.plot_cvss_distribution(sample_data)
        
        # File should be readable
        assert os.access(output_path, os.R_OK)
        
        # Directory should be writable
        assert os.access(visualizer.output_dir, os.W_OK)

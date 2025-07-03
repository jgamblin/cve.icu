"""
Integration tests for CVE analysis pipeline.

These tests verify that different components work together correctly.
"""

import pytest
import pandas as pd
import tempfile
import json
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from cve_analyzer import CVEDataProcessor, CVEAnalyzer, CVEVisualizer


class TestCVEAnalysisPipeline:
    """Integration tests for the complete CVE analysis pipeline."""
    
    @pytest.fixture
    def sample_nvd_data(self):
        """Sample NVD data in the expected JSON format."""
        return [
            {
                "cve": {
                    "id": "CVE-2023-0001",
                    "published": "2023-01-15T12:00:00.000Z",
                    "descriptions": [{"value": "SQL injection vulnerability"}],
                    "sourceIdentifier": "security@vendor.com",
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
                        "description": [{"value": "CWE-89"}]
                    }]
                }
            },
            {
                "cve": {
                    "id": "CVE-2023-0002",
                    "published": "2023-02-20T15:30:00.000Z",
                    "descriptions": [{"value": "Cross-site scripting vulnerability"}],
                    "sourceIdentifier": "cve@mitre.org",
                    "vulnStatus": "Analyzed",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "REQUIRED",
                                "scope": "CHANGED",
                                "confidentialityImpact": "LOW",
                                "integrityImpact": "LOW",
                                "availabilityImpact": "NONE",
                                "baseScore": 5.4,
                                "baseSeverity": "MEDIUM"
                            },
                            "exploitabilityScore": 2.3,
                            "impactScore": 2.7
                        }]
                    },
                    "weaknesses": [{
                        "description": [{"value": "CWE-79"}]
                    }]
                }
            },
            {
                "cve": {
                    "id": "CVE-2023-0003",
                    "published": "2023-03-10T09:45:00.000Z",
                    "descriptions": [{"value": "Buffer overflow vulnerability"}],
                    "sourceIdentifier": "security@company.org",
                    "vulnStatus": "Rejected"
                }
            }
        ]
    
    @pytest.fixture
    def temp_data_file(self, sample_nvd_data):
        """Create a temporary JSON file with sample CVE data."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            json.dump(sample_nvd_data, f)
            temp_file = f.name
        
        yield temp_file
        
        # Cleanup
        Path(temp_file).unlink()
    
    @pytest.fixture
    def temp_output_dir(self):
        """Create a temporary output directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    def test_full_analysis_pipeline(self, temp_data_file, temp_output_dir):
        """Test the complete analysis pipeline from data loading to visualization."""
        # Step 1: Process data
        processor = CVEDataProcessor(temp_data_file)
        data = processor.process_data()
        
        # Verify data processing
        assert isinstance(data, pd.DataFrame)
        assert len(data) == 2  # One CVE should be filtered out (rejected)
        assert "CVE" in data.columns
        assert "BaseScore" in data.columns
        
        # Step 2: Analyze data
        analyzer = CVEAnalyzer(data)
        
        # Test growth analysis
        growth_results = analyzer.analyze_growth_trends()
        assert "yearly" in growth_results
        assert isinstance(growth_results["yearly"], pd.DataFrame)
        
        # Test CVSS analysis
        cvss_results = analyzer.analyze_cvss_distribution()
        assert "statistics" in cvss_results
        assert "distribution" in cvss_results
        
        # Test attack vector analysis
        attack_results = analyzer.analyze_attack_vectors()
        assert "counts" in attack_results
        assert "percentages" in attack_results
        
        # Step 3: Generate visualizations
        visualizer = CVEVisualizer(temp_output_dir)
        
        # Test CVSS distribution plot
        cvss_plot = visualizer.plot_cvss_distribution(data)
        assert Path(cvss_plot).exists()
        
        # Test yearly growth plot
        yearly_plot = visualizer.plot_yearly_growth(growth_results["yearly"])
        assert Path(yearly_plot).exists()
        
        # Step 4: Generate summary report
        summary = analyzer.generate_summary_report()
        assert "total_cves" in summary
        assert summary["total_cves"] == 2
        assert "cvss_statistics" in summary
    
    def test_pipeline_with_empty_data(self):
        """Test pipeline behavior with empty data file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            json.dump([], f)
            temp_file = f.name
        
        try:
            # Process empty data
            processor = CVEDataProcessor(temp_file)
            data = processor.process_data()
            
            assert isinstance(data, pd.DataFrame)
            assert len(data) == 0
            
            # Analyze empty data
            analyzer = CVEAnalyzer(data)
            
            growth_results = analyzer.analyze_growth_trends()
            assert growth_results == {}
            
            cvss_results = analyzer.analyze_cvss_distribution()
            assert cvss_results == {}
            
            # Summary should handle empty data
            summary = analyzer.generate_summary_report()
            assert summary["total_cves"] == 0
            
        finally:
            Path(temp_file).unlink()
    
    def test_pipeline_with_missing_file(self, temp_output_dir):
        """Test pipeline behavior with missing data file."""
        # Use non-existent file
        processor = CVEDataProcessor("non_existent_file.jsonl")
        data = processor.process_data()
        
        # Should return empty DataFrame
        assert isinstance(data, pd.DataFrame)
        assert len(data) == 0
        
        # Analysis should handle empty data gracefully
        analyzer = CVEAnalyzer(data)
        summary = analyzer.generate_summary_report()
        assert summary["total_cves"] == 0
    
    def test_data_consistency_through_pipeline(self, temp_data_file):
        """Test that data remains consistent through the entire pipeline."""
        # Process data
        processor = CVEDataProcessor(temp_data_file)
        data = processor.process_data()
        
        # Verify initial data
        initial_cve_count = len(data)
        initial_cves = set(data["CVE"].tolist())
        
        # Analyze data
        analyzer = CVEAnalyzer(data)
        
        # Generate statistics
        stats = processor.get_statistics(data)
        summary = analyzer.generate_summary_report()
        
        # Verify consistency
        assert stats["total_cves"] == initial_cve_count
        assert summary["total_cves"] == initial_cve_count
        
        # Verify specific CVEs are preserved
        assert "CVE-2023-0001" in initial_cves
        assert "CVE-2023-0002" in initial_cves
        assert "CVE-2023-0003" not in initial_cves  # Should be filtered out
    
    def test_year_filtering_integration(self, temp_data_file):
        """Test year filtering functionality across components."""
        # Process data
        processor = CVEDataProcessor(temp_data_file)
        data = processor.process_data()
        
        # Test processor year filtering
        year_2023_data = processor.filter_by_year(data, 2023)
        assert len(year_2023_data) == 2  # All non-rejected CVEs are from 2023
        
        # Test analyzer year statistics
        analyzer = CVEAnalyzer(data)
        year_stats = analyzer.get_year_statistics(2023)
        assert year_stats["count"] == 2
        assert year_stats["year"] == 2023
    
    def test_cvss_score_processing_integration(self, temp_data_file):
        """Test CVSS score processing across components."""
        # Process data
        processor = CVEDataProcessor(temp_data_file)
        data = processor.process_data()
        
        # Verify score processing
        scores = data["BaseScore"].dropna()
        assert len(scores) == 2
        assert 9.8 in scores.values
        assert 5.4 in scores.values
        
        # Verify analysis statistics
        analyzer = CVEAnalyzer(data)
        cvss_results = analyzer.analyze_cvss_distribution()
        
        stats = cvss_results["statistics"]
        expected_avg = (9.8 + 5.4) / 2
        assert abs(stats["average"] - expected_avg) < 0.01
    
    def test_attack_vector_consistency(self, temp_data_file):
        """Test attack vector analysis consistency."""
        # Process data
        processor = CVEDataProcessor(temp_data_file)
        data = processor.process_data()
        
        # Verify attack vectors in processed data
        attack_vectors = data["AttackVector"].value_counts()
        assert attack_vectors["NETWORK"] == 2
        
        # Verify analysis results
        analyzer = CVEAnalyzer(data)
        attack_results = analyzer.analyze_attack_vectors()
        
        counts_df = attack_results["counts"]
        network_count = counts_df[counts_df["Attack Vector"] == "NETWORK"]["Count"].iloc[0]
        assert network_count == 2
    
    def test_visualization_file_creation(self, temp_data_file, temp_output_dir):
        """Test that all expected visualization files are created."""
        # Process and analyze data
        processor = CVEDataProcessor(temp_data_file)
        data = processor.process_data()
        analyzer = CVEAnalyzer(data)
        
        # Generate visualizations
        visualizer = CVEVisualizer(temp_output_dir)
        
        # Create multiple plots
        plots_created = []
        
        # CVSS distribution
        cvss_plot = visualizer.plot_cvss_distribution(data)
        plots_created.append(cvss_plot)
        
        # Yearly growth
        growth_data = analyzer.analyze_growth_trends()
        if growth_data and "yearly" in growth_data:
            yearly_plot = visualizer.plot_yearly_growth(growth_data["yearly"])
            plots_created.append(yearly_plot)
        
        # Verify all plots exist
        for plot_path in plots_created:
            assert Path(plot_path).exists()
            assert Path(plot_path).stat().st_size > 0  # File is not empty
    
    def test_memory_usage_during_pipeline(self, temp_data_file):
        """Test that memory usage is reasonable during pipeline execution."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Run complete pipeline
        processor = CVEDataProcessor(temp_data_file)
        data = processor.process_data()
        
        analyzer = CVEAnalyzer(data)
        growth_results = analyzer.analyze_growth_trends()
        cvss_results = analyzer.analyze_cvss_distribution()
        summary = analyzer.generate_summary_report()
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB for small dataset)
        assert memory_increase < 100 * 1024 * 1024
    
    @patch('matplotlib.pyplot.savefig')
    def test_visualization_error_handling(self, mock_savefig, temp_data_file, temp_output_dir):
        """Test error handling in visualization pipeline."""
        # Make savefig raise an exception
        mock_savefig.side_effect = Exception("Disk full")
        
        processor = CVEDataProcessor(temp_data_file)
        data = processor.process_data()
        
        visualizer = CVEVisualizer(temp_output_dir)
        
        # Should handle visualization errors gracefully
        with pytest.raises(Exception):
            visualizer.plot_cvss_distribution(data)

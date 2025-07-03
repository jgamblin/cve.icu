"""
Unit tests for CVE Analyzer module.
"""

import pytest
import pandas as pd
import numpy as np
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from cve_analyzer.analyzer import CVEAnalyzer


class TestCVEAnalyzer:
    """Test suite for CVEAnalyzer class."""
    
    @pytest.fixture
    def sample_data(self):
        """Sample CVE data for testing."""
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
            "AttackVector": ["NETWORK", "NETWORK", "LOCAL", "NETWORK", "LOCAL"],
            "CWE": ["CWE-78", "CWE-79", "CWE-89", "CWE-78", "CWE-79"],
            "Assigner": ["cve@mitre.org", "security@vendor.com", "cve@mitre.org", 
                        "security@vendor.com", "bugs@company.org"]
        })
    
    @pytest.fixture
    def analyzer(self, sample_data):
        """Create a CVEAnalyzer instance with sample data."""
        return CVEAnalyzer(sample_data)
    
    @pytest.fixture
    def empty_analyzer(self):
        """Create a CVEAnalyzer instance with empty data."""
        return CVEAnalyzer(pd.DataFrame())
    
    def test_init(self, sample_data):
        """Test CVEAnalyzer initialization."""
        analyzer = CVEAnalyzer(sample_data)
        assert len(analyzer.data) == 5
        assert list(analyzer.data.columns) == list(sample_data.columns)
    
    def test_analyze_growth_trends(self, analyzer):
        """Test growth trends analysis."""
        result = analyzer.analyze_growth_trends()
        
        # Check that all expected keys are present
        assert "monthly" in result
        assert "yearly" in result
        assert "weekly" in result
        assert "daily" in result
        
        # Check yearly data structure
        yearly_df = result["yearly"]
        assert isinstance(yearly_df, pd.DataFrame)
        assert "Published" in yearly_df.columns
        assert "CVEs" in yearly_df.columns
        assert "Percentage Of CVEs" in yearly_df.columns
        assert "Growth YOY" in yearly_df.columns
        
        # Check that percentages sum to 100 (approximately)
        total_percentage = yearly_df["Percentage Of CVEs"].sum()
        assert abs(total_percentage - 100.0) < 0.01
    
    def test_analyze_growth_trends_empty_data(self, empty_analyzer):
        """Test growth trends analysis with empty data."""
        result = empty_analyzer.analyze_growth_trends()
        assert result == {}
    
    def test_analyze_cvss_distribution(self, analyzer):
        """Test CVSS score distribution analysis."""
        result = analyzer.analyze_cvss_distribution()
        
        # Check structure
        assert "distribution" in result
        assert "statistics" in result
        
        # Check statistics
        stats = result["statistics"]
        assert "most_common" in stats
        assert "least_common" in stats
        assert "average" in stats
        assert "median" in stats
        assert "std" in stats
        
        # Verify calculated values
        assert abs(stats["average"] - 7.38) < 0.01  # (9.8+7.5+5.2+8.1+6.3)/5
        assert stats["median"] == 7.5
    
    def test_analyze_cvss_distribution_no_scores(self):
        """Test CVSS analysis with no BaseScore column."""
        data_no_scores = pd.DataFrame({
            "CVE": ["CVE-2023-0001"],
            "Published": pd.to_datetime(["2023-01-15"])
        })
        analyzer = CVEAnalyzer(data_no_scores)
        
        result = analyzer.analyze_cvss_distribution()
        assert result == {}
    
    def test_analyze_attack_vectors(self, analyzer):
        """Test attack vector analysis."""
        result = analyzer.analyze_attack_vectors()
        
        # Check structure
        assert "counts" in result
        assert "percentages" in result
        assert "yearly_breakdown" in result
        
        # Check counts
        counts_df = result["counts"]
        assert isinstance(counts_df, pd.DataFrame)
        assert "Attack Vector" in counts_df.columns
        assert "Count" in counts_df.columns
        
        # Verify specific counts
        network_count = counts_df[counts_df["Attack Vector"] == "NETWORK"]["Count"].iloc[0]
        local_count = counts_df[counts_df["Attack Vector"] == "LOCAL"]["Count"].iloc[0]
        assert network_count == 3
        assert local_count == 2
        
        # Check percentages
        percentages_df = result["percentages"]
        assert isinstance(percentages_df, pd.DataFrame)
        assert "Percentage" in percentages_df.columns
        
        # Percentages should sum to 100
        total_percentage = percentages_df["Percentage"].sum()
        assert abs(total_percentage - 100.0) < 0.01
    
    def test_analyze_cwe_distribution(self, analyzer):
        """Test CWE distribution analysis."""
        result = analyzer.analyze_cwe_distribution()
        
        # Check structure
        assert "top_cwes" in result
        assert "total_unique_cwes" in result
        
        # Check values
        top_cwes = result["top_cwes"]
        assert isinstance(top_cwes, pd.DataFrame)
        assert "CWE" in top_cwes.columns
        assert "counts" in top_cwes.columns
        
        # Check specific CWE counts
        cwe_78_count = top_cwes[top_cwes["CWE"] == "CWE-78"]["counts"].iloc[0]
        cwe_79_count = top_cwes[top_cwes["CWE"] == "CWE-79"]["counts"].iloc[0]
        assert cwe_78_count == 2
        assert cwe_79_count == 2
    
    def test_analyze_cna_distribution(self, analyzer):
        """Test CNA distribution analysis."""
        result = analyzer.analyze_cna_distribution()
        
        # Check structure
        assert "all_assigners" in result
        assert "top_assigners" in result
        assert "top_without_mitre" in result
        assert "mitre_cve_count" in result
        
        # Check MITRE count
        mitre_count = result["mitre_cve_count"]
        assert mitre_count == 2  # Two CVEs assigned by MITRE
        
        # Check assigners
        all_assigners = result["all_assigners"]
        assert isinstance(all_assigners, pd.DataFrame)
        assert "Assigner" in all_assigners.columns
        assert "counts" in all_assigners.columns
    
    def test_get_year_statistics(self, analyzer):
        """Test year-specific statistics."""
        # Test 2023 statistics
        stats_2023 = analyzer.get_year_statistics(2023)
        assert stats_2023["year"] == 2023
        assert stats_2023["count"] == 3
        assert "avg_cvss" in stats_2023
        assert "attack_vectors" in stats_2023
        
        # Test 2022 statistics
        stats_2022 = analyzer.get_year_statistics(2022)
        assert stats_2022["year"] == 2022
        assert stats_2022["count"] == 2
        
        # Test year with no data
        stats_2021 = analyzer.get_year_statistics(2021)
        assert stats_2021["year"] == 2021
        assert stats_2021["count"] == 0
    
    def test_generate_summary_report(self, analyzer):
        """Test summary report generation."""
        result = analyzer.generate_summary_report()
        
        # Check basic structure
        assert "total_cves" in result
        assert "date_range" in result
        assert "last_updated" in result
        
        # Check values
        assert result["total_cves"] == 5
        assert result["date_range"]["start"] == pd.Timestamp("2022-11-05")
        assert result["date_range"]["end"] == pd.Timestamp("2023-03-10")
        
        # Check that last_updated is a valid datetime string
        last_updated = datetime.fromisoformat(result["last_updated"])
        assert isinstance(last_updated, datetime)
        
        # Check optional sections
        assert "cvss_statistics" in result
        assert "recent_growth" in result
        assert "top_attack_vectors" in result
    
    def test_analyze_with_missing_columns(self):
        """Test analysis with minimal DataFrame structure."""
        minimal_data = pd.DataFrame({
            "CVE": ["CVE-2023-0001"],
            "Published": pd.to_datetime(["2023-01-15"])
        })
        analyzer = CVEAnalyzer(minimal_data)
        
        # Most analysis functions should handle missing columns gracefully
        growth_result = analyzer.analyze_growth_trends()
        assert "yearly" in growth_result
        
        cvss_result = analyzer.analyze_cvss_distribution()
        assert cvss_result == {}  # No BaseScore column
        
        attack_result = analyzer.analyze_attack_vectors()
        assert attack_result == {}  # No AttackVector column
    
    @pytest.mark.parametrize("year,expected_count", [
        (2023, 3),
        (2022, 2),
        (2021, 0),
        (2024, 0)
    ])
    def test_year_filtering(self, analyzer, year, expected_count):
        """Test year filtering with various years."""
        stats = analyzer.get_year_statistics(year)
        assert stats["count"] == expected_count
    
    def test_growth_trends_data_types(self, analyzer):
        """Test that growth trends return correct data types."""
        result = analyzer.analyze_growth_trends()
        
        # Yearly data should be a proper DataFrame
        yearly_df = result["yearly"]
        assert isinstance(yearly_df, pd.DataFrame)
        
        # Check column data types
        assert pd.api.types.is_integer_dtype(yearly_df["CVEs"])
        assert pd.api.types.is_float_dtype(yearly_df["Percentage Of CVEs"])
        assert pd.api.types.is_float_dtype(yearly_df["Growth YOY"])
    
    def test_cna_domain_processing(self, analyzer):
        """Test CNA domain processing logic."""
        result = analyzer.analyze_cna_distribution()
        
        all_assigners = result["all_assigners"]
        
        # Check that MITRE entries are processed correctly
        mitre_entries = all_assigners[all_assigners["Assigner"].str.contains("mitre.org", na=False)]
        assert len(mitre_entries) > 0
        
        # Check MITRE count
        mitre_count = result["mitre_cve_count"]
        expected_mitre = all_assigners[all_assigners["Assigner"].str.contains("mitre.org", na=False)]["counts"].sum()
        assert mitre_count == expected_mitre

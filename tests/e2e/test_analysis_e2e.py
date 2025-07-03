#!/usr/bin/env python3
"""
End-to-End tests for CVE analysis scripts.

These tests verify that the analysis scripts work correctly with real or sample data.
"""

import pytest
import subprocess
import tempfile
import json
import os
from pathlib import Path


@pytest.fixture
def sample_cve_data():
    """Create sample CVE data for testing."""
    sample_data = [
        {
            "cve": {
                "id": "CVE-2023-0001",
                "published": "2023-01-15T10:00:00.000",
                "lastModified": "2023-01-15T10:00:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Sample vulnerability description"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "NONE"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-79"
                            }
                        ]
                    }
                ],
                "sourceIdentifier": "test@example.com",
                "vulnStatus": "Analyzed"
            }
        },
        {
            "cve": {
                "id": "CVE-2023-0002",
                "published": "2023-02-20T14:30:00.000",
                "lastModified": "2023-02-20T14:30:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Another sample vulnerability"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 5.9
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-94"
                            }
                        ]
                    }
                ],
                "sourceIdentifier": "test@example.com",
                "vulnStatus": "Analyzed"
            }
        }
    ]
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        for item in sample_data:
            f.write(json.dumps(item) + '\n')
        return Path(f.name)


class TestAnalysisScripts:
    """Test analysis scripts end-to-end functionality."""
    
    def test_main_analysis_script(self, sample_cve_data):
        """Test the main analysis script with sample data."""
        scripts_dir = Path(__file__).parent.parent.parent / "scripts"
        project_root = Path(__file__).parent.parent.parent
        
        # Set PYTHONPATH to include src directory
        env = os.environ.copy()
        env["PYTHONPATH"] = str(project_root / "src")
        
        # Run the main analysis script
        result = subprocess.run([
            "python", 
            str(scripts_dir / "analyze_cves.py"),
            "--data-path", str(sample_cve_data),
            "--output-dir", str(tempfile.mkdtemp())
        ], capture_output=True, text=True, env=env)
        
        assert result.returncode == 0, f"Analysis script failed: {result.stderr}"
        assert "Analysis complete" in result.stdout or result.stderr
    
    def test_cve_growth_analysis(self, sample_cve_data):
        """Test CVE growth analysis script."""
        scripts_dir = Path(__file__).parent.parent.parent / "scripts" / "analysis"
        project_root = Path(__file__).parent.parent.parent
        output_dir = Path(tempfile.mkdtemp())
        
        # Set PYTHONPATH to include src directory
        env = os.environ.copy()
        env["PYTHONPATH"] = str(project_root / "src")
        
        # Run the growth analysis script
        result = subprocess.run([
            "python", 
            str(scripts_dir / "cve_growth_analysis.py"),
            "--input", str(sample_cve_data),
            "--output", str(output_dir)
        ], capture_output=True, text=True, env=env)
        
        # Check if script exists and runs
        if (scripts_dir / "cve_growth_analysis.py").exists():
            assert result.returncode == 0, f"Growth analysis failed: {result.stderr}"
        else:
            pytest.skip("CVE growth analysis script not yet implemented")
    
    def test_cvss_analysis(self, sample_cve_data):
        """Test CVSS analysis script."""
        scripts_dir = Path(__file__).parent.parent.parent / "scripts" / "analysis"
        project_root = Path(__file__).parent.parent.parent
        output_dir = Path(tempfile.mkdtemp())
        
        # Set PYTHONPATH to include src directory
        env = os.environ.copy()
        env["PYTHONPATH"] = str(project_root / "src")
        
        # Run the CVSS analysis script
        result = subprocess.run([
            "python", 
            str(scripts_dir / "cvss_analysis.py"),
            "--input", str(sample_cve_data),
            "--output", str(output_dir)
        ], capture_output=True, text=True, env=env)
        
        # Check if script exists and runs
        if (scripts_dir / "cvss_analysis.py").exists():
            assert result.returncode == 0, f"CVSS analysis failed: {result.stderr}"
        else:
            pytest.skip("CVSS analysis script not yet implemented")


class TestTaskRunner:
    """Test the task runner functionality."""
    
    def test_tasks_help(self):
        """Test that tasks.py shows help."""
        result = subprocess.run([
            "python", "tasks.py", "--help"
        ], cwd=Path(__file__).parent.parent.parent, capture_output=True, text=True)
        
        assert result.returncode == 0
        assert "CVE.ICU" in result.stdout or "task" in result.stdout.lower()
    
    def test_tasks_clean(self):
        """Test the clean task."""
        result = subprocess.run([
            "python", "tasks.py", "clean"
        ], cwd=Path(__file__).parent.parent.parent, capture_output=True, text=True)
        
        assert result.returncode == 0
        assert "Cleaning" in result.stdout or result.stderr
    
    def test_tasks_install(self):
        """Test the install task."""
        result = subprocess.run([
            "python", "tasks.py", "install"
        ], cwd=Path(__file__).parent.parent.parent, capture_output=True, text=True)
        
        assert result.returncode == 0
        assert "Install" in result.stdout or "install" in result.stdout.lower()
    
    def test_tasks_generate(self):
        """Test the generate task."""
        result = subprocess.run([
            "python", "tasks.py", "generate"
        ], cwd=Path(__file__).parent.parent.parent, capture_output=True, text=True)
        
        assert result.returncode == 0
        assert "Generating" in result.stdout or result.stderr


class TestFullPipeline:
    """Test the complete analysis pipeline."""
    
    def test_complete_workflow(self, sample_cve_data):
        """Test the complete workflow from data to website."""
        project_root = Path(__file__).parent.parent.parent
        
        # 1. Clean previous outputs
        result = subprocess.run([
            "python", "tasks.py", "clean"
        ], cwd=project_root, capture_output=True, text=True)
        assert result.returncode == 0
        
        # 2. Generate website
        result = subprocess.run([
            "python", "tasks.py", "generate"
        ], cwd=project_root, capture_output=True, text=True)
        assert result.returncode == 0
        
        # 3. Check that website was generated
        website_output = project_root / "website" / "output"
        assert website_output.exists()
        assert (website_output / "index.html").exists()
        assert (website_output / "static" / "css" / "main.css").exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

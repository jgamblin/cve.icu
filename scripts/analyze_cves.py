#!/usr/bin/env python3
"""
CVE Analysis Application - Main Entry Point

This script provides a command-line interface for analyzing CVE data
and generating reports and visualizations.
"""

import argparse
import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from cve_analyzer import CVEDataProcessor, CVEAnalyzer, CVEVisualizer


def setup_output_directories() -> Dict[str, Path]:
    """Create output directories for generated content."""
    base_dir = Path("output")
    directories = {
        "plots": base_dir / "plots",
        "data": base_dir / "data", 
        "reports": base_dir / "reports"
    }
    
    for dir_path in directories.values():
        dir_path.mkdir(parents=True, exist_ok=True)
    
    return directories


def process_cve_data(data_path: str = "nvd.jsonl") -> tuple:
    """Process CVE data and return processor, analyzer, and data."""
    print(f"Loading CVE data from {data_path}...")
    
    processor = CVEDataProcessor(data_path)
    data = processor.process_data()
    
    if data.empty:
        print("No CVE data found. Please ensure nvd.jsonl exists.")
        sys.exit(1)
    
    print(f"Loaded {len(data)} CVE records")
    
    analyzer = CVEAnalyzer(data)
    return processor, analyzer, data


def generate_growth_analysis(analyzer: CVEAnalyzer, visualizer: CVEVisualizer, 
                           output_dirs: Dict[str, Path]) -> Dict[str, Any]:
    """Generate CVE growth analysis and visualizations."""
    print("Generating growth analysis...")
    
    # Get growth trends
    growth_data = analyzer.analyze_growth_trends()
    
    if not growth_data:
        print("No growth data available")
        return {}
    
    # Generate yearly growth visualization
    if 'yearly' in growth_data:
        yearly_plot_path = visualizer.plot_yearly_growth(
            growth_data['yearly'], 
            str(output_dirs['plots'] / "yearly_growth.png")
        )
        print(f"Yearly growth plot saved to: {yearly_plot_path}")
    
    # Save growth data as CSV
    if 'yearly' in growth_data:
        csv_path = output_dirs['data'] / "yearly_growth.csv"
        growth_data['yearly'].to_csv(csv_path, index=False)
        print(f"Yearly growth data saved to: {csv_path}")
    
    return growth_data


def generate_cvss_analysis(analyzer: CVEAnalyzer, visualizer: CVEVisualizer,
                          data, output_dirs: Dict[str, Path]) -> Dict[str, Any]:
    """Generate CVSS score analysis and visualizations."""
    print("Generating CVSS analysis...")
    
    # Get CVSS distribution
    cvss_data = analyzer.analyze_cvss_distribution()
    
    if not cvss_data:
        print("No CVSS data available")
        return {}
    
    # Generate CVSS distribution visualization
    cvss_plot_path = visualizer.plot_cvss_distribution(
        data,
        str(output_dirs['plots'] / "cvss_distribution.png")
    )
    print(f"CVSS distribution plot saved to: {cvss_plot_path}")
    
    # Save CVSS distribution data
    if 'distribution' in cvss_data:
        csv_path = output_dirs['data'] / "cvss_distribution.csv"
        cvss_data['distribution'].to_csv(csv_path, index=False)
        print(f"CVSS distribution data saved to: {csv_path}")
    
    return cvss_data


def generate_attack_vector_analysis(analyzer: CVEAnalyzer, output_dirs: Dict[str, Path]) -> Dict[str, Any]:
    """Generate attack vector analysis."""
    print("Generating attack vector analysis...")
    
    attack_vector_data = analyzer.analyze_attack_vectors()
    
    if not attack_vector_data:
        print("No attack vector data available")
        return {}
    
    # Save attack vector data
    if 'counts' in attack_vector_data:
        csv_path = output_dirs['data'] / "attack_vectors.csv"
        attack_vector_data['counts'].to_csv(csv_path, index=False)
        print(f"Attack vector data saved to: {csv_path}")
    
    return attack_vector_data


def generate_cwe_analysis(analyzer: CVEAnalyzer, output_dirs: Dict[str, Path]) -> Dict[str, Any]:
    """Generate CWE (Common Weakness Enumeration) analysis."""
    print("Generating CWE analysis...")
    
    cwe_data = analyzer.analyze_cwe_distribution()
    
    if not cwe_data:
        print("No CWE data available")
        return {}
    
    # Save CWE data
    if 'top_cwes' in cwe_data:
        csv_path = output_dirs['data'] / "top_cwes.csv"
        cwe_data['top_cwes'].to_csv(csv_path, index=False)
        print(f"Top CWEs data saved to: {csv_path}")
    
    return cwe_data


def generate_cna_analysis(analyzer: CVEAnalyzer, output_dirs: Dict[str, Path]) -> Dict[str, Any]:
    """Generate CNA (CVE Numbering Authority) analysis."""
    print("Generating CNA analysis...")
    
    cna_data = analyzer.analyze_cna_distribution()
    
    if not cna_data:
        print("No CNA data available")
        return {}
    
    # Save CNA data
    if 'top_assigners' in cna_data:
        csv_path = output_dirs['data'] / "top_assigners.csv"
        cna_data['top_assigners'].to_csv(csv_path, index=False)
        print(f"Top assigners data saved to: {csv_path}")
    
    return cna_data


def generate_summary_report(analyzer: CVEAnalyzer, output_dirs: Dict[str, Path]) -> Dict[str, Any]:
    """Generate a comprehensive summary report."""
    print("Generating summary report...")
    
    summary = analyzer.generate_summary_report()
    
    # Save summary as JSON
    import json
    json_path = output_dirs['reports'] / "summary_report.json"
    with open(json_path, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"Summary report saved to: {json_path}")
    
    return summary


def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(description="CVE Analysis Application")
    parser.add_argument("--data-path", default="nvd.jsonl", 
                       help="Path to NVD JSON data file")
    parser.add_argument("--output-dir", default="output",
                       help="Output directory for generated files")
    parser.add_argument("--analysis", choices=['all', 'growth', 'cvss', 'attack-vectors', 'cwe', 'cna'],
                       default='all', help="Type of analysis to run")
    
    args = parser.parse_args()
    
    # Setup output directories
    output_dirs = setup_output_directories()
    
    # Process data
    processor, analyzer, data = process_cve_data(args.data_path)
    
    # Initialize visualizer
    visualizer = CVEVisualizer(str(output_dirs['plots']))
    
    # Run specified analysis
    if args.analysis in ['all', 'growth']:
        generate_growth_analysis(analyzer, visualizer, output_dirs)
    
    if args.analysis in ['all', 'cvss']:
        generate_cvss_analysis(analyzer, visualizer, data, output_dirs)
    
    if args.analysis in ['all', 'attack-vectors']:
        generate_attack_vector_analysis(analyzer, output_dirs)
    
    if args.analysis in ['all', 'cwe']:
        generate_cwe_analysis(analyzer, output_dirs)
    
    if args.analysis in ['all', 'cna']:
        generate_cna_analysis(analyzer, output_dirs)
    
    if args.analysis == 'all':
        generate_summary_report(analyzer, output_dirs)
    
    print("\\nAnalysis complete! Check the output directory for results.")


if __name__ == "__main__":
    main()

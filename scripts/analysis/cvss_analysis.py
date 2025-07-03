#!/usr/bin/env python3
"""
CVE CVSS Analysis Script

Analyzes and visualizes CVSS score distribution and trends.
This script replaces the CVECVSS.ipynb notebook functionality.
"""

import sys
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cve_analyzer import CVEDataProcessor, CVEAnalyzer, CVEVisualizer


def create_score_distribution_by_year(data: pd.DataFrame, output_path: str) -> str:
    """
    Create CVSS score distribution plot by year.
    
    Args:
        data: Processed CVE DataFrame
        output_path: Path to save the plot
        
    Returns:
        Path to saved plot
    """
    # Filter for recent years and remove missing scores
    recent_years = [2020, 2021, 2022, 2023, 2024, 2025]
    data_with_scores = data.dropna(subset=['BaseScore'])
    
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    axes = axes.flatten()
    
    for i, year in enumerate(recent_years):
        year_filter = (
            (data_with_scores['Published'] >= f'{year}-01-01') & 
            (data_with_scores['Published'] < f'{year + 1}-01-01')
        )
        year_data = data_with_scores.loc[year_filter]
        
        if not year_data.empty:
            scores = year_data['BaseScore']
            
            # Create histogram
            axes[i].hist(scores, bins=50, alpha=0.7, color='steelblue', edgecolor='black')
            axes[i].set_title(f'{year} CVSS Scores (n={len(scores)})', fontweight='bold')
            axes[i].set_xlabel('CVSS Score')
            axes[i].set_ylabel('Count')
            axes[i].grid(True, alpha=0.3)
            
            # Add statistics
            mean_score = scores.mean()
            median_score = scores.median()
            axes[i].axvline(mean_score, color='red', linestyle='--', label=f'Mean: {mean_score:.2f}')
            axes[i].axvline(median_score, color='orange', linestyle='--', label=f'Median: {median_score:.2f}')
            axes[i].legend()
        else:
            axes[i].text(0.5, 0.5, f'No data for {year}', 
                        transform=axes[i].transAxes, ha='center', va='center')
            axes[i].set_title(f'{year} CVSS Scores')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return output_path


def create_severity_distribution_plot(data: pd.DataFrame, output_path: str) -> str:
    """
    Create a pie chart showing distribution of CVSS severity levels.
    
    Args:
        data: Processed CVE DataFrame
        output_path: Path to save the plot
        
    Returns:
        Path to saved plot
    """
    # Get severity distribution
    severity_counts = data['BaseSeverity'].value_counts()
    
    # Define colors for each severity level
    colors = {
        'CRITICAL': '#8B0000',  # Dark red
        'HIGH': '#FF4500',      # Orange red
        'MEDIUM': '#FFA500',    # Orange
        'LOW': '#32CD32',       # Lime green
        'NONE': '#808080'       # Gray
    }
    
    # Create pie chart
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Get colors in the same order as the data
    chart_colors = [colors.get(severity, '#808080') for severity in severity_counts.index]
    
    pie_result = ax.pie(
        severity_counts.values.tolist(),
        labels=severity_counts.index.tolist(),
        colors=chart_colors,
        autopct='%1.1f%%',
        startangle=90,
        textprops={'fontsize': 12}
    )
    
    # Handle the pie chart result (could be 2 or 3 elements)
    if len(pie_result) == 3:
        wedges, texts, autotexts = pie_result
        # Enhance the appearance
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
    else:
        wedges, texts = pie_result
    
    ax.set_title('CVE Distribution by CVSS Severity Level', fontsize=16, fontweight='bold', pad=20)
    
    # Add a legend with counts
    legend_labels = [f'{severity}: {count:,}' for severity, count in severity_counts.items()]
    ax.legend(wedges, legend_labels, title="Severity Levels", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
    
    # Add watermark
    fig.text(0.95, 0.02, 'cve.icu', fontsize=12, color='gray', alpha=0.5, ha='right')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return output_path


def create_score_trend_plot(data: pd.DataFrame, output_path: str) -> str:
    """
    Create a line plot showing CVSS score trends over time.
    
    Args:
        data: Processed CVE DataFrame
        output_path: Path to save the plot
        
    Returns:
        Path to saved plot
    """
    # Remove missing scores and group by month
    data_with_scores = data.dropna(subset=['BaseScore'])
    data_with_scores['YearMonth'] = data_with_scores['Published'].dt.to_period('M')
    
    # Calculate monthly statistics
    monthly_stats = data_with_scores.groupby('YearMonth')['BaseScore'].agg([
        'mean', 'median', 'std', 'count'
    ]).reset_index()
    
    # Convert period to datetime for plotting
    monthly_stats['Date'] = monthly_stats['YearMonth'].dt.to_timestamp()
    
    # Create the plot
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 12), sharex=True)
    
    # Plot average scores over time
    ax1.plot(monthly_stats['Date'], monthly_stats['mean'], 
             color='steelblue', linewidth=2, label='Mean Score')
    ax1.plot(monthly_stats['Date'], monthly_stats['median'], 
             color='orange', linewidth=2, label='Median Score')
    
    ax1.set_title('CVSS Score Trends Over Time', fontsize=16, fontweight='bold')
    ax1.set_ylabel('CVSS Score')
    ax1.grid(True, alpha=0.3)
    ax1.legend()
    ax1.set_ylim(0, 10)
    
    # Plot number of CVEs per month
    ax2.bar(monthly_stats['Date'], monthly_stats['count'], 
            alpha=0.7, color='lightcoral', width=20)
    ax2.set_title('Number of CVEs with CVSS Scores by Month', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Date')
    ax2.set_ylabel('Count')
    ax2.grid(True, alpha=0.3)
    
    # Add watermark
    fig.text(0.99, 0.01, 'cve.icu', fontsize=12, color='gray', alpha=0.5, ha='right')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return output_path


def main():
    """Main function to run CVSS analysis."""
    print("Starting CVSS Analysis...")
    
    # Setup output directory
    output_dir = Path("output/cvss_analysis")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Process CVE data
    processor = CVEDataProcessor("nvd.jsonl")
    data = processor.process_data()
    
    if data.empty:
        print("No CVE data found. Please ensure nvd.jsonl exists.")
        return
    
    print(f"Loaded {len(data)} CVE records")
    
    # Initialize analyzer and visualizer
    analyzer = CVEAnalyzer(data)
    visualizer = CVEVisualizer(str(output_dir))
    
    # Generate CVSS analysis
    cvss_data = analyzer.analyze_cvss_distribution()
    
    if not cvss_data:
        print("No CVSS data available")
        return
    
    # Create visualizations
    
    # Standard CVSS distribution plot
    distribution_plot = visualizer.plot_cvss_distribution(
        data,
        str(output_dir / "cvss_distribution.png")
    )
    print(f"CVSS distribution plot saved: {distribution_plot}")
    
    # Yearly score distribution plots
    yearly_plot = create_score_distribution_by_year(
        data,
        str(output_dir / "cvss_by_year.png")
    )
    print(f"Yearly CVSS plots saved: {yearly_plot}")
    
    # Severity distribution pie chart
    severity_plot = create_severity_distribution_plot(
        data,
        str(output_dir / "severity_distribution.png")
    )
    print(f"Severity distribution plot saved: {severity_plot}")
    
    # Score trends over time
    trend_plot = create_score_trend_plot(
        data,
        str(output_dir / "cvss_trends.png")
    )
    print(f"CVSS trends plot saved: {trend_plot}")
    
    # Save CVSS analysis data
    if 'distribution' in cvss_data:
        csv_path = output_dir / "cvss_distribution_data.csv"
        cvss_data['distribution'].to_csv(csv_path, index=False)
        print(f"CVSS distribution data saved: {csv_path}")
    
    # Save statistics
    if 'statistics' in cvss_data:
        import json
        stats_path = output_dir / "cvss_statistics.json"
        with open(stats_path, 'w') as f:
            json.dump(cvss_data['statistics'], f, indent=2, default=str)
        print(f"CVSS statistics saved: {stats_path}")
    
    print("\\nCVSS Analysis Complete!")
    print(f"Results saved in: {output_dir}")


if __name__ == "__main__":
    main()

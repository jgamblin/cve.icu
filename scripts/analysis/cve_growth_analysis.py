#!/usr/bin/env python3
"""
CVE Growth Analysis Script

Analyzes and visualizes CVE publication growth trends over time.
This script replaces the CVEGrowth.ipynb notebook functionality.
"""

import sys
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cve_analyzer import CVEDataProcessor, CVEAnalyzer, CVEVisualizer


def create_monthly_comparison_plot(data: pd.DataFrame, output_path: str) -> str:
    """
    Create a monthly comparison plot showing CVE publication trends across years.
    
    Args:
        data: Processed CVE DataFrame
        output_path: Path to save the plot
        
    Returns:
        Path to saved plot
    """
    # Filter data for recent years (2020-2025)
    years_to_compare = [2020, 2021, 2022, 2023, 2024, 2025]
    monthly_data = {}
    
    for year in years_to_compare:
        year_filter = (
            (data['Published'] >= f'{year}-01-01') & 
            (data['Published'] < f'{year + 1}-01-01')
        )
        year_data = data.loc[year_filter]
        
        if not year_data.empty:
            monthly_counts = year_data['Published'].groupby(
                year_data['Published'].dt.to_period("M")
            ).agg('count')
            
            # Reset index and convert to month names
            monthly_counts = monthly_counts.reset_index()
            monthly_counts['Month'] = monthly_counts['Published'].dt.strftime('%B')
            monthly_counts = monthly_counts.rename(columns={'Published': 'Month_Period'})
            monthly_counts = monthly_counts.set_index('Month')
            monthly_data[str(year)] = monthly_counts[0]  # The count column
    
    # Create DataFrame from monthly data
    monthly_df = pd.DataFrame(monthly_data)
    monthly_df = monthly_df.reindex([
        'January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December'
    ])
    
    # Create cumulative plot
    fig, ax = plt.subplots(figsize=(16, 8))
    monthly_df.fillna(0).cumsum().plot(
        ax=ax, 
        title='Cumulative Yearly CVE Publication (NVD Data)',
        colormap='viridis',
        linewidth=2
    )
    
    ax.set_ylabel("Cumulative CVEs")
    ax.set_xlabel("Month")
    ax.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)
    ax.legend(title="Year", bbox_to_anchor=(1.05, 1), loc='upper left')
    
    # Customize x-axis
    ax.set_xticks(range(12))
    ax.set_xticklabels([
        'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
        'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
    ], rotation=45)
    
    # Add watermark
    ax.text(0.99, 0.01, 'cve.icu', transform=ax.transAxes, fontsize=12,
            color='gray', alpha=0.5, ha='right', va='bottom')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return output_path


def create_percentage_plot(yearly_data: pd.DataFrame, output_path: str) -> str:
    """
    Create a percentage distribution plot of CVEs by year.
    
    Args:
        yearly_data: DataFrame with yearly CVE statistics
        output_path: Path to save the plot
        
    Returns:
        Path to saved plot
    """
    fig, ax = plt.subplots(figsize=(16, 8))
    
    # Create bar plot
    yearly_data.plot.bar(
        x='Published', 
        y='Percentage Of CVEs',
        ax=ax,
        color='steelblue',
        title='Percentage of CVEs Published by Year',
        legend=False
    )
    
    ax.set_ylabel("Percentage")
    ax.set_xlabel("Year")
    ax.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)
    
    # Add watermark
    ax.text(0.99, 0.01, 'cve.icu', transform=ax.transAxes, fontsize=12,
            color='gray', alpha=0.5, ha='right', va='bottom')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return output_path


def main():
    """Main function to run CVE growth analysis."""
    print("Starting CVE Growth Analysis...")
    
    # Setup output directory
    output_dir = Path("output/growth_analysis")
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
    
    # Generate growth analysis
    growth_data = analyzer.analyze_growth_trends()
    
    if not growth_data:
        print("No growth data available")
        return
    
    # Create visualizations
    if 'yearly' in growth_data:
        # Standard yearly growth plot
        yearly_plot = visualizer.plot_yearly_growth(
            growth_data['yearly'],
            str(output_dir / "yearly_growth.png")
        )
        print(f"Yearly growth plot saved: {yearly_plot}")
        
        # Percentage distribution plot
        percentage_plot = create_percentage_plot(
            growth_data['yearly'],
            str(output_dir / "yearly_percentage.png")
        )
        print(f"Percentage distribution plot saved: {percentage_plot}")
        
        # Save yearly data
        csv_path = output_dir / "yearly_growth_data.csv"
        growth_data['yearly'].to_csv(csv_path, index=False)
        print(f"Yearly data saved: {csv_path}")
    
    # Monthly comparison plot
    monthly_plot = create_monthly_comparison_plot(
        data,
        str(output_dir / "monthly_comparison.png")
    )
    print(f"Monthly comparison plot saved: {monthly_plot}")
    
    # Generate summary statistics
    summary = analyzer.generate_summary_report()
    
    # Save summary
    import json
    summary_path = output_dir / "growth_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"Growth summary saved: {summary_path}")
    
    print("\\nCVE Growth Analysis Complete!")
    print(f"Results saved in: {output_dir}")


if __name__ == "__main__":
    main()

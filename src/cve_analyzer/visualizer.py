"""Visualization module for creating charts and graphs from CVE data."""

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import calplot
from matplotlib import rcParams
from typing import Dict, List, Any, Optional, Tuple
import os
from pathlib import Path


class CVEVisualizer:
    """Creates visualizations for CVE data analysis."""
    
    def __init__(self, output_dir: str = "plots"):
        """
        Initialize the visualizer.
        
        Args:
            output_dir: Directory to save generated plots
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Set default font to avoid Helvetica warning
        rcParams['font.family'] = 'DejaVu Sans'
        
        # Configure matplotlib
        plt.style.use('default')
    
    def plot_cvss_distribution(self, data: pd.DataFrame, save_path: Optional[str] = None) -> str:
        """
        Create a histogram of CVSS score distribution.
        
        Args:
            data: DataFrame with BaseScore column
            save_path: Optional custom save path
            
        Returns:
            Path to saved plot
        """
        if 'BaseScore' not in data.columns:
            raise ValueError("Data must contain 'BaseScore' column")
        
        scores = data['BaseScore'].dropna()
        
        fig, ax = plt.subplots(figsize=(16, 8))
        
        # Create histogram
        counts, bins, patches = ax.hist(scores, bins=100, color='#1f77b4', alpha=0.7, edgecolor='black')
        
        ax.set_title('CVSS Score Distribution', fontsize=16, fontweight='bold')
        ax.set_xlabel('CVSS Score', fontsize=12)
        ax.set_ylabel('Number of CVEs', fontsize=12)
        ax.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)
        
        # Add statistics annotation
        most_common_score = scores.mode().iloc[0] if not scores.mode().empty else 0
        least_common_score = scores.value_counts().idxmin() if not scores.empty else 0
        most_common_count = scores.value_counts().max() if not scores.empty else 0
        least_common_count = scores.value_counts().min() if not scores.empty else 0
        average_score = scores.mean()
        
        annotation_text = (
            f'Most Common: {most_common_score} ({most_common_count} CVEs)\\n'
            f'Least Common: {least_common_score} ({least_common_count} CVEs)\\n'
            f'Average Score: {average_score:.2f}'
        )
        
        ax.text(0.02, 0.98, annotation_text, transform=ax.transAxes, fontsize=10,
                verticalalignment='top', bbox=dict(boxstyle="round,pad=0.3", 
                edgecolor='black', facecolor='white', alpha=0.9))
        
        # Add watermark
        ax.text(0.99, 0.01, 'cve.icu', transform=ax.transAxes, fontsize=12, 
                color='gray', alpha=0.5, ha='right', va='bottom')
        
        plt.tight_layout()
        
        if save_path is None:
            save_path = str(self.output_dir / "cvss_distribution.png")
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(save_path)
    
    def plot_yearly_growth(self, yearly_data: pd.DataFrame, save_path: Optional[str] = None) -> str:
        """
        Create a bar chart of yearly CVE growth.
        
        Args:
            yearly_data: DataFrame with yearly statistics
            save_path: Optional custom save path
            
        Returns:
            Path to saved plot
        """
        fig, ax = plt.subplots(figsize=(16, 8))
        
        bars = ax.bar(yearly_data.index, yearly_data['Percentage Of CVEs'], 
                     color='#2E8B57', alpha=0.8, edgecolor='black')
        
        ax.set_title('Percentage of CVEs Published by Year', fontsize=16, fontweight='bold')
        ax.set_xlabel('Year', fontsize=12)
        ax.set_ylabel('Percentage of Total CVEs', fontsize=12)
        ax.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)
        
        # Rotate x-axis labels
        plt.xticks(rotation=45)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                   f'{height:.1f}%', ha='center', va='bottom', fontsize=9)
        
        # Add watermark
        ax.text(0.99, 0.01, 'cve.icu', transform=ax.transAxes, fontsize=12, 
                color='gray', alpha=0.5, ha='right', va='bottom')
        
        plt.tight_layout()
        
        if save_path is None:
            save_path = str(self.output_dir / "yearly_growth.png")
            
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(save_path)
    
    def plot_cumulative_growth(self, monthly_data: Dict[str, pd.Series], save_path: Optional[str] = None) -> str:
        """
        Create cumulative growth chart by month for recent years.
        
        Args:
            monthly_data: Dictionary with monthly data for different years
            save_path: Optional custom save path
            
        Returns:
            Path to saved plot
        """
        fig, ax = plt.subplots(figsize=(16, 8))
        
        colors = plt.cm.get_cmap('viridis')(np.linspace(0, 1, len(monthly_data)))
        
        for i, (year, data) in enumerate(monthly_data.items()):
            if isinstance(data, pd.Series) and not data.empty:
                months = range(len(data))
                cumulative = data.cumsum()
                ax.plot(months, cumulative, label=year, color=colors[i], 
                       linewidth=2, marker='o', markersize=4)
        
        ax.set_title('Cumulative CVE Publication by Month', fontsize=16, fontweight='bold')
        ax.set_xlabel('Month', fontsize=12)
        ax.set_ylabel('Cumulative CVEs', fontsize=12)
        ax.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)
        
        # Set month labels
        month_labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                       'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        ax.set_xticks(range(12))
        ax.set_xticklabels(month_labels)
        
        ax.legend()
        
        # Add watermark
        ax.text(0.99, 0.01, 'cve.icu', transform=ax.transAxes, fontsize=12, 
                color='gray', alpha=0.5, ha='right', va='bottom')
        
        plt.tight_layout()
        
        if save_path is None:
            save_path = str(self.output_dir / "cumulative_growth.png")
            
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(save_path)
    
    def plot_attack_vectors(self, attack_vector_data: pd.DataFrame, save_path: Optional[str] = None) -> str:
        """
        Create a horizontal bar chart of attack vectors.
        
        Args:
            attack_vector_data: DataFrame with attack vector counts
            save_path: Optional custom save path
            
        Returns:
            Path to saved plot
        """
        fig, ax = plt.subplots(figsize=(16, 8))
        
        # Sort by count for better visualization
        data_sorted = attack_vector_data.sort_values('Count', ascending=True)
        
        bars = ax.barh(data_sorted['Attack Vector'], data_sorted['Count'], 
                      color='#FF6B6B', alpha=0.8, edgecolor='black')
        
        ax.set_title('CVE Distribution by Attack Vector', fontsize=16, fontweight='bold')
        ax.set_xlabel('Number of CVEs', fontsize=12)
        ax.set_ylabel('Attack Vector', fontsize=12)
        ax.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)
        
        # Add value labels on bars
        for bar in bars:
            width = bar.get_width()
            ax.text(width + max(data_sorted['Count']) * 0.01, bar.get_y() + bar.get_height()/2,
                   f'{int(width):,}', ha='left', va='center', fontsize=10)
        
        # Add watermark
        ax.text(0.99, 0.01, 'cve.icu', transform=ax.transAxes, fontsize=12, 
                color='gray', alpha=0.5, ha='right', va='bottom')
        
        plt.tight_layout()
        
        if save_path is None:
            save_path = str(self.output_dir / "attack_vectors.png")
            
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(save_path)
    
    def plot_cwe_distribution(self, cwe_data: pd.DataFrame, save_path: Optional[str] = None) -> str:
        """
        Create a horizontal bar chart of top CWEs.
        
        Args:
            cwe_data: DataFrame with CWE counts
            save_path: Optional custom save path
            
        Returns:
            Path to saved plot
        """
        fig, ax = plt.subplots(figsize=(16, 8))
        
        # Take top 20 for readability
        top_data = cwe_data.head(20)
        
        bars = ax.barh(top_data['CWE'], top_data['counts'], 
                      color='#4ECDC4', alpha=0.8, edgecolor='black')
        
        ax.set_title('Most Common CWEs in CVE Records', fontsize=16, fontweight='bold')
        ax.set_xlabel('Number of CVEs', fontsize=12)
        ax.set_ylabel('Common Weakness Enumeration (CWE)', fontsize=12)
        ax.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)
        
        # Add value labels on bars
        for bar in bars:
            width = bar.get_width()
            ax.text(width + max(top_data['counts']) * 0.01, bar.get_y() + bar.get_height()/2,
                   f'{int(width):,}', ha='left', va='center', fontsize=10)
        
        # Add watermark
        ax.text(0.99, 0.01, 'cve.icu', transform=ax.transAxes, fontsize=12, 
                color='gray', alpha=0.5, ha='right', va='bottom')
        
        plt.tight_layout()
        
        if save_path is None:
            save_path = str(self.output_dir / "cwe_distribution.png")
            
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(save_path)
    
    def plot_cna_distribution(self, cna_data: pd.DataFrame, save_path: Optional[str] = None) -> str:
        """
        Create a horizontal bar chart of top CNAs.
        
        Args:
            cna_data: DataFrame with CNA counts
            save_path: Optional custom save path
            
        Returns:
            Path to saved plot
        """
        fig, ax = plt.subplots(figsize=(16, 8))
        
        # Take top 20 for readability
        top_data = cna_data.head(20)
        
        bars = ax.barh(top_data['Assigner'], top_data['counts'], 
                      color='#9B59B6', alpha=0.8, edgecolor='black')
        
        ax.set_title('Top 20 CVE Numbering Authorities (CNAs)', fontsize=16, fontweight='bold')
        ax.set_xlabel('Number of CVEs Assigned', fontsize=12)
        ax.set_ylabel('CNA', fontsize=12)
        ax.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)
        
        # Add value labels on bars
        for bar in bars:
            width = bar.get_width()
            ax.text(width + max(top_data['counts']) * 0.01, bar.get_y() + bar.get_height()/2,
                   f'{int(width):,}', ha='left', va='center', fontsize=10)
        
        # Add watermark
        ax.text(0.99, 0.01, 'cve.icu', transform=ax.transAxes, fontsize=12, 
                color='gray', alpha=0.5, ha='right', va='bottom')
        
        plt.tight_layout()
        
        if save_path is None:
            save_path = str(self.output_dir / "cna_distribution.png")
            
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(save_path)
    
    def plot_calendar_heatmap(self, data: pd.DataFrame, save_path: Optional[str] = None) -> str:
        """
        Create a calendar heatmap of CVE publications.
        
        Args:
            data: DataFrame with Published column
            save_path: Optional custom save path
            
        Returns:
            Path to saved plot
        """
        if 'Published' not in data.columns:
            raise ValueError("Data must contain 'Published' column")
        
        # Prepare data for calendar plot
        daily_counts = data['Published'].value_counts()
        daily_counts.index = pd.to_datetime(daily_counts.index)
        
        # Create calendar plot
        cmap = plt.get_cmap('Blues')
        vmin = 5
        vmax = 300
        
        fig, axes = calplot.calplot(
            daily_counts,
            cmap=cmap,
            vmin=vmin,
            vmax=vmax,
            colorbar=True,
            dropzero=True,
            edgecolor="grey",
            textcolor="black",
            textformat='{:.0f}',
            textfiller='',
            yearascending=False,
            figsize=(25, 20)  # Reduced size for web display
        )
        
        # Manually adjust text colors for better readability
        for ax in axes.flatten():
            for text in ax.texts:
                try:
                    value = float(text.get_text())
                    # Simple text color logic
                    if value > (vmax - vmin) / 2:
                        text.set_color('white')
                    else:
                        text.set_color('black')
                except ValueError:
                    continue
        
        if save_path is None:
            save_path = str(self.output_dir / "calendar_heatmap.png")
            
        plt.savefig(save_path, dpi=200, bbox_inches='tight')  # Lower DPI for file size
        plt.close()
        
        return str(save_path)
    
    def create_summary_dashboard(self, data: pd.DataFrame, analysis_results: Dict[str, Any]) -> Dict[str, str]:
        """
        Create a comprehensive dashboard with multiple visualizations.
        
        Args:
            data: Processed CVE DataFrame
            analysis_results: Results from CVEAnalyzer
            
        Returns:
            Dictionary mapping plot names to file paths
        """
        plot_paths = {}
        
        try:
            # CVSS Distribution
            if 'BaseScore' in data.columns:
                plot_paths['cvss_distribution'] = self.plot_cvss_distribution(data)
            
            # Yearly Growth
            if 'growth_trends' in analysis_results and 'yearly' in analysis_results['growth_trends']:
                yearly_data = analysis_results['growth_trends']['yearly']
                plot_paths['yearly_growth'] = self.plot_yearly_growth(yearly_data)
            
            # Attack Vectors
            if 'attack_vectors' in analysis_results and 'counts' in analysis_results['attack_vectors']:
                attack_data = analysis_results['attack_vectors']['counts']
                plot_paths['attack_vectors'] = self.plot_attack_vectors(attack_data)
            
            # CWE Distribution
            if 'cwe_analysis' in analysis_results and 'top_cwes' in analysis_results['cwe_analysis']:
                cwe_data = analysis_results['cwe_analysis']['top_cwes']
                if not cwe_data.empty:
                    plot_paths['cwe_distribution'] = self.plot_cwe_distribution(cwe_data)
            
            # CNA Distribution
            if 'cna_analysis' in analysis_results and 'top_without_mitre' in analysis_results['cna_analysis']:
                cna_data = analysis_results['cna_analysis']['top_without_mitre']
                if not cna_data.empty:
                    plot_paths['cna_distribution'] = self.plot_cna_distribution(cna_data)
            
            # Calendar Heatmap (optional, as it can be large)
            if len(data) < 50000:  # Only for smaller datasets
                plot_paths['calendar_heatmap'] = self.plot_calendar_heatmap(data)
                
        except Exception as e:
            print(f"Warning: Could not create some visualizations: {e}")
        
        return plot_paths

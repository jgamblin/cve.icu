"""Analysis module for CVE data insights and statistics."""

import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime


class CVEAnalyzer:
    """Provides analysis methods for processed CVE data."""
    
    def __init__(self, data: pd.DataFrame):
        """
        Initialize the analyzer with processed CVE data.
        
        Args:
            data: Processed CVE DataFrame
        """
        self.data = data
    
    def analyze_growth_trends(self) -> Dict[str, Any]:
        """
        Analyze CVE publication growth trends by different time periods.
        
        Returns:
            Dictionary containing DataFrames for monthly, yearly, weekly, and daily trends
        """
        if self.data.empty or 'Published' not in self.data.columns:
            return {}
        
        # Group by different time periods
        monthly = self.data['Published'].groupby(self.data['Published'].dt.to_period("M")).agg('count')
        yearly = self.data['Published'].groupby(self.data['Published'].dt.to_period("Y")).agg('count')
        weekly = self.data['Published'].groupby(self.data['Published'].dt.to_period("W")).agg('count')
        daily = self.data['Published'].groupby(self.data['Published'].dt.to_period("D")).agg('count')
        
        # Process yearly data with additional metrics
        yearly_df = pd.DataFrame(yearly)
        yearly_df.columns = ['Count']
        yearly_df = yearly_df.reset_index()
        yearly_df['Percentage Of CVEs'] = (yearly_df['Count'] / yearly_df['Count'].sum()) * 100
        yearly_df['Growth YOY'] = yearly_df['Count'].pct_change() * 100
        yearly_df = yearly_df.round(2)
        yearly_df = yearly_df.rename(columns={"Count": "CVEs"})
        
        return {
            'monthly': monthly,
            'yearly': yearly_df,
            'weekly': weekly,
            'daily': daily
        }
    
    def analyze_cvss_distribution(self) -> Dict[str, Any]:
        """
        Analyze CVSS score distribution and statistics.
        
        Returns:
            Dictionary with CVSS analysis results
        """
        if 'BaseScore' not in self.data.columns:
            return {}
        
        scores = self.data['BaseScore'].dropna()
        
        if scores.empty:
            return {}
        
        # Define bins for whole number grouping
        bins = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        labels = [str(i) for i in range(1, 11)]
        
        binned_scores = pd.cut(scores, bins=bins, labels=labels, right=True)
        score_counts = binned_scores.value_counts().sort_index()
        
        return {
            'distribution': score_counts.reset_index(),
            'statistics': {
                'most_common': scores.mode().iloc[0] if not scores.mode().empty else None,
                'least_common': scores.value_counts().idxmin() if not scores.empty else None,
                'most_common_count': scores.value_counts().max() if not scores.empty else 0,
                'least_common_count': scores.value_counts().min() if not scores.empty else 0,
                'average': scores.mean(),
                'median': scores.median(),
                'std': scores.std()
            }
        }
    
    def analyze_attack_vectors(self) -> Dict[str, Any]:
        """
        Analyze attack vector distribution and trends.
        
        Returns:
            Dictionary with attack vector analysis
        """
        if 'AttackVector' not in self.data.columns:
            return {}
        
        # Overall distribution
        vector_counts = self.data['AttackVector'].value_counts().reset_index()
        vector_counts.columns = ['Attack Vector', 'Count']
        
        # Percentage distribution
        vector_percentages = self.data['AttackVector'].value_counts(normalize=True).mul(100).round(2).reset_index()
        vector_percentages.columns = ['Attack Vector', 'Percentage']
        
        # Yearly breakdown
        yearly_breakdown = {}
        if 'Published' in self.data.columns:
            data_with_year = self.data.copy()
            data_with_year['Year'] = data_with_year['Published'].dt.strftime('%Y')
            
            yearly_data = data_with_year[['Year', 'AttackVector']].copy()
            yearly_counts = yearly_data.value_counts().to_frame('AttackVectorCount').reset_index()
            yearly_counts = yearly_counts.sort_values(by=['Year', 'AttackVectorCount'], ascending=[False, False])
            
            # Create pivot table
            yearly_breakdown = yearly_counts.pivot(
                index='Year', 
                columns='AttackVector', 
                values='AttackVectorCount'
            ).fillna(0).sort_index(ascending=False)
        
        return {
            'counts': vector_counts,
            'percentages': vector_percentages,
            'yearly_breakdown': yearly_breakdown
        }
    
    def analyze_cwe_distribution(self) -> Dict[str, Any]:
        """
        Analyze CWE (Common Weakness Enumeration) distribution.
        
        Returns:
            Dictionary with CWE analysis results
        """
        if 'CWE' not in self.data.columns:
            return {}
        
        # Filter out missing data and get top CWEs
        cwe_data = self.data[~self.data['CWE'].str.contains('Missing_', na=False)]
        cwe_counts = cwe_data['CWE'].value_counts().reset_index()
        cwe_counts.columns = ['CWE', 'counts']
        
        # Get top 25 CWEs with more than 100 occurrences
        top_cwes = cwe_counts[cwe_counts['counts'] > 100].head(25)
        
        return {
            'top_cwes': top_cwes,
            'total_unique_cwes': len(cwe_counts),
            'cwes_with_significant_count': len(cwe_counts[cwe_counts['counts'] > 100])
        }
    
    def analyze_cna_distribution(self) -> Dict[str, Any]:
        """
        Analyze CNA (CVE Numbering Authority) distribution.
        
        Returns:
            Dictionary with CNA analysis results
        """
        if 'Assigner' not in self.data.columns:
            return {}
        
        data_copy = self.data.copy()
        
        # Replace specific assigner ID with email
        data_copy['Assigner'].replace('416baaa9-dc9f-4396-8d5f-8c081fb06d67', 'cve@kernel.org', inplace=True)
        
        # Extract domain names and check for uniqueness
        data_copy['Domain'] = data_copy['Assigner'].apply(lambda x: x.split('@')[-1] if isinstance(x, str) else x)
        
        # Modify Assigner column based on domain uniqueness
        unique_domains = data_copy.groupby('Domain')['Assigner'].nunique()
        data_copy['ProcessedAssigner'] = data_copy.apply(
            lambda x: x['Domain'] if unique_domains.get(x['Domain'], 0) == 1 
            else f"{x['Domain']} ({x['Assigner'].split('@')[0]})" if isinstance(x['Assigner'], str) and '@' in x['Assigner']
            else x['Assigner'], 
            axis=1
        )
        
        # Calculate frequency of assigners
        assigner_frequency = data_copy['ProcessedAssigner'].value_counts().reset_index()
        assigner_frequency.columns = ['Assigner', 'counts']
        
        # Get top assigners (excluding and including MITRE)
        top_assigners = assigner_frequency[assigner_frequency['counts'] > 100].head(50)
        
        # Calculate MITRE CVEs
        mitre_cves = assigner_frequency[
            assigner_frequency['Assigner'].str.contains('mitre.org', na=False)
        ]['counts'].sum()
        
        # Top assigners without MITRE
        top_without_mitre = assigner_frequency[
            ~assigner_frequency['Assigner'].str.contains('mitre.org', na=False)
        ]
        top_without_mitre = top_without_mitre[top_without_mitre['counts'] > 100].head(20)
        
        return {
            'all_assigners': assigner_frequency,
            'top_assigners': top_assigners,
            'top_without_mitre': top_without_mitre,
            'mitre_cve_count': mitre_cves
        }
    
    def analyze_cpe_data(self) -> Dict[str, Any]:
        """
        Analyze CPE (Common Platform Enumeration) data if available.
        
        Returns:
            Dictionary with CPE analysis results
        """
        # Note: CPE data requires special processing from configurations
        # This is a placeholder for the CPE analysis functionality
        return {
            'note': 'CPE analysis requires separate processing from CVE configurations'
        }
    
    def get_year_statistics(self, year: int) -> Dict[str, Any]:
        """
        Get statistics for a specific year.
        
        Args:
            year: Target year for analysis
            
        Returns:
            Dictionary with year-specific statistics
        """
        if 'Published' not in self.data.columns:
            return {}
        
        year_filter = (
            (self.data['Published'] >= f'{year}-01-01') & 
            (self.data['Published'] < f'{year + 1}-01-01')
        )
        year_data = self.data.loc[year_filter]
        
        if year_data.empty:
            return {'year': year, 'count': 0}
        
        stats = {
            'year': year,
            'count': len(year_data),
            'avg_cvss': year_data['BaseScore'].mean() if 'BaseScore' in year_data.columns else None
        }
        
        # Add attack vector breakdown for the year
        if 'AttackVector' in year_data.columns:
            stats['attack_vectors'] = year_data['AttackVector'].value_counts().to_dict()
        
        return stats
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive summary report of the CVE data.
        
        Returns:
            Dictionary with summary statistics and insights
        """
        total_cves = len(self.data)
        
        report = {
            'total_cves': total_cves,
            'date_range': {
                'start': self.data['Published'].min() if 'Published' in self.data.columns else None,
                'end': self.data['Published'].max() if 'Published' in self.data.columns else None
            },
            'last_updated': datetime.now().isoformat()
        }
        
        # Add CVSS statistics
        if 'BaseScore' in self.data.columns:
            cvss_stats = self.analyze_cvss_distribution()
            if cvss_stats:
                report['cvss_statistics'] = cvss_stats['statistics']
        
        # Add growth trends
        growth = self.analyze_growth_trends()
        if growth and 'yearly' in growth:
            recent_years = growth['yearly'].tail(5)
            report['recent_growth'] = recent_years.to_dict('records')
        
        # Add top attack vectors
        attack_vectors = self.analyze_attack_vectors()
        if attack_vectors and 'counts' in attack_vectors:
            report['top_attack_vectors'] = attack_vectors['counts'].head(5).to_dict('records')
        
        return report

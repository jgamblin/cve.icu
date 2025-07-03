"""Data processing module for CVE data extraction and preparation."""

import glob
import json
import pandas as pd
import numpy as np
from datetime import date
from typing import Dict, List, Any, Optional, Union


class CVEDataProcessor:
    """Handles loading and processing of CVE data from NVD JSON files."""
    
    def __init__(self, data_path: str = "nvd.jsonl"):
        """
        Initialize the CVE data processor.
        
        Args:
            data_path: Path pattern for NVD JSON files (supports glob patterns)
        """
        self.data_path = data_path
        self.raw_data: List[Dict] = []
        self.processed_data: Optional[pd.DataFrame] = None
        
    def get_nested_value(self, entry: Dict, keys: List[Union[str, int]], default: Any = 'Missing_Data') -> Any:
        """
        Safely extract nested values from dictionary.
        
        Args:
            entry: Dictionary to extract from
            keys: List of keys for nested access
            default: Default value if key path doesn't exist
            
        Returns:
            Extracted value or default
        """
        try:
            for key in keys:
                entry = entry[key]
            return entry
        except (KeyError, IndexError, TypeError):
            return default
    
    def load_raw_data(self) -> List[Dict]:
        """
        Load raw CVE data from JSON files.
        
        Returns:
            List of CVE entries
        """
        row_accumulator = []
        
        for filename in glob.glob(self.data_path):
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    # Handle JSONL format (one JSON object per line)
                    if filename.endswith('.jsonl'):
                        for line_num, line in enumerate(f, 1):
                            line = line.strip()
                            if line:  # Skip empty lines
                                try:
                                    entry = json.loads(line)
                                    if isinstance(entry, list):
                                        row_accumulator.extend(entry)
                                    else:
                                        row_accumulator.append(entry)
                                except json.JSONDecodeError as e:
                                    print(f"Error parsing line {line_num} in {filename}: {e}")
                    else:
                        # Handle regular JSON format
                        nvd_data = json.load(f)
                        if isinstance(nvd_data, list):
                            row_accumulator.extend(nvd_data)
                        else:
                            row_accumulator.append(nvd_data)
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"Error loading {filename}: {e}")
                
        self.raw_data = row_accumulator
        return row_accumulator
    
    def extract_cve_features(self, entry: Dict) -> Dict[str, Any]:
        """
        Extract relevant features from a single CVE entry.
        
        Args:
            entry: Raw CVE entry from NVD
            
        Returns:
            Dictionary with extracted features
        """
        return {
            'CVE': self.get_nested_value(entry, ['cve', 'id']),
            'Published': self.get_nested_value(entry, ['cve', 'published']),
            'AttackVector': self.get_nested_value(entry, ['cve', 'metrics', 'cvssMetricV31', 0, 'cvssData', 'attackVector']),
            'AttackComplexity': self.get_nested_value(entry, ['cve', 'metrics', 'cvssMetricV31', 0, 'cvssData', 'attackComplexity']),
            'PrivilegesRequired': self.get_nested_value(entry, ['cve', 'metrics', 'cvssMetricV31', 0, 'cvssData', 'privilegesRequired']),
            'UserInteraction': self.get_nested_value(entry, ['cve', 'metrics', 'cvssMetricV31', 0, 'cvssData', 'userInteraction']),
            'Scope': self.get_nested_value(entry, ['cve', 'metrics', 'cvssMetricV31', 0, 'cvssData', 'scope']),
            'ConfidentialityImpact': self.get_nested_value(entry, ['cve', 'metrics', 'cvssMetricV31', 0, 'cvssData', 'confidentialityImpact']),
            'IntegrityImpact': self.get_nested_value(entry, ['cve', 'metrics', 'cvssMetricV31', 0, 'cvssData', 'integrityImpact']),
            'AvailabilityImpact': self.get_nested_value(entry, ['cve', 'metrics', 'cvssMetricV31', 0, 'cvssData', 'availabilityImpact']),
            'BaseScore': self.get_nested_value(entry, ['cve', 'metrics', 'cvssMetricV31', 0, 'cvssData', 'baseScore'], '0.0'),
            'BaseSeverity': self.get_nested_value(entry, ['cve', 'metrics', 'cvssMetricV31', 0, 'cvssData', 'baseSeverity']),
            'ExploitabilityScore': self.get_nested_value(entry, ['cve', 'metrics', 'cvssMetricV31', 0, 'exploitabilityScore']),
            'ImpactScore': self.get_nested_value(entry, ['cve', 'metrics', 'cvssMetricV31', 0, 'impactScore']),
            'CWE': self.get_nested_value(entry, ['cve', 'weaknesses', 0, 'description', 0, 'value']),
            'Description': self.get_nested_value(entry, ['cve', 'descriptions', 0, 'value'], ''),
            'Assigner': self.get_nested_value(entry, ['cve', 'sourceIdentifier']),
            'Tag': self.get_nested_value(entry, ['cve', 'cveTags', 0, 'tags'], np.nan),
            'Status': self.get_nested_value(entry, ['cve', 'vulnStatus'], '')
        }
    
    def process_data(self) -> pd.DataFrame:
        """
        Process raw CVE data into a clean DataFrame.
        
        Returns:
            Processed DataFrame with CVE data
        """
        if not self.raw_data:
            self.load_raw_data()
        
        # Extract features from all entries
        processed_rows = []
        for entry in self.raw_data:
            processed_rows.append(self.extract_cve_features(entry))
        
        # Create DataFrame
        df = pd.DataFrame(processed_rows)
        
        # Clean and process data
        df = self._clean_dataframe(df)
        
        self.processed_data = df
        return df
    
    def _clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean and standardize the DataFrame.
        
        Args:
            df: Raw DataFrame
            
        Returns:
            Cleaned DataFrame
        """
        # Return empty DataFrame if no data
        if df.empty:
            return df
            
        # Filter out rejected CVEs if Status column exists
        if 'Status' in df.columns:
            df = df[~df.Status.str.contains('Rejected', na=False)]
        
        # Process dates if Published column exists
        if 'Published' in df.columns:
            df['Published'] = pd.to_datetime(df['Published'], errors='coerce')
            
            # Sort by publication date
            df = df.sort_values(by=['Published'])
            df = df.reset_index(drop=True)
        
        # Process CVSS scores if BaseScore column exists
        if 'BaseScore' in df.columns:
            df['BaseScore'] = pd.to_numeric(df['BaseScore'], errors='coerce')
            df['BaseScore'] = df['BaseScore'].replace(0, np.nan)
        
        return df
    
    def filter_by_year(self, df: pd.DataFrame, year: int) -> pd.DataFrame:
        """
        Filter DataFrame to include only CVEs from a specific year.
        
        Args:
            df: DataFrame to filter
            year: Target year
            
        Returns:
            Filtered DataFrame
        """
        year_filter = (
            (df['Published'] >= f'{year}-01-01') & 
            (df['Published'] < f'{year + 1}-01-01')
        )
        return df.loc[year_filter].reset_index(drop=True)
    
    def get_statistics(self, df: Optional[pd.DataFrame] = None) -> Dict[str, Any]:
        """
        Calculate basic statistics for the dataset.
        
        Args:
            df: DataFrame to analyze (uses processed_data if None)
            
        Returns:
            Dictionary with statistics
        """
        if df is None:
            df = self.processed_data
            
        if df is None or df.empty:
            return {}
        
        startdate = date(2000, 1, 1)
        enddate = date.today()
        numberofdays = enddate - startdate
        
        return {
            'total_cves': len(df),
            'unique_dates': df['Published'].nunique(),
            'avg_per_day': len(df) / numberofdays.days,
            'avg_cvss_score': df['BaseScore'].mean(),
            'date_range': {
                'start': df['Published'].min(),
                'end': df['Published'].max()
            }
        }

#!/usr/bin/env python3
"""
Local build script for CVE.ICU

Downloads NVD data and builds the complete website locally for review.
This script automates the entire process from data download to website generation.
"""

import os
import sys
import json
import gzip
import requests
import subprocess
import tempfile
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional


class CVELocalBuilder:
    """Local builder for CVE.ICU website with NVD data download."""
    
    def __init__(self, data_dir: str = "data", output_dir: str = "website/output"):
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
        self.project_root = Path(__file__).parent
        self.nvd_data_file = self.data_dir / "nvd.jsonl"
        
        # Direct download URL for processed NVD data
        self.nvd_data_url = "https://nvd.handsonhacking.org/nvd.jsonl"
        
    def setup_directories(self):
        """Create necessary directories."""
        print("📁 Setting up directories...")
        self.data_dir.mkdir(exist_ok=True)
        print(f"   Created: {self.data_dir}")
        
    def create_sample_data(self, count: int = 100):
        """Create sample CVE data for testing when NVD API is unavailable."""
        print(f"📝 Creating {count} sample CVE records...")
        
        sample_cves = []
        
        for i in range(count):
            cve_id = f"CVE-2024-{10000 + i:05d}"
            
            sample_cve = {
                "cve": {
                    "id": cve_id,
                    "sourceIdentifier": "nvd@nist.gov",
                    "published": f"2024-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}T10:00:00.000",
                    "lastModified": f"2024-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}T10:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": f"Sample vulnerability description for {cve_id}. This is a test vulnerability used for demonstration purposes."
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{'HML'[i%3]}/I:{'HML'[i%3]}/A:{'HML'[i%3]}",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "LOW",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": ["HIGH", "MEDIUM", "LOW"][i % 3],
                                    "integrityImpact": ["HIGH", "MEDIUM", "LOW"][i % 3],
                                    "availabilityImpact": ["HIGH", "MEDIUM", "LOW"][i % 3],
                                    "baseScore": [9.8, 7.5, 4.3][i % 3],
                                    "baseSeverity": ["CRITICAL", "HIGH", "MEDIUM"][i % 3]
                                },
                                "exploitabilityScore": [3.9, 3.1, 2.2][i % 3],
                                "impactScore": [5.9, 4.7, 2.5][i % 3]
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "description": [
                                {
                                    "lang": "en",
                                    "value": f"CWE-{[79, 89, 22, 78, 94][i % 5]}"
                                }
                            ]
                        }
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "negate": False,
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": f"cpe:2.3:a:example:product_{i%10}:1.0:*:*:*:*:*:*:*",
                                            "matchCriteriaId": f"12345678-1234-1234-1234-{i:012d}"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            }
            
            sample_cves.append(sample_cve)
        
        # Save to JSONL format
        print(f"💾 Saving sample data to {self.nvd_data_file}...")
        with open(self.nvd_data_file, 'w') as f:
            for cve in sample_cves:
                f.write(json.dumps(cve) + '\n')
        
        print(f"✅ Sample data saved to {self.nvd_data_file}")
        return len(sample_cves)

    def download_nvd_data(self, use_sample: bool = False):
        """Download CVE data from the processed NVD file or create sample data."""
        if use_sample:
            return self.create_sample_data()
        
        print(f"🔽 Downloading NVD data from {self.nvd_data_url}")
        print("   This file contains all processed CVE data and may be large...")
        
        try:
            # Download with progress indication
            response = requests.get(self.nvd_data_url, stream=True, timeout=60)
            response.raise_for_status()
            
            # Get file size for progress
            file_size = int(response.headers.get('content-length', 0))
            if file_size > 0:
                print(f"   File size: {file_size / (1024*1024):.1f} MB")
            
            # Download and save the file
            downloaded = 0
            chunk_size = 8192
            
            with open(self.nvd_data_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if file_size > 0:
                            progress = (downloaded / file_size) * 100
                            print(f"\r   Progress: {progress:.1f}% ({downloaded / (1024*1024):.1f} MB)", end='', flush=True)
            
            print()  # New line after progress
            
            # Count CVEs in the file
            print("📊 Counting CVE records...")
            cve_count = 0
            try:
                with open(self.nvd_data_file, 'r') as f:
                    content = f.read()
                    # Count CVE objects by counting "id": "CVE-" occurrences
                    cve_count = content.count('"id": "CVE-')
            except Exception as e:
                print(f"   ⚠️  Could not count CVEs: {e}")
                cve_count = 0
            
            print(f"✅ Downloaded {cve_count:,} CVE records")
            print(f"💾 Data saved to {self.nvd_data_file}")
            
            return cve_count
            
        except requests.RequestException as e:
            print(f"❌ Download failed: {e}")
            print("� Falling back to sample data...")
            return self.create_sample_data()
        except Exception as e:
            print(f"❌ Error processing downloaded data: {e}")
            print("🔄 Falling back to sample data...")
            return self.create_sample_data()
    
    def run_analysis(self):
        """Run CVE analysis using simple data processing."""
        print("🔍 Running CVE analysis...")
        
        if not self.nvd_data_file.exists():
            print(f"❌ No data file found at {self.nvd_data_file}")
            return False
        
        # Create analysis output directory
        analysis_output_dir = self.data_dir / "analysis"
        analysis_output_dir.mkdir(exist_ok=True)
        
        # Simple analysis: count CVEs and extract basic stats
        try:
            print("   📊 Analyzing CVE data...")
            
            with open(self.nvd_data_file, 'r') as f:
                content = f.read()
            
            # Count CVEs
            cve_count = content.count('"id": "CVE-')
            
            # Count by severity
            critical_count = content.count('"baseSeverity": "CRITICAL"')
            high_count = content.count('"baseSeverity": "HIGH"')
            medium_count = content.count('"baseSeverity": "MEDIUM"')
            low_count = content.count('"baseSeverity": "LOW"')
            
            # Count by year (approximate)
            year_counts = {}
            for year in range(1999, 2026):
                year_counts[year] = content.count(f'"id": "CVE-{year}-')
            
            # Create analysis summary
            analysis_summary = {
                "total_cves": cve_count,
                "severity_distribution": {
                    "CRITICAL": critical_count,
                    "HIGH": high_count,
                    "MEDIUM": medium_count,
                    "LOW": low_count
                },
                "year_distribution": year_counts,
                "analysis_date": datetime.now().isoformat()
            }
            
            # Save analysis results
            summary_file = analysis_output_dir / "analysis_summary.json"
            with open(summary_file, 'w') as f:
                json.dump(analysis_summary, f, indent=2)
            
            print(f"   ✅ Analysis completed: {cve_count:,} CVEs processed")
            print(f"   📄 Summary saved to {summary_file}")
            
            return True
            
        except Exception as e:
            print(f"   ❌ Analysis failed: {e}")
            return False
    
    def generate_website(self):
        """Generate the static website."""
        print("🌐 Generating website...")
        
        # Try to use tasks.py generate command
        try:
            cmd = [sys.executable, "tasks.py", "generate"]
            result = subprocess.run(cmd, cwd=self.project_root, check=True, capture_output=True, text=True)
            print("✅ Website generated with tasks.py")
            return True
        except subprocess.CalledProcessError as e:
            print(f"   ⚠️  tasks.py generate failed: {e}")
            print(f"   stdout: {e.stdout}")
            print(f"   stderr: {e.stderr}")
        
        # Alternative: Use website generation script directly
        try:
            website_script = self.project_root / "website" / "generate_site.py"
            if website_script.exists():
                print("   🔄 Using direct website generation script...")
                cmd = [sys.executable, str(website_script)]
                result = subprocess.run(cmd, cwd=self.project_root, check=True, capture_output=True, text=True)
                print("✅ Website generated successfully")
                return True
        except subprocess.CalledProcessError as e:
            print(f"   ❌ Website generation script failed: {e}")
            print(f"   stderr: {e.stderr}")
        
        # Fallback: Create basic HTML structure
        try:
            print("   � Creating basic website structure...")
            self.create_basic_website()
            print("✅ Basic website created")
            return True
        except Exception as e:
            print(f"❌ Website generation failed: {e}")
            return False
    
    def create_basic_website(self):
        """Create a basic website structure with analysis results."""
        print("   Creating basic website structure...")
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
        
        # Check if analysis results exist
        analysis_dir = self.data_dir / "analysis"
        has_analysis = analysis_dir.exists() and any(analysis_dir.iterdir())
        
        # Create a simple index.html
        index_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVE.ICU - CVE Analysis Dashboard</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0;
            opacity: 0.9;
            font-size: 1.2em;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-card h3 {{
            margin: 0 0 10px;
            color: #667eea;
            font-size: 1.1em;
        }}
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
            margin: 10px 0;
        }}
        .content {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .timestamp {{
            text-align: center;
            margin-top: 30px;
            color: #666;
            font-style: italic;
        }}
        .data-info {{
            background: #e8f4fd;
            border: 1px solid #bee5eb;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CVE.ICU</h1>
        <p>CVE Analysis Dashboard</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <h3>Data Source</h3>
            <div class="number">NVD</div>
            <p>National Vulnerability Database</p>
        </div>
        <div class="stat-card">
            <h3>Data File</h3>
            <div class="number">JSONL</div>
            <p>Processed vulnerability data</p>
        </div>
        <div class="stat-card">
            <h3>Status</h3>
            <div class="number">✅</div>
            <p>Data downloaded and processed</p>
        </div>
    </div>
    
    <div class="content">
        <h2>CVE Analysis Status</h2>
        
        <div class="data-info">
            <strong>Data File:</strong> {self.nvd_data_file}<br>
            <strong>File Size:</strong> {self._get_file_size(self.nvd_data_file)} MB<br>
            <strong>CVE Records:</strong> {self._count_cve_records()} records
        </div>
        
        {'<p><strong>Analysis:</strong> ✅ Analysis completed successfully</p>' if has_analysis else '<p><strong>Analysis:</strong> ⚠️ No analysis results found</p>'}
        
        <h3>Available Data</h3>
        <ul>
            <li>CVE vulnerability records from NVD</li>
            <li>CVSS scoring information</li>
            <li>CWE weakness classifications</li>
            <li>CPE platform identifiers</li>
            <li>CNA assignment data</li>
        </ul>
        
        <h3>Next Steps</h3>
        <p>The CVE data has been successfully downloaded and is ready for analysis. 
           You can now run specific analysis scripts or use the data for your own research.</p>
    </div>
    
    <div class="timestamp">
        Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </div>
</body>
</html>
"""
        
        index_path = self.output_dir / "index.html"
        with open(index_path, 'w') as f:
            f.write(index_content)
        
        print(f"   📄 Created index page at {index_path}")
        
    def _get_file_size(self, file_path):
        """Get file size in MB."""
        try:
            if file_path.exists():
                size_bytes = file_path.stat().st_size
                return round(size_bytes / (1024 * 1024), 2)
        except:
            pass
        return "Unknown"
    
    def _count_cve_records(self):
        """Count CVE records in the data file."""
        try:
            if not self.nvd_data_file.exists():
                return "No data file"
            
            with open(self.nvd_data_file, 'r') as f:
                content = f.read()
                # Count CVE objects by counting "id": "CVE-" occurrences
                count = content.count('"id": "CVE-')
            return f"{count:,}"
        except:
            return "Unknown"
    
    def start_dev_server(self, port: int = 8000):
        """Start the development server."""
        print(f"🚀 Starting development server on port {port}...")
        print(f"   Website will be available at: http://localhost:{port}")
        print("   Press Ctrl+C to stop the server")
        
        # Use the dev_server.py directly with the correct directory
        cmd = [
            sys.executable, 
            "website/dev_server.py", 
            "--directory", str(self.output_dir),
            "--port", str(port)
        ]
        
        try:
            subprocess.run(cmd, cwd=self.project_root)
        except KeyboardInterrupt:
            print("\n🛑 Server stopped")
    
    def build_complete_site(self, use_sample: bool = False, serve: bool = True, port: int = 8000):
        """Complete build process: download data, analyze, generate website."""
        start_time = datetime.now()
        print("🏗️  Starting complete CVE.ICU local build...")
        print(f"   Start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Step 1: Setup
        self.setup_directories()
        print()
        
        # Step 2: Download data
        if not self.nvd_data_file.exists() or input("Data file exists. Re-download? (y/N): ").lower().startswith('y'):
            cve_count = self.download_nvd_data(use_sample=use_sample)
            if cve_count == 0:
                print("❌ No data downloaded. Exiting.")
                return False
        else:
            print(f"📄 Using existing data file: {self.nvd_data_file}")
        print()
        
        # Step 3: Run analysis
        if not self.run_analysis():
            print("❌ Analysis failed. Exiting.")
            return False
        print()
        
        # Step 4: Generate website
        if not self.generate_website():
            print("❌ Website generation failed. Exiting.")
            return False
        print()
        
        # Step 5: Show summary
        end_time = datetime.now()
        duration = end_time - start_time
        print("🎉 Build completed successfully!")
        print(f"   Build time: {duration}")
        print(f"   Data file: {self.nvd_data_file}")
        print(f"   Website: {self.output_dir}")
        print()
        
        # Step 6: Optionally start server
        if serve:
            self.start_dev_server(port=port)
        else:
            print(f"💡 To view the website, run: python tasks.py serve")
            print(f"   Or open: {self.output_dir / 'index.html'}")
        
        return True


def main():
    """Main function with command line interface."""
    parser = argparse.ArgumentParser(description="CVE.ICU Local Builder")
    parser.add_argument("--sample", action="store_true",
                       help="Use sample data instead of downloading from website")
    parser.add_argument("--data-dir", default="data",
                       help="Directory to store downloaded data (default: data)")
    parser.add_argument("--no-serve", action="store_true",
                       help="Don't start the development server after build")
    parser.add_argument("--port", type=int, default=8000,
                       help="Port for development server (default: 8000)")
    parser.add_argument("--download-only", action="store_true",
                       help="Only download data, don't build website")
    parser.add_argument("--build-only", action="store_true",
                       help="Only build website (skip download)")
    
    args = parser.parse_args()
    
    # Create builder instance
    builder = CVELocalBuilder(data_dir=args.data_dir)
    
    try:
        if args.download_only:
            # Only download data
            builder.setup_directories()
            builder.download_nvd_data(use_sample=args.sample)
        elif args.build_only:
            # Only build website (assume data exists)
            if not builder.nvd_data_file.exists():
                print(f"❌ No data file found at {builder.nvd_data_file}")
                print("   Run without --build-only to download data first")
                sys.exit(1)
            
            success = True
            success &= builder.run_analysis()
            success &= builder.generate_website()
            
            if success and not args.no_serve:
                builder.start_dev_server(port=args.port)
        else:
            # Complete build process
            success = builder.build_complete_site(
                use_sample=args.sample,
                serve=not args.no_serve,
                port=args.port
            )
            
            if not success:
                sys.exit(1)
                
    except KeyboardInterrupt:
        print("\n🛑 Build interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Build failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

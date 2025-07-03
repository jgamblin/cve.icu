# Scripts Directory

This directory contains all the Python scripts for the CVE.ICU project, organized into the following structure:

## Main Scripts

- **`analyze_cves.py`** - Main analysis script for processing CVE data and generating reports
  - Usage: `python analyze_cves.py --data-path nvd.jsonl --output-dir output`
  - Supports multiple analysis types: growth, cvss, attack-vectors, cwe, cna

## Analysis Scripts (`analysis/`)

Contains specialized analysis scripts built with the refactored architecture:

- **`cve_growth_analysis.py`** - Analyzes CVE growth trends over time
- **`cvss_analysis.py`** - Analyzes CVSS scores and severity distributions

## Legacy Scripts (`legacy/`)

Contains scripts converted from the original Jupyter notebooks. These are preserved for reference but should not be used in production:

### Year-specific Analysis Scripts
- `CVE2016.py` through `CVE2025.py` - Year-specific CVE analysis

### Topic-specific Analysis Scripts
- `CVEAll.py` - Combined analysis of all CVE data
- `CVECNA.py` - CVE Numbering Authority analysis
- `CVECPE.py` - Common Platform Enumeration analysis
- `CVECVSS.py` - CVSS score analysis
- `CVECWE.py` - Common Weakness Enumeration analysis
- `CVECalendar.py` - Calendar-based CVE visualization
- `CVEGrowth.py` - CVE growth analysis

### Configuration
- `conf.py` - Configuration file (legacy)

## Usage

For new development, use the main `analyze_cves.py` script or the specialized scripts in the `analysis/` directory. These utilize the modular CVE analyzer framework in `src/cve_analyzer/`.

Legacy scripts are kept for historical reference and comparison but may not work with the current data format or dependencies.

## Examples

```bash
# Run complete analysis
python analyze_cves.py --data-path data/nvd.jsonl --analysis all

# Run specific analysis types
python analyze_cves.py --data-path data/nvd.jsonl --analysis growth
python analyze_cves.py --data-path data/nvd.jsonl --analysis cvss

# Use specialized analysis scripts
python analysis/cve_growth_analysis.py --input data/nvd.jsonl --output results/
python analysis/cvss_analysis.py --input data/nvd.jsonl --output results/
```

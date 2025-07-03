# CVE.ICU

[CVE.ICU](https://cve.icu) is a passion project by [Jerry Gamblin](https://www.jerrygamblin.com). The goal is to dive deep into Common Vulnerabilities and Exposures (CVE) by pulling and analyzing all the CVE data from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/).

## Goals
The main aim of CVE.ICU is to make sense of all this data and present it in a way that's easy to understand through cool graphs and charts.  
This automated analysis helps:
- Spot patterns and trends in cybersecurity vulnerabilities.
- Give researchers and cybersecurity pros a better handle on what's going on and what's coming next.

## Open Source and Collaboration
The [source code](https://github.com/jgamblin/cve.icu) for this project is up on GitHub. It's open for everyone to see, use, and improve. By keeping it open-source, I'm hoping to get contributions and ideas from the community to make it even better.

## Timely Updates
To keep things fresh, the data on CVE.ICU is updated every 4 hours using GitHub Actions. This way, you always get the latest insights into the ever-changing world of cybersecurity vulnerabilities.

## Project Structure

This project has been refactored from Jupyter notebooks to a modular Python application:

- **`src/cve_analyzer/`** - Core analysis modules (data processing, analysis, visualization)
- **`scripts/`** - Analysis scripts organized by category:
  - `analyze_cves.py` - Main analysis script
  - `analysis/` - Specialized analysis scripts  
  - `legacy/` - Converted legacy notebook scripts
- **`website/`** - Static website generator and templates
- **`tests/`** - Comprehensive test suite (unit, integration, E2E)

## Quick Start

1. **Clone the repository**:
    ```sh
    git clone https://github.com/jgamblin/cve.icu.git
    cd cve.icu
    ```

2. **Install dependencies**:
    ```sh
    python tasks.py install
    ```

3. **Run analysis** (requires CVE data):
    ```sh
    python scripts/analyze_cves.py --data-path nvd.jsonl --analysis all
    ```

4. **Generate website**:
    ```sh
    python tasks.py generate
    ```

5. **Serve locally**:
    ```sh
    python tasks.py serve
    ```

## Available Commands

Use the task runner for common development operations:

```sh
python tasks.py --help
```

Available commands:
- `clean` - Clean generated files
- `install` - Install dependencies  
- `analyze` - Run CVE analysis
- `generate` - Generate static website
- `serve` - Start development server
- `test` - Run all tests
- `test-unit` - Run unit tests
- `test-integration` - Run integration tests
- `test-e2e` - Run end-to-end tests
- `lint` - Format and lint code
- `build` - Complete build process

## Get Involved
I love hearing from people who are interested in this project. Feel free to reach out to me on Twitter [@jgamblin](https://twitter.com/jgamblin) if you have any questions or just want to chat about CVE.ICU. If you're interested in contributing, check out the [GitHub repository](https://github.com/jgamblin/cve.icu).

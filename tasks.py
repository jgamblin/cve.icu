#!/usr/bin/env python3
"""
CVE.ICU Build and Development Tasks

A task runner script for common development and build operations.
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path


def run_command(command: str, description: str, cwd=None):
    """Run a shell command and handle errors."""
    print(f"📋 {description}")
    print(f"🔧 Running: {command}")
    
    result = subprocess.run(
        command, 
        shell=True, 
        cwd=cwd,
        capture_output=False,
        text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Failed: {description}")
        sys.exit(result.returncode)
    else:
        print(f"✅ Success: {description}\n")


def clean():
    """Clean generated files and cache."""
    print("🧹 Cleaning generated files...")
    
    paths_to_clean = [
        "website/output",
        "output",
        "__pycache__",
        "*.pyc",
        "*.pyo",
        ".pytest_cache",
        ".coverage",
        "htmlcov",
        "dist",
        "build",
        "*.egg-info"
    ]
    
    for path in paths_to_clean:
        if "*" in path:
            run_command(f"find . -name '{path}' -delete", f"Remove {path}")
        else:
            if Path(path).exists():
                run_command(f"rm -rf {path}", f"Remove {path}")
    
    print("✅ Cleanup complete!\n")


def install_deps():
    """Install Python dependencies."""
    python_cmd = "/opt/homebrew/opt/python@3.13/libexec/bin/python"
    
    run_command(
        f"{python_cmd} -m pip install -r requirements-refactored.txt",
        "Install Python dependencies"
    )


def convert_notebooks():
    """Convert Jupyter notebooks to Python scripts."""
    python_cmd = "/opt/homebrew/opt/python@3.13/libexec/bin/python"
    
    run_command(
        f"{python_cmd} -m jupyter nbconvert --to script *.ipynb",
        "Convert notebooks to Python scripts"
    )


def run_analysis():
    """Run CVE analysis scripts."""
    python_cmd = "/opt/homebrew/opt/python@3.13/libexec/bin/python"
    
    print("📊 Running CVE analysis...")
    
    # Run main analysis script
    run_command(
        f"{python_cmd} scripts/analyze_cves.py",
        "Run main CVE analysis"
    )
    
    # Run specific analysis scripts
    analysis_scripts = [
        "scripts/analysis/cve_growth_analysis.py",
        "scripts/analysis/cvss_analysis.py"
    ]
    
    for script in analysis_scripts:
        if Path(script).exists():
            run_command(
                f"{python_cmd} {script}",
                f"Run {Path(script).stem}"
            )


def generate_website():
    """Generate the static website."""
    python_cmd = "/opt/homebrew/opt/python@3.13/libexec/bin/python"
    
    run_command(
        f"{python_cmd} website/generate_site.py",
        "Generate static website"
    )


def serve_website(port: int = 8000):
    """Start development server."""
    python_cmd = "/opt/homebrew/opt/python@3.13/libexec/bin/python"
    
    print(f"🌐 Starting development server on port {port}...")
    print("Press Ctrl+C to stop")
    
    try:
        subprocess.run([
            python_cmd, 
            "website/dev_server.py", 
            "--port", str(port)
        ])
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")


def run_tests():
    """Run the test suite."""
    python_cmd = "/opt/homebrew/opt/python@3.13/libexec/bin/python"
    
    # Check if pytest is available
    result = subprocess.run([python_cmd, "-m", "pytest", "--version"], 
                          capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Installing pytest...")
        run_command(f"{python_cmd} -m pip install pytest pytest-cov", "Install pytest")
    
    run_command(
        f"{python_cmd} -m pytest tests/ -v --cov=src/cve_analyzer",
        "Run test suite with coverage"
    )


def run_unit_tests():
    """Run only unit tests."""
    python_cmd = "/opt/homebrew/opt/python@3.13/libexec/bin/python"
    
    run_command(
        f"{python_cmd} -m pytest tests/unit/ -v",
        "Run unit tests"
    )


def run_integration_tests():
    """Run only integration tests."""
    python_cmd = "/opt/homebrew/opt/python@3.13/libexec/bin/python"
    
    run_command(
        f"{python_cmd} -m pytest tests/integration/ -v",
        "Run integration tests"
    )


def run_e2e_tests():
    """Run end-to-end tests."""
    python_cmd = "/opt/homebrew/opt/python@3.13/libexec/bin/python"
    
    # Check if playwright is available
    result = subprocess.run([python_cmd, "-m", "playwright", "--version"], 
                          capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Installing playwright...")
        run_command(f"{python_cmd} -m pip install playwright pytest-playwright", "Install Playwright")
        run_command(f"{python_cmd} -m playwright install chromium", "Install Chromium")
    
    run_command(
        f"{python_cmd} -m pytest tests/e2e/ -v",
        "Run end-to-end tests"
    )


def lint_code():
    """Run code linting and formatting."""
    python_cmd = "/opt/homebrew/opt/python@3.13/libexec/bin/python"
    
    # Install linting tools if needed
    linting_tools = ["black", "flake8", "isort"]
    for tool in linting_tools:
        result = subprocess.run([python_cmd, "-m", tool, "--version"], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            run_command(f"{python_cmd} -m pip install {tool}", f"Install {tool}")
    
    # Run formatting and linting
    run_command(f"{python_cmd} -m black src/ scripts/ website/", "Format code with Black")
    run_command(f"{python_cmd} -m isort src/ scripts/ website/", "Sort imports with isort")
    run_command(f"{python_cmd} -m flake8 src/ scripts/ website/", "Lint code with flake8")


def build_all():
    """Complete build process."""
    print("🏗️  Starting complete build process...\n")
    
    # Clean first
    clean()
    
    # Install dependencies
    install_deps()
    
    # Convert notebooks if any exist
    if list(Path(".").glob("*.ipynb")):
        convert_notebooks()
    
    # Run analysis if data exists
    if Path("nvd.jsonl").exists():
        run_analysis()
    
    # Generate website
    generate_website()
    
    print("🎉 Build complete! Use 'python tasks.py serve' to start the development server.")


def main():
    """Main task runner."""
    parser = argparse.ArgumentParser(description="CVE.ICU Task Runner")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Clean command
    subparsers.add_parser("clean", help="Clean generated files")
    
    # Install command
    subparsers.add_parser("install", help="Install dependencies")
    
    # Convert command
    subparsers.add_parser("convert", help="Convert notebooks to scripts")
    
    # Analyze command
    subparsers.add_parser("analyze", help="Run CVE analysis")
    
    # Generate command
    subparsers.add_parser("generate", help="Generate website")
    
    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start development server")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port number")
    
    # Test commands
    subparsers.add_parser("test", help="Run all tests")
    subparsers.add_parser("test-unit", help="Run unit tests")
    subparsers.add_parser("test-integration", help="Run integration tests")
    subparsers.add_parser("test-e2e", help="Run end-to-end tests")
    
    # Lint command
    subparsers.add_parser("lint", help="Lint and format code")
    
    # Build command
    subparsers.add_parser("build", help="Complete build process")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Change to project directory
    project_root = Path(__file__).parent
    os.chdir(project_root)
    
    # Execute command
    if args.command == "clean":
        clean()
    elif args.command == "install":
        install_deps()
    elif args.command == "convert":
        convert_notebooks()
    elif args.command == "analyze":
        run_analysis()
    elif args.command == "generate":
        generate_website()
    elif args.command == "serve":
        serve_website(args.port)
    elif args.command == "test":
        run_tests()
    elif args.command == "test-unit":
        run_unit_tests()
    elif args.command == "test-integration":
        run_integration_tests()
    elif args.command == "test-e2e":
        run_e2e_tests()
    elif args.command == "lint":
        lint_code()
    elif args.command == "build":
        build_all()


if __name__ == "__main__":
    main()

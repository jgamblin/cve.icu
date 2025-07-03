"""Setup configuration for CVE Analyzer package."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
if readme_path.exists():
    with open(readme_path, "r", encoding="utf-8") as f:
        long_description = f.read()
else:
    long_description = "CVE Analysis Tool - A comprehensive tool for analyzing CVE data"

# Read requirements
requirements_path = Path(__file__).parent / "requirements-new.txt"
if requirements_path.exists():
    with open(requirements_path, "r", encoding="utf-8") as f:
        requirements = [
            line.strip() 
            for line in f.readlines() 
            if line.strip() and not line.startswith('#')
        ]
else:
    requirements = []

setup(
    name="cve-analyzer",
    version="1.0.0",
    author="Jerry Gamblin",
    author_email="jerry@jerrygamblin.com",
    description="A comprehensive tool for analyzing CVE data from the National Vulnerability Database",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jgamblin/cve.icu",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
        "web": [
            "pelican>=4.8.0",
            "playwright>=1.36.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cve-analyzer=main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)

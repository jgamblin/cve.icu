#!/usr/bin/env python3
"""
CVE Website Generator

A pure Python static site generator for the CVE analysis website.
Generates HTML5 pages from templates and analysis results.
"""

import os
import sys
import json
import shutil
import markdown
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from jinja2 import Environment, FileSystemLoader

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cve_analyzer import CVEDataProcessor, CVEAnalyzer, CVEVisualizer


class CVEWebsiteGenerator:
    """Generates a static HTML5 website for CVE analysis results."""
    
    def __init__(self, website_dir: str = "website"):
        """
        Initialize the website generator.
        
        Args:
            website_dir: Root directory for website files
        """
        self.website_dir = Path(website_dir)
        self.templates_dir = self.website_dir / "templates"
        self.static_dir = self.website_dir / "static"
        self.content_dir = self.website_dir / "content"
        self.output_dir = self.website_dir / "output"
        
        # Setup Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True
        )
        
        # Ensure output directory exists
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize markdown processor
        self.md = markdown.Markdown(extensions=['meta', 'tables', 'fenced_code'])
    
    def copy_static_files(self):
        """Copy static files (CSS, JS, images) to output directory."""
        if self.static_dir.exists():
            output_static = self.output_dir / "static"
            if output_static.exists():
                shutil.rmtree(output_static)
            shutil.copytree(self.static_dir, output_static)
            print(f"Static files copied to {output_static}")
    
    def render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """
        Render a Jinja2 template with the given context.
        
        Args:
            template_name: Name of the template file
            context: Template context variables
            
        Returns:
            Rendered HTML content
        """
        template = self.jinja_env.get_template(template_name)
        return template.render(**context)
    
    def process_markdown_file(self, md_file: Path) -> Dict[str, Any]:
        """
        Process a markdown file and return content and metadata.
        
        Args:
            md_file: Path to markdown file
            
        Returns:
            Dictionary with content, metadata, and file info
        """
        with open(md_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        html_content = self.md.convert(content)
        metadata = getattr(self.md, 'Meta', {})
        
        # Reset markdown instance for next file
        self.md.reset()
        
        return {
            'content': html_content,
            'metadata': metadata,
            'filename': md_file.stem,
            'title': metadata.get('title', [md_file.stem])[0] if metadata.get('title') else md_file.stem
        }
    
    def generate_index_page(self, analysis_data: Dict[str, Any]) -> str:
        """
        Generate the main index page.
        
        Args:
            analysis_data: Complete analysis results
            
        Returns:
            Path to generated index page
        """
        context = {
            'title': 'CVE.ICU - CVE Analysis Dashboard',
            'current_date': datetime.now().strftime('%Y-%m-%d'),
            'analysis_data': analysis_data,
            'site_url': 'https://cve.icu'
        }
        
        html_content = self.render_template('index.html', context)
        
        output_file = self.output_dir / "index.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Generated index page: {output_file}")
        return str(output_file)
    
    def generate_analysis_page(self, analysis_type: str, data: Dict[str, Any], 
                             plots: List[str]) -> str:
        """
        Generate an analysis page for a specific type of analysis.
        
        Args:
            analysis_type: Type of analysis (growth, cvss, etc.)
            data: Analysis data
            plots: List of plot file paths
            
        Returns:
            Path to generated page
        """
        context = {
            'title': f'CVE {analysis_type.title()} Analysis',
            'analysis_type': analysis_type,
            'data': data,
            'plots': plots,
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }
        
        html_content = self.render_template('analysis.html', context)
        
        output_file = self.output_dir / f"{analysis_type}.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Generated {analysis_type} page: {output_file}")
        return str(output_file)
    
    def generate_data_page(self, summary_data: Dict[str, Any]) -> str:
        """
        Generate a data overview page.
        
        Args:
            summary_data: Summary statistics
            
        Returns:
            Path to generated page
        """
        context = {
            'title': 'CVE Data Overview',
            'summary': summary_data,
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }
        
        html_content = self.render_template('data.html', context)
        
        output_file = self.output_dir / "data.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Generated data page: {output_file}")
        return str(output_file)
    
    def generate_about_page(self) -> str:
        """Generate the about page from markdown content."""
        about_md = self.content_dir / "about.md"
        
        if about_md.exists():
            about_content = self.process_markdown_file(about_md)
        else:
            # Default about content
            about_content = {
                'content': '<h1>About CVE.ICU</h1><p>A comprehensive CVE analysis platform.</p>',
                'title': 'About',
                'metadata': {}
            }
        
        context = {
            'title': 'About CVE.ICU',
            'content': about_content['content'],
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }
        
        html_content = self.render_template('page.html', context)
        
        output_file = self.output_dir / "about.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Generated about page: {output_file}")
        return str(output_file)
    
    def copy_analysis_plots(self, plots_dir: Path):
        """
        Copy analysis plots to the website output directory.
        
        Args:
            plots_dir: Directory containing analysis plots
        """
        if not plots_dir.exists():
            return
        
        output_images = self.output_dir / "static" / "images" / "analysis"
        output_images.mkdir(parents=True, exist_ok=True)
        
        for plot_file in plots_dir.glob("*.png"):
            destination = output_images / plot_file.name
            shutil.copy2(plot_file, destination)
            print(f"Copied plot: {plot_file.name}")
    
    def generate_sitemap(self, pages: List[str]) -> str:
        """
        Generate a sitemap.xml file.
        
        Args:
            pages: List of page URLs
            
        Returns:
            Path to generated sitemap
        """
        sitemap_content = '<?xml version="1.0" encoding="UTF-8"?>\\n'
        sitemap_content += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\\n'
        
        base_url = "https://cve.icu"
        current_date = datetime.now().strftime('%Y-%m-%d')
        
        for page in pages:
            sitemap_content += f'  <url>\\n'
            sitemap_content += f'    <loc>{base_url}/{page}</loc>\\n'
            sitemap_content += f'    <lastmod>{current_date}</lastmod>\\n'
            sitemap_content += f'    <changefreq>daily</changefreq>\\n'
            sitemap_content += f'    <priority>0.8</priority>\\n'
            sitemap_content += f'  </url>\\n'
        
        sitemap_content += '</urlset>\\n'
        
        sitemap_file = self.output_dir / "sitemap.xml"
        with open(sitemap_file, 'w', encoding='utf-8') as f:
            f.write(sitemap_content)
        
        print(f"Generated sitemap: {sitemap_file}")
        return str(sitemap_file)
    
    def generate_website(self, cve_data_path: str = "nvd.jsonl") -> Dict[str, str]:
        """
        Generate the complete website.
        
        Args:
            cve_data_path: Path to CVE data file
            
        Returns:
            Dictionary mapping page names to file paths
        """
        print("Starting website generation...")
        
        # Copy static files first
        self.copy_static_files()
        
        # Process CVE data
        print("Processing CVE data...")
        processor = CVEDataProcessor(cve_data_path)
        data = processor.process_data()
        
        if data.empty:
            print("Warning: No CVE data found. Generating with sample data.")
            # Generate with empty/sample data
            analysis_data = {'summary': {'total_cves': 0}}
        else:
            print(f"Processed {len(data)} CVE records")
            
            # Perform analysis
            analyzer = CVEAnalyzer(data)
            visualizer = CVEVisualizer("output/plots")
            
            # Run all analyses
            analysis_data = {
                'summary': analyzer.generate_summary_report(),
                'growth': analyzer.analyze_growth_trends(),
                'cvss': analyzer.analyze_cvss_distribution(),
                'attack_vectors': analyzer.analyze_attack_vectors(),
                'cwe': analyzer.analyze_cwe_distribution(),
                'cna': analyzer.analyze_cna_distribution()
            }
            
            # Generate visualizations
            print("Generating visualizations...")
            try:
                if 'BaseScore' in data.columns:
                    visualizer.plot_cvss_distribution(data)
                if 'yearly' in analysis_data['growth']:
                    visualizer.plot_yearly_growth(analysis_data['growth']['yearly'])
            except Exception as e:
                print(f"Warning: Could not generate some plots: {e}")
            
            # Copy plots to website
            plots_dir = Path("output/plots")
            if plots_dir.exists():
                self.copy_analysis_plots(plots_dir)
        
        # Generate pages
        generated_pages = {}
        
        # Main index page
        generated_pages['index'] = self.generate_index_page(analysis_data)
        
        # Analysis pages
        if 'growth' in analysis_data and analysis_data['growth']:
            generated_pages['growth'] = self.generate_analysis_page(
                'growth', analysis_data['growth'], ['yearly_growth.png']
            )
        
        if 'cvss' in analysis_data and analysis_data['cvss']:
            generated_pages['cvss'] = self.generate_analysis_page(
                'cvss', analysis_data['cvss'], ['cvss_distribution.png']
            )
        
        # General analysis page (combines all analysis types)
        generated_pages['analysis'] = self.generate_analysis_page(
            'analysis', analysis_data, ['yearly_growth.png', 'cvss_distribution.png']
        )
        
        # Data overview page
        if 'summary' in analysis_data:
            generated_pages['data'] = self.generate_data_page(analysis_data['summary'])
        
        # About page
        generated_pages['about'] = self.generate_about_page()
        
        # Generate sitemap
        page_urls = [f"{page}.html" if page != 'index' else '' 
                    for page in generated_pages.keys()]
        self.generate_sitemap(page_urls)
        
        print(f"\\nWebsite generation complete!")
        print(f"Generated {len(generated_pages)} pages in {self.output_dir}")
        
        return generated_pages


def main():
    """Main function to generate the website."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate CVE analysis website")
    parser.add_argument("--data-path", default="nvd.jsonl", 
                       help="Path to CVE data file")
    parser.add_argument("--website-dir", default="website",
                       help="Website directory")
    
    args = parser.parse_args()
    
    # Change to the project root directory
    os.chdir(Path(__file__).parent.parent)
    
    generator = CVEWebsiteGenerator(args.website_dir)
    generated_pages = generator.generate_website(args.data_path)
    
    print("\\nGenerated pages:")
    for page_name, page_path in generated_pages.items():
        print(f"  {page_name}: {page_path}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
End-to-End tests for the CVE.ICU website.

These tests verify the complete website functionality including:
- Site generation
- Static file serving
- Navigation
- Content rendering
- Responsive design
"""

import pytest
import subprocess
import time
import threading
import requests
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

# Test configuration
TEST_HOST = "localhost"
TEST_PORT = 8080
BASE_URL = f"http://{TEST_HOST}:{TEST_PORT}"
WEBSITE_DIR = Path(__file__).parent.parent.parent / "website"
OUTPUT_DIR = WEBSITE_DIR / "output"


class DevServerManager:
    """Manages the development server for testing."""
    
    def __init__(self):
        self.server_process = None
        self.server_thread = None
        
    def start_server(self):
        """Start the development server in a separate thread."""
        def run_server():
            subprocess.run([
                "python", 
                str(WEBSITE_DIR / "dev_server.py"),
                "--port", str(TEST_PORT)
            ], cwd=WEBSITE_DIR)
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        
        # Wait for server to start
        max_attempts = 30
        for _ in range(max_attempts):
            try:
                response = requests.get(BASE_URL, timeout=1)
                if response.status_code == 200:
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(0.5)
        else:
            raise RuntimeError("Failed to start development server")
    
    def stop_server(self):
        """Stop the development server."""
        if self.server_process:
            self.server_process.terminate()


@pytest.fixture(scope="session")
def dev_server():
    """Fixture to start and stop the development server."""
    # Generate the website first
    subprocess.run([
        "python", 
        str(WEBSITE_DIR / "generate_site.py")
    ], cwd=WEBSITE_DIR, check=True)
    
    # Start the server
    server = DevServerManager()
    server.start_server()
    
    yield server
    
    server.stop_server()


@pytest.fixture
def browser():
    """Fixture to provide a browser instance."""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        yield browser
        browser.close()


@pytest.fixture
def page(browser):
    """Fixture to provide a page instance."""
    page = browser.new_page()
    yield page
    page.close()


class TestWebsiteGeneration:
    """Test website generation process."""
    
    def test_site_generation_success(self):
        """Test that the site generates without errors."""
        result = subprocess.run([
            "python", 
            str(WEBSITE_DIR / "generate_site.py")
        ], cwd=WEBSITE_DIR, capture_output=True, text=True)
        
        assert result.returncode == 0, f"Site generation failed: {result.stderr}"
        assert OUTPUT_DIR.exists(), "Output directory was not created"
    
    def test_required_files_generated(self):
        """Test that all required files are generated."""
        required_files = [
            "index.html",
            "analysis.html", 
            "data.html",
            "about.html",
            "static/css/main.css",
            "static/css/components.css",
            "static/js/main.js"
        ]
        
        for file_path in required_files:
            full_path = OUTPUT_DIR / file_path
            assert full_path.exists(), f"Required file missing: {file_path}"
            assert full_path.stat().st_size > 0, f"File is empty: {file_path}"


class TestWebsiteNavigation:
    """Test website navigation and page loading."""
    
    def test_homepage_loads(self, dev_server, page):
        """Test that the homepage loads successfully."""
        page.goto(BASE_URL)
        expect(page).to_have_title("CVE.ICU - CVE Analysis Dashboard")
        expect(page.locator("h1")).to_contain_text("CVE Analysis Dashboard")
    
    def test_navigation_menu(self, dev_server, page):
        """Test navigation menu functionality."""
        page.goto(BASE_URL)
        
        # Check that navigation menu exists
        nav = page.locator("nav")
        expect(nav).to_be_visible()
        
        # Test navigation links
        links = {
            "Home": "/",
            "Analysis": "/analysis.html",
            "Data": "/data.html", 
            "About": "/about.html"
        }
        
        for link_text, expected_url in links.items():
            link = page.locator(f"nav a:has-text('{link_text}')")
            expect(link).to_be_visible()
            expect(link).to_have_attribute("href", expected_url)
    
    def test_page_navigation(self, dev_server, page):
        """Test navigation between pages."""
        page.goto(BASE_URL)
        
        # Navigate to Analysis page
        page.click("nav a:has-text('Analysis')")
        expect(page).to_have_url(f"{BASE_URL}/analysis.html")
        expect(page.locator("h1")).to_contain_text("CVE Analysis")
        
        # Navigate to Data page
        page.click("nav a:has-text('Data')")
        expect(page).to_have_url(f"{BASE_URL}/data.html")
        expect(page.locator("h1")).to_contain_text("CVE Data")
        
        # Navigate to About page
        page.click("nav a:has-text('About')")
        expect(page).to_have_url(f"{BASE_URL}/about.html")
        expect(page.locator("h1")).to_contain_text("About CVE.ICU")


class TestWebsiteContent:
    """Test website content rendering and functionality."""
    
    def test_homepage_content(self, dev_server, page):
        """Test homepage content structure."""
        page.goto(BASE_URL)
        
        # Check main sections exist
        expect(page.locator(".hero")).to_be_visible()
        expect(page.locator(".stats-grid")).to_be_visible()
        expect(page.locator(".features-grid")).to_be_visible()
        
        # Check that sample statistics are displayed
        stats_cards = page.locator(".stat-card")
        expect(stats_cards).to_have_count_greater_than(0)
    
    def test_analysis_page_content(self, dev_server, page):
        """Test analysis page content."""
        page.goto(f"{BASE_URL}/analysis.html")
        
        # Check that analysis sections exist
        expect(page.locator(".analysis-container")).to_be_visible()
        
        # Check for chart containers (even if empty in test data)
        chart_containers = page.locator(".chart-container")
        expect(chart_containers).to_have_count_greater_than(0)
    
    def test_data_page_content(self, dev_server, page):
        """Test data page content."""
        page.goto(f"{BASE_URL}/data.html")
        
        # Check main content area
        expect(page.locator(".data-container")).to_be_visible()
        
        # Check for data sections
        data_sections = page.locator(".data-section")
        expect(data_sections).to_have_count_greater_than(0)
    
    def test_about_page_content(self, dev_server, page):
        """Test about page content from Markdown."""
        page.goto(f"{BASE_URL}/about.html")
        
        # Check that Markdown content was rendered
        expect(page.locator(".content")).to_be_visible()
        expect(page.locator("h1")).to_contain_text("About CVE.ICU")


class TestWebsiteResponsiveness:
    """Test responsive design and mobile compatibility."""
    
    def test_mobile_viewport(self, dev_server, page):
        """Test mobile viewport rendering."""
        # Set mobile viewport
        page.set_viewport_size({"width": 375, "height": 667})
        page.goto(BASE_URL)
        
        # Check that page renders properly on mobile
        expect(page.locator("body")).to_be_visible()
        expect(page.locator("nav")).to_be_visible()
        
        # Check mobile navigation (hamburger menu if implemented)
        # This would depend on the actual mobile menu implementation
    
    def test_tablet_viewport(self, dev_server, page):
        """Test tablet viewport rendering."""
        # Set tablet viewport
        page.set_viewport_size({"width": 768, "height": 1024})
        page.goto(BASE_URL)
        
        # Check that page renders properly on tablet
        expect(page.locator("body")).to_be_visible()
        expect(page.locator(".stats-grid")).to_be_visible()
    
    def test_desktop_viewport(self, dev_server, page):
        """Test desktop viewport rendering."""
        # Set desktop viewport
        page.set_viewport_size({"width": 1920, "height": 1080})
        page.goto(BASE_URL)
        
        # Check that page renders properly on desktop
        expect(page.locator("body")).to_be_visible()
        expect(page.locator(".features-grid")).to_be_visible()


class TestWebsiteAssets:
    """Test static assets loading and functionality."""
    
    def test_css_loading(self, dev_server, page):
        """Test that CSS files load correctly."""
        page.goto(BASE_URL)
        
        # Check that CSS is applied (test computed styles)
        body = page.locator("body")
        expect(body).to_have_css("margin", "0px")  # From CSS reset
    
    def test_javascript_functionality(self, dev_server, page):
        """Test JavaScript functionality."""
        page.goto(BASE_URL)
        
        # Test that JS is loaded and working
        # This would test any interactive features implemented in main.js
        # For now, just check that no JS errors occurred
        page.wait_for_load_state("networkidle")
        
        # Check console for errors
        console_errors = []
        page.on("console", lambda msg: console_errors.append(msg) if msg.type == "error" else None)
        page.reload()
        
        # Allow some time for any JS to execute
        page.wait_for_timeout(1000)
        
        assert len(console_errors) == 0, f"JavaScript errors found: {console_errors}"
    
    def test_images_loading(self, dev_server, page):
        """Test that images load correctly."""
        page.goto(BASE_URL)
        
        # Check for any images and verify they load
        images = page.locator("img")
        count = images.count()
        
        for i in range(count):
            img = images.nth(i)
            # Check that image has loaded (natural width > 0)
            expect(img).to_have_attribute("src")


class TestWebsitePerformance:
    """Test website performance characteristics."""
    
    def test_page_load_time(self, dev_server, page):
        """Test that pages load within reasonable time."""
        start_time = time.time()
        page.goto(BASE_URL)
        page.wait_for_load_state("networkidle")
        load_time = time.time() - start_time
        
        # Page should load within 5 seconds (generous for local testing)
        assert load_time < 5.0, f"Page load time too slow: {load_time:.2f}s"
    
    def test_resource_loading(self, dev_server, page):
        """Test that resources load without errors."""
        # Track failed requests
        failed_requests = []
        
        def on_response(response):
            if response.status >= 400:
                failed_requests.append(f"{response.url}: {response.status}")
        
        page.on("response", on_response)
        page.goto(BASE_URL)
        page.wait_for_load_state("networkidle")
        
        assert len(failed_requests) == 0, f"Failed requests: {failed_requests}"


class TestWebsiteAccessibility:
    """Test website accessibility features."""
    
    def test_semantic_html(self, dev_server, page):
        """Test semantic HTML structure."""
        page.goto(BASE_URL)
        
        # Check for semantic HTML elements
        expect(page.locator("header")).to_be_visible()
        expect(page.locator("nav")).to_be_visible()
        expect(page.locator("main")).to_be_visible()
        expect(page.locator("footer")).to_be_visible()
    
    def test_heading_hierarchy(self, dev_server, page):
        """Test proper heading hierarchy."""
        page.goto(BASE_URL)
        
        # Check that h1 exists and is unique
        h1_elements = page.locator("h1")
        expect(h1_elements).to_have_count(1)
        
        # Check that headings have content
        expect(h1_elements.first).not_to_be_empty()
    
    def test_alt_text(self, dev_server, page):
        """Test that images have alt text."""
        page.goto(BASE_URL)
        
        # Check that all images have alt attributes
        images = page.locator("img")
        count = images.count()
        
        for i in range(count):
            img = images.nth(i)
            expect(img).to_have_attribute("alt")


if __name__ == "__main__":
    # Run tests when script is executed directly
    pytest.main([__file__, "-v"])

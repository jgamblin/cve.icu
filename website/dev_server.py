#!/usr/bin/env python3
"""
Development server for CVE.ICU website

A simple HTTP server for testing the generated static website locally.
"""

import os
import sys
import argparse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path


class CVEHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Custom HTTP request handler for the CVE.ICU website."""
    
    def __init__(self, *args, **kwargs):
        # Set the directory to serve files from
        super().__init__(*args, directory=kwargs.pop('directory', None), **kwargs)
    
    def end_headers(self):
        # Add security headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        super().end_headers()
    
    def do_GET(self):
        """Handle GET requests with custom routing."""
        # Handle root path
        if self.path == '/':
            self.path = '/index.html'
        
        # Handle missing .html extension
        if not self.path.endswith(('.html', '.css', '.js', '.png', '.jpg', '.svg', '.ico', '.json', '.xml')):
            if not os.path.exists(os.path.join(self.directory, self.path.lstrip('/'))):
                # Try adding .html extension
                html_path = self.path + '.html'
                if os.path.exists(os.path.join(self.directory, html_path.lstrip('/'))):
                    self.path = html_path
        
        return super().do_GET()
    
    def log_message(self, format, *args):
        """Custom log format."""
        print(f"[{self.log_date_time_string()}] {format % args}")


def main():
    """Main function to start the development server."""
    parser = argparse.ArgumentParser(description="CVE.ICU Development Server")
    parser.add_argument("--port", type=int, default=8000, 
                       help="Port to serve on (default: 8000)")
    parser.add_argument("--host", default="localhost", 
                       help="Host to bind to (default: localhost)")
    parser.add_argument("--directory", default="output",
                       help="Directory to serve (default: output)")
    
    args = parser.parse_args()
    
    # Ensure the output directory exists
    output_dir = Path(args.directory)
    if not output_dir.exists():
        print(f"Error: Directory '{output_dir}' does not exist.")
        print("Please run the website generator first:")
        print("python website/generate_site.py")
        sys.exit(1)
    
    # Check if index.html exists
    index_file = output_dir / "index.html"
    if not index_file.exists():
        print(f"Warning: No index.html found in '{output_dir}'")
        print("The website may not display correctly.")
    
    # Create server
    server_address = (args.host, args.port)
    
    # Create handler with directory
    handler = lambda *args, **kwargs: CVEHTTPRequestHandler(
        *args, directory=str(output_dir.resolve()), **kwargs
    )
    
    httpd = HTTPServer(server_address, handler)
    
    print(f"\\nStarting CVE.ICU Development Server...")
    print(f"Serving directory: {output_dir.resolve()}")
    print(f"Server running at: http://{args.host}:{args.port}/")
    print("Press Ctrl+C to stop the server\\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\\nShutting down server...")
        httpd.shutdown()
        print("Server stopped.")


if __name__ == "__main__":
    main()

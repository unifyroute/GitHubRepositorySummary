#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys
import argparse

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # Map root path to GitHubDashBoard.html
        if path == "/" or path == "":
            path = "/GitHubDashBoard.html"
        return super().translate_path(path)

def run_server(port, directory):
    # Change working directory of the handler to serve from the correct folder.
    # SimpleHTTPRequestHandler accepts a directory argument in Python 3.7+
    handler = lambda *args, **kwargs: DashboardHandler(*args, directory=directory, **kwargs)
    
    # Enable address reuse to avoid "Address already in use" errors on restart
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"\n==================================================")
        print(f"[*] GitHub Repository Dashboard Server")
        print(f"==================================================")
        print(f"Serving from directory: {os.path.abspath(directory)}")
        print(f"Dashboard URL:          http://localhost:{port}/")
        print(f"==================================================")
        print("Press Ctrl+C to stop the server.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Serve the GitHub Repository Dashboard")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on (default: 8000)")
    parser.add_argument("--dir", default=None, help="Directory containing GitHubDashBoard.html (defaults to auto-detect)")
    args = parser.parse_args()
    
    target_dir = args.dir
    
    # Auto-detection logic if no directory was provided
    if not target_dir:
        # Check standard default dirs
        if os.path.isdir("20260806"):
            target_dir = "20260806"
        elif os.path.isdir("output"):
            target_dir = "output"
        else:
            # Find any 8-digit date directory (YYYYMMDD format)
            subdirs = [d for d in os.listdir(".") if os.path.isdir(d) and d.isdigit() and len(d) == 8]
            if subdirs:
                target_dir = sorted(subdirs)[-1]
            else:
                target_dir = "."
                
    # Validate directory
    if not os.path.isdir(target_dir):
        print(f"Error: Directory '{target_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)
        
    # Check if dashboard file is present
    dashboard_path = os.path.join(target_dir, "GitHubDashBoard.html")
    if not os.path.isfile(dashboard_path):
        print(f"Warning: 'GitHubDashBoard.html' not found in '{target_dir}'.", file=sys.stderr)
        print("Make sure you run the scanner and generate the dashboard first.", file=sys.stderr)
        
    run_server(args.port, target_dir)

#!/usr/bin/env python3
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

segment = sys.argv[1] if len(sys.argv) > 1 else "unknown"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        response_body = f"Hello from segment: {segment}\n".encode("utf-8")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format, *args):
        # Silence access logging to keep stdout clean
        pass

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

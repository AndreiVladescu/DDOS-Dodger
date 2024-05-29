import http.server
import socketserver

PORT = 8000

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)  # Send OK HTTP response
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write("Hello".encode())  # Send the response body

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("Server serving at port", PORT)
    httpd.serve_forever()
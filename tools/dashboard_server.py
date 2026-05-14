import http.server
import socketserver
import json
import os
import csv
from urllib.parse import urlparse

PORT = 8000
DIRECTORY = "dashboard"

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/api/alerts":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            alerts = []
            file_path = "out/alerts_stream.csv"
            if os.path.exists(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            alerts.append(row)
                except Exception as e:
                    print(f"Error reading alerts_stream.csv: {e}")
            
            self.wfile.write(json.dumps(alerts).encode("utf-8"))
            
        elif parsed_path.path == "/api/clear":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            file_path = "out/alerts_stream.csv"
            success = True
            try:
                # Ensure the parent directory exists
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                # Truncate or create the file and write only the CSV header.
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("incident_id,event_id,timestamp,src_ip,dst_ip,asset_role,protocol,classification,top_severity,asset_criticality,threat_severity,confidence_score,risk_score,latency_ms,verdict,reasons\n")
            except Exception as e:
                print(f"Error truncating file: {e}")
                success = False
            
            self.wfile.write(json.dumps({"success": success}).encode("utf-8"))
        else:
            # Serve static files normally
            super().do_GET()

def main():
    # Ensure dashboard directory exists
    os.makedirs(DIRECTORY, exist_ok=True)
    
    # Check if index.html is there, if not log warning
    if not os.path.exists(os.path.join(DIRECTORY, "index.html")):
        print(f"Warning: dashboard/index.html not found. Place your index.html in the '{DIRECTORY}' folder.")

    handler = DashboardHandler
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"=================================================================")
        print(f" ThreatFusion AI - OT/ICS Premium Security Dashboard Server")
        print(f" Running locally at: http://localhost:{PORT}")
        print(f"=================================================================")
        print("Press Ctrl+C to terminate the dashboard server.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nDashboard server stopped.")

if __name__ == "__main__":
    main()

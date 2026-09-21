# reports/report_generator.py
import json
from datetime import datetime

def generate_html_report(results, filename="report.html"):
    """Generate HTML vulnerability report"""
    # Create a simple HTML table with findings
    pass

def generate_json_report(results, filename="report.json"):
    """Export to JSON for further processing"""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)


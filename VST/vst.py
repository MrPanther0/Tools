import re
import requests
import subprocess
import logging
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(filename="scan_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

def log_scan_start(url):
    logging.info(f"Started scanning URL: {url}")

def log_scan_result(url, vulnerabilities):
    logging.info(f"Scan result for {url}: {vulnerabilities}")

def log_scan_end(url):
    logging.info(f"Scan finished for URL: {url}")

def validate_url(url):
    """Validate the input URL."""
    pattern = re.compile(
        r'^(http|https)://([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:[0-9]{1,5})?(/.*)?$')
    return pattern.match(url)

def scan_sql_injection(url):
    """Check for SQL Injection vulnerability."""
    payload = "' OR '1'='1"
    test_url = f"{url}?id={payload}"
    try:
        response = requests.get(test_url, timeout=5)
        # Look for keywords indicating SQL errors or check if the response is different
        if "error" in response.text.lower() or "syntax" in response.text.lower() or len(response.text) != len(requests.get(url).text):
            return True
    except requests.RequestException:
        pass
    return False

def scan_xss(url):
    """Check for XSS vulnerability."""
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?q={payload}"
    try:
        response = requests.get(test_url, timeout=5)
        # Check if payload appears in the response text (basic check for XSS)
        if payload in response.text:
            return True
    except requests.RequestException:
        pass
    return False

def analyze_http_headers(url):
    """Analyze HTTP security headers."""
    headers_to_check = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]
    findings = {}
    try:
        response = requests.get(url, timeout=5)
        for header in headers_to_check:
            findings[header] = response.headers.get(header, "Not Set")
    except requests.RequestException:
        return None
    return findings

def scan_open_ports(host):
    """Scan for open ports using Nmap."""
    try:
        result = subprocess.check_output(
            ["nmap", "-p", "80,443", "-sV", "-T4", "--script=http-title,http-headers,ssl-enum-ciphers", host], 
            universal_newlines=True)
        return result
    except subprocess.CalledProcessError:
        return "Nmap scan failed. Check if Nmap is installed and try again."
    except FileNotFoundError:
        return "Nmap is not installed. Please install Nmap to proceed."

def calculate_security_score(vulnerabilities):
    """Calculate the security score based on the severity of vulnerabilities."""
    score = 100
    severity_weights = {"High": 40, "Medium": 20, "Low": 5}

    for vuln in vulnerabilities:
        if vuln["severity"] == "High":
            score -= severity_weights["High"]
        elif vuln["severity"] == "Medium":
            score -= severity_weights["Medium"]
        elif vuln["severity"] == "Low":
            score -= severity_weights["Low"]

    return max(0, score)  # Ensure the score doesn't go below 0

def generate_report(url, sql_result, xss_result, header_results, nmap_result, security_score):
    """Generate an HTML report with enhanced styling."""
    report_content = f"""
    <html>
    <head>
        <title>Vulnerability Scanner Report</title>
        <link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
        <div class="container">
            <h1>Vulnerability Scanner Report</h1>
            <h2>Target URL: {url}</h2>
            <h3>Security Score: {security_score}</h3>
            <div class="section">
                <h3>SQL Injection:</h3>
                <p class="result">{'Vulnerable' if sql_result else 'Not Vulnerable'}</p>
            </div>
            <div class="section">
                <h3>Cross-Site Scripting (XSS):</h3>
                <p class="result">{'Vulnerable' if xss_result else 'Not Vulnerable'}</p>
            </div>
            <div class="section">
                <h3>HTTP Headers Analysis:</h3>
    """
    
    if header_results:
        report_content += "<ul>"
        for header, value in header_results.items():
            report_content += f"<li>{header}: {value}</li>"
        report_content += "</ul>"
    else:
        report_content += "<p>Could not retrieve HTTP headers or no headers set.</p>"

    report_content += f"""
            </div>
            <div class="section">
                <h3>Open Ports:</h3>
                <pre>{nmap_result}</pre>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Save the report with dynamic file names based on the website
    filename = url.split("//")[-1].split("/")[0]
    filename = filename.replace(".", "_")

    count = 1
    report_filename = f"{filename}_report.html"  # Initialize the report_filename outside the loop

    while True:
        # Check if the file already exists, and if so, increment the count
        try:
            with open(report_filename, "w") as file:
                file.write(report_content)
            
            print(f"Saving report as: {report_filename}")  # Now print after successful assignment
            break
        except Exception as e:
            print(f"Error: {e}")
            count += 1
            report_filename = f"{filename}_report_{count}.html"  # Increment count and retry


def main():
    url = input("Enter the target URL (e.g., http://example.com): ").strip()
    
    if not validate_url(url):
        print("Invalid URL. Please enter a valid web application URL.")
    else:
        log_scan_start(url)  # Log scan start
        print("\nStarting scans...\n")
        
        sql_result = scan_sql_injection(url)
        print(f"SQL Injection: {'Vulnerable' if sql_result else 'Not Vulnerable'}")

        xss_result = scan_xss(url)
        print(f"Cross-Site Scripting (XSS): {'Vulnerable' if xss_result else 'Not Vulnerable'}")

        print("\nAnalyzing HTTP headers...")
        header_results = analyze_http_headers(url)
        if header_results:
            for header, value in header_results.items():
                print(f"{header}: {value}")
        else:
            print("Could not retrieve HTTP headers.")

        print("\nScanning open ports...")
        nmap_result = scan_open_ports(url.split("//")[-1].split("/")[0])
        print(nmap_result)

        # Log scan result
        vulnerabilities = [
            {"type": "SQL Injection", "severity": "High" if sql_result else "Low"},
            {"type": "XSS", "severity": "Medium" if xss_result else "Low"},
            {"type": "HTTP Headers", "severity": "Medium" if header_results else "Low"},
            {"type": "Nmap Results", "severity": "Low" if "open" not in nmap_result else "Medium"}
        ]
        
        # Calculate the security score
        security_score = calculate_security_score(vulnerabilities)

        # Generate the report with the score
        generate_report(url, sql_result, xss_result, header_results, nmap_result, security_score)

        # Log scan end
        log_scan_end(url)
        
        print(f"Security Score: {security_score}")
        print("\nReport saved with a dynamic filename based on the website.")


if __name__ == "__main__":
    main()

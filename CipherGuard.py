import os
import re
import argparse
import subprocess
import json

# ANSI escape codes for coloring
RED = "\033[91m"   # Red for weak ciphers
GREEN = "\033[92m" # Green for strong ciphers
BLUE = "\033[94m"  # Blue for strong cipher recommendations
YELLOW = "\033[93m" # Yellow for config paths
RESET = "\033[0m"  # Reset to default color

# Vulnerability mappings for ciphers
vulnerabilities = {
    "CBC": "Cipher Block Chaining (CBC) mode vulnerabilities are Padding Oracle Attack, BEAST Attack ,Chosen Ciphertext Attacks,CRIME",
    "RSA": "Potential vulnerabilities related to RSA key exchange, Bleichenbacher's Attack, Common Modulus Attack",
    "NULL": "Null cipher; no encryption",
    "EXPORT": "Export ciphers; weak due to limited key size",
    "3DES": "Triple DES; Weak due to small block size, Sweet32 Attack,Meet-in-the-Middle Attack",
    "RC4": "RC4 stream cipher vulnerabilities, Key Recovery Attacks,Bias in Output, Key Reuse, Rogue Key Recovery",
    }

# Dictionary of server types and corresponding cipher configuration paths
server_config_paths = {
    'Apache': '/etc/apache2/apache2.conf or /etc/httpd/conf/httpd.conf',
    'Nginx': '/etc/nginx/nginx.conf or /etc/nginx/sites-available/default',
    'IIS': 'Windows Registry: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers',
    'HAProxy': '/etc/haproxy/haproxy.cfg',
    'Tomcat': '/etc/tomcat/server.xml',
    'Postfix': '/etc/postfix/main.cf',
    'Dovecot': '/etc/dovecot/conf.d/10-ssl.conf',
    'OpenSSL': '/etc/ssl/openssl.cnf',
    'Lighttpd': '/etc/lighttpd/lighttpd.conf',
    'Node.js (Express)': 'app.js (or equivalent server file)',
    'Caddy': '/etc/caddy/Caddyfile',
    'Oracle WebLogic': '/path/to/your/weblogic/config.xml',
    'JBoss': '/path/to/your/jboss/standalone/configuration/standalone.xml',
    'GlassFish': '/path/to/your/glassfish/domains/domain1/config/domain.xml',
    'PostgREST': '/etc/postrest/config.yaml',
    'Envoy': '/etc/envoy/envoy.yaml',
    'Microsoft Azure': 'Azure Portal: Networking > SSL settings',
    'OpenResty': '/usr/local/openresty/nginx/conf/nginx.conf',
    'Varnish': '/etc/varnish/default.vcl',
    'Kubernetes Ingress': '/etc/kubernetes/ingress/ingress.yaml',
    'Squid Proxy': '/etc/squid/squid.conf',
    'Apache HTTP Server (Windows)': 'C:\\Program Files (x86)\\Apache Group\\Apache2\\conf\\httpd.conf',
    'Citrix ADC (NetScaler)': '/nsconfig/ssl/ssl.conf',
    'NGINX Unit': '/etc/unit/config.json',
    'Haproxy (Windows)': 'C:\\Program Files\\haproxy\\haproxy.cfg',
    'Tengine': '/etc/nginx/nginx.conf',
    'Resin': '/path/to/your/resin/conf/resin.xml',
    'WebSphere': '/opt/IBM/WebSphere/AppServer/profiles/your_profile/config/cells/your_cell_name/nodes/your_node_name/servers/your_server_name/server.xml',
    'Plesk': '/usr/local/psa/admin/conf/ssl.conf',
    'AWS Elastic Load Balancer': 'AWS Console > Load Balancers > [Your Load Balancer] > Listeners',
    'Apache Traffic Server': '/etc/trafficserver/records.config',
    'Traefik': '/etc/traefik/traefik.toml',
    'Zebra': '/etc/zebra/zebra.conf',
    'F5 BIG-IP': '/etc/ssl/ssl.conf',
    'A10 Networks': '/config/a10.conf',
    'OpenVPN': '/etc/openvpn/server.conf',
    'Coyote': '/path/to/coyote.conf',
    'SonicWall': 'Management Console > SSL Settings',
    'Lightwave': '/opt/lw/bin/lw_config',
    'Pound': '/etc/pound/pound.cfg',
    'Cloudflare': 'Cloudflare Dashboard > SSL/TLS settings',
    'HAProxy (Docker)': '/usr/local/etc/haproxy/haproxy.cfg',
    'Caddy (Windows)': 'C:\\Caddy\\Caddyfile',
    'nginx (Windows)': 'C:\\nginx\\conf\\nginx.conf',
    'GWS': 'Configuration typically handled by Google Cloud Platform (no direct access)',
}

# Strong cipher recommendations
strong_ciphers = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305",
    "TLS_AES_128_CCM_8_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_ECCPWD_WITH_AES_128_CCM_SHA256",
    "TLS_ECCPWD_WITH_AES_256_CCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"
]

# Function to perform SSL enumeration using Nmap
# Function to perform SSL enumeration using Nmap 
def ssl_enum(target, port=443):
    nmap_command = f"nmap --script ssl-enum-ciphers -p {port} {target}"
    process = os.popen(nmap_command)
    output = process.read()
    process.close()
    return output

# Function to identify the server type
def identify_server(target):
    # Step 1: Try to detect server from HTTP response headers
    response = subprocess.run(['curl', '-I', target], capture_output=True, text=True)
    server_header = next((line for line in response.stdout.splitlines() if line.startswith('Server:')), None)
    if server_header:
        return server_header.split(': ')[1]

    # Step 2: If 'Server' header not found, fetch full response to analyze patterns
    full_response = subprocess.run(['curl', '-s', target], capture_output=True, text=True)
    
    # Common server-specific response patterns
    response_body = full_response.stdout.lower()
    
    # Step 3: List of known server types for detection without paths
    server_types = {
        'Apache': 'Apache',
        'Nginx': 'Nginx',
        'IIS': 'Microsoft IIS',
        'HAProxy': 'HAProxy',
        'Tomcat': 'Tomcat',
        'Postfix': 'Postfix',
        'Dovecot': 'Dovecot',
        'OpenSSL': 'OpenSSL',
        'Lighttpd': 'Lighttpd',
        'Node.js': 'Node.js (Express)',
        'Caddy': 'Caddy',
        'Oracle WebLogic': 'Oracle WebLogic',
        'JBoss': 'JBoss',
        'GlassFish': 'GlassFish',
        'PostgREST': 'PostgREST',
        'Envoy': 'Envoy',
        'Microsoft Azure': 'Microsoft Azure',
        'OpenResty': 'OpenResty',
        'Varnish': 'Varnish',
        'Kubernetes Ingress': 'Kubernetes Ingress',
        'Squid Proxy': 'Squid Proxy',
        'Apache HTTP Server (Windows)': 'Apache HTTP Server (Windows)',
        'Citrix ADC (NetScaler)': 'Citrix ADC (NetScaler)',
        'NGINX Unit': 'NGINX Unit',
        'Tengine': 'Tengine',
        'Resin': 'Resin',
        'WebSphere': 'WebSphere',
        'Plesk': 'Plesk',
        'AWS Elastic Load Balancer': 'AWS Elastic Load Balancer',
        'Apache Traffic Server': 'Apache Traffic Server',
        'Traefik': 'Traefik',
        'Zebra': 'Zebra',
        'F5 BIG-IP': 'F5 BIG-IP',
        'A10 Networks': 'A10 Networks',
        'OpenVPN': 'OpenVPN',
        'Coyote': 'Coyote',
        'SonicWall': 'SonicWall',
        'Lightwave': 'Lightwave',
        'Pound': 'Pound',
        'Cloudflare': 'Cloudflare',
        'HAProxy (Docker)': 'HAProxy (Docker)',
        'Caddy (Windows)': 'Caddy (Windows)',
        'nginx (Windows)': 'nginx (Windows)',
        'GWS': 'GWS'
    }
    
    # Step 4: Check the response body for any known server types
    for server_name in server_types:
        if server_name.lower() in response_body:
            return server_types[server_name]
    
    # Step 5: If response body doesn't help, attempt to detect via Nmap based on open ports
    nmap_command = f"nmap -sV {target}"
    process = os.popen(nmap_command)
    output = process.read()
    process.close()
    
    # Look for the version info in the nmap output
    version_info = re.search(r"^\d+/tcp\s+open\s+(\S+)\s+(\S+)", output, re.MULTILINE)
    if version_info:
        return f"{version_info.group(1)} {version_info.group(2)}"
    
    # Step 6: If no info found, return "Unknown"
    return "Unknown"
# Function to find ciphers from the Nmap output
def find_ciphers(nmap_output):
    ciphers = []
    cipher_pattern = re.compile(r"^\s*(.*?)(weak|insecure|deprecated|strong|secure|CBC|DHE|RSA)(.*)$", re.IGNORECASE)

    for line in nmap_output.splitlines():
        if cipher_pattern.search(line):
            ciphers.append(line.strip())
    
    return ciphers

# Function to classify ciphers
def classify_ciphers(ciphers):
    weak_ciphers = []
    strong_ciphers = []
    
    for cipher in ciphers:
        if any(weak_term in cipher for weak_term in ["CBC", "RSA"]) and "ECDHE" not in cipher:
            weak_ciphers.append(cipher)
        elif "ECDHE" in cipher and ("GCM" in cipher or "POLY" in cipher):
            strong_ciphers.append(cipher)
        else:
            weak_ciphers.append(cipher)  # Default to weak for all others

    return weak_ciphers, strong_ciphers

# Function to read OpenSSL names from JSON
def read_openssl_mapping(json_file):
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        openssl_mapping = {}
        
        for item in data:
            # Handle the new keys "Name (OpenSSL)" and "Cipher Suite Name (IANA)"
            openssl_name = item.get('Name (OpenSSL)', None)
            iana_name = item.get('Cipher Suite Name (IANA)', None)
            
            if openssl_name and iana_name:
                openssl_mapping[iana_name.strip()] = openssl_name.strip()  # Store exact names
            else:
                print(f"Warning: Skipping entry due to missing keys: {item}")  # Log skipped entry

        return openssl_mapping
    except FileNotFoundError:
        print(f"Error: The file '{json_file}' was not found.")
        exit(1)
    except json.JSONDecodeError:
        print(f"Error: The file '{json_file}' is not a valid JSON file.")
        exit(1)

# Function to match IANA names with OpenSSL names
def match_iana_to_openssl(iana_name, openssl_mapping):
    # Clean the IANA cipher name to remove non-alphanumeric characters
    cleaned_iana_name = re.sub(r'[^A-Za-z0-9_ ]+', '', iana_name.strip()).lower()
    
    # Try to find exact or partial matches
    for key, openssl_name in openssl_mapping.items():
        cleaned_key = re.sub(r'[^A-Za-z0-9_ ]+', '', key.strip()).lower()
        
        if cleaned_iana_name == cleaned_key:
            return openssl_name
            
        if cleaned_iana_name in cleaned_key or cleaned_key in cleaned_iana_name:
            return openssl_name
    
    return "Not found in JSON"

# Function to get server configuration path based on server type
def get_server_config_path(server_type):
    for server, config_path in server_config_paths.items():
        if server.lower() in server_type.lower():
            return YELLOW + config_path + RESET  # Add coloring to the path
    return "Configuration path not found for the detected server."

if __name__ == "__main__":
    # Argument parser for command-line flags
    parser = argparse.ArgumentParser(description="SSL Enumeration using Nmap")
    parser.add_argument('-u', '--url', required=True, help='Target domain or IP address')
    parser.add_argument('-p', '--port', default='443', help='Port (default is 443)')
    parser.add_argument('-j', '--json', required=True, help='Path to JSON file containing OpenSSL and IANA cipher mappings')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Identify the server type
    server_type = identify_server(args.url)
    print(f"\nDetected Server Type: {server_type}\n")

    # Get server configuration path based on the detected server type
    config_path = get_server_config_path(server_type)
    print(f"Configuration path for {server_type}: {config_path}\n")

    # Perform SSL enumeration
    print(f"Performing SSL enumeration on {args.url} at port {args.port}...\n")
    ssl_result = ssl_enum(args.url, args.port)
    print(ssl_result)

    # Find ciphers
    ciphers = find_ciphers(ssl_result)

    if ciphers:
        print("\nCiphers Found:")
        weak_ciphers, strong_ciphers = classify_ciphers(ciphers)
        
        if strong_ciphers:
            print(f"\nApplication is using strong ciphers:")
            for cipher in strong_ciphers:
                print(GREEN + cipher + RESET)  # Strong ciphers in green

        if weak_ciphers:
            print("\nWeak ciphers are present:")
            for cipher in weak_ciphers:
                print(RED + cipher + RESET)
            
            # List down strong cipher recommendations if weak ciphers are found
            print("\n**Recommendations:**")
            print("It is highly recommended to use the following strong ciphers:")
            for cipher in strong_ciphers:
                print(BLUE + f"- {cipher}" + RESET)  # Recommendations in blue

        # Read OpenSSL names from JSON
        openssl_mapping = read_openssl_mapping(args.json)

        print("\nMatching ciphers to OpenSSL Names from JSON:")
        for cipher in weak_ciphers:
            iana_name = cipher.strip()  # Clean up the cipher name
            
            # Check if IANA name exists in the mapping (exact or partial match)
            matching_openssl_name = match_iana_to_openssl(iana_name, openssl_mapping)
            print(f"{iana_name} => {matching_openssl_name}")

        # Unique vulnerabilities for weak ciphers

if weak_ciphers:
    vulnerability_set = set()  # Use a set to track unique vulnerabilities
    for cipher in weak_ciphers:
        for term in vulnerabilities:
            if term in cipher:
                vulnerability_set.add(vulnerabilities[term])
    
    # ANSI escape code for red text
    red_color = "\033[91m"
    reset_color = "\033[0m"

    print("\nIdentified Vulnerabilities: " + red_color + ", ".join(vulnerability_set) + reset_color)  # Print unique vulnerabilities in red
else:
    print("\nNo ciphers found.")



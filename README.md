![image](https://github.com/user-attachments/assets/97b5c279-1619-4d5a-8b70-18b6d7c3f420)CipherGuard

CipherGuard is a comprehensive command-line tool for SSL enumeration and cipher analysis, designed to help security professionals identify weak ciphers and enhance server security configurations. This tool leverages Nmap for enumeration, detects server types, and provides strong cipher recommendations based on industry standards.

Features
SSL Enumeration: Uses Nmap to scan and enumerate supported SSL/TLS ciphers on the target server.
Server Identification: Automatically detects the type of web server based on HTTP response headers or port information.
Vulnerability Mapping: Identifies potential vulnerabilities associated with weak ciphers.
Strong Cipher Recommendations: Suggests strong ciphers to replace weak ones for better security.
Config Path Retrieval: Provides recommended configuration paths based on detected server types.
Installation
Clone the repository:

git clone https://github.com/Have-Faith-ctrl/CipherGuard.git

cd CipherGuard
Install dependencies: Ensure you have Python and Nmap installed on your machine.

pip install python-nmap
pip install requests
pip install cryptography


Run CipherGuard with the following command:

python cipherguard.py -u <target_url> -p <port> -j <json_file>


Parameters
-u or --url: Target domain or IP address (required).
-p or --port: Port to scan (default is 443).
-j or --json: Path to the JSON file containing OpenSSL and IANA cipher mappings (required).


python cipherguard.py -u example.com -p 443 -j openssl_mappings.json


Detected server type
Server configuration path
List of found ciphers categorized as weak or strong
Unique vulnerabilities associated with weak ciphers
Vulnerability Mappings
CipherGuard identifies potential vulnerabilities associated with certain ciphers, including but not limited to

![image](https://github.com/user-attachments/assets/cca3d84a-ed75-4efa-9d05-f9a6d18aec95)
![image](https://github.com/user-attachments/assets/c1988726-e01a-49d0-8b84-3f74b1690964)
![image](https://github.com/user-attachments/assets/bb2697df-c8f2-4566-b577-d6a77ce3811c)







CipherGuard

CipherGuard is a comprehensive command-line tool for SSL enumeration and cipher analysis, designed to help security professionals identify weak ciphers and enhance server security configurations. This tool leverages Nmap for enumeration, detects server types, and provides strong cipher recommendations based on industry standards.

Features
SSL Enumeration: Uses Nmap to scan and enumerate supported SSL/TLS ciphers on the target server.
Server Identification: Automatically detects the type of web server based on HTTP response headers or port information.
Vulnerability Mapping: Identifies potential vulnerabilities associated with weak ciphers.
Strong Cipher Recommendations: Suggests strong ciphers to replace weak ones for better security.
Config Path Retrieval: Provides recommended configuration paths based on detected server types.
Installation
Clone the repository:

git clone https://github.com/Have-Faith-ctrl/CipherGuard

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
CipherGuard identifies potential vulnerabilities associated with certain ciphers
Also provide OPENSSL Name for the Cipher Suite Name (IANA)

![image](https://github.com/user-attachments/assets/d888fb97-7ab1-44d1-9303-ae007eff799a)
![image](https://github.com/user-attachments/assets/14f886a5-e0c3-45cf-bc43-9a8e7b2cee22)
![image](https://github.com/user-attachments/assets/7970cfc3-404c-46bb-ac1c-de1ef215f105)




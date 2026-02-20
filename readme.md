![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)


NetHawk Enterprise | Advanced Port Scanner
NetHawk Enterprise is a high-performance, multi-threaded network intelligence tool built with Python. It features a modern GUI developed with Tkinter, allowing users to scan for open ports, identify services, and export findings efficiently.

🚀 Features
High-Speed Scanning: Utilizes ThreadPoolExecutor for concurrent, multi-threaded port analysis.

Pre-defined Profiles: Easily scan Well-Known (1-1024), Registered (1024-49151), or Full (1-65535) port ranges.

Service Identification: Automatically attempts to resolve the service protocol (e.g., HTTP, FTP, SSH) for open ports.

Data Export: Save your scan results directly to a CSV file for documentation and reporting.

Modern UI: Clean, professional interface with real-time progress tracking and status updates.

🛠️ Installation
Clone the Repository:

Bash
git clone https://github.com/hassaanshakeel1/NetHawk-Enterprise.git
cd NetHawk-Enterprise
Ensure Python is Installed:
This tool requires Python 3.x. You can check your version by running:

Bash
python --version
💻 Usage
Launch the Tool:
Run the script using the following command:

Bash
python "port scanner.py"
Configure Your Scan:

Target: Enter the IP address or URL (e.g., scanme.nmap.org).

Profile: Select a scan range from the dropdown menu.

Threads: Adjust the number of threads (Default: 300) to balance speed and system stability.

Start Scanning:
Click ▶ Start Scan. Open ports will appear in the table in real-time.

Export Results:
Once the scan is finished or stopped, click 💾 Export CSV to save your results.

⚠️ Disclaimer
This tool is developed for educational and ethical security testing purposes only. Unauthorized scanning of networks is illegal and unethical. The developer, Hassaan Shakeel, is not responsible for any misuse of this software.

👤 Author
Developed by: Hassaan Shakeel

Project: NetHawk Enterprise Network Intelligence Tool

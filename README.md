# SecScan Automator

A comprehensive security scanning automation tool that combines the power of Nmap and SQLmap. This terminal-based application provides an elegant, colorful, and user-friendly interface to perform a wide variety of security scans and attacks.

## Features

- **Unified Interface**: Combines Nmap and SQLmap functionalities in a single tool
- **User-Friendly Menus**: Colorful, readable terminal menus for easy navigation
- **Comprehensive Scanning Options**:
  - 22 different Nmap scanning functions with detailed descriptions
  - 22 different SQLmap attack options with detailed descriptions
- **Parameter Management**: Customizable parameters for all scan types
- **Error Handling**: Provides retry options for incorrect inputs
- **Logging System**: All scan results are saved with timestamps
- **Log Management**: View, rename, or delete log files directly from the tool
- **Security Tips**: Shows random security tips during navigation
- **Modular Design**: Clean, well-structured Python code for easy maintenance

## Prerequisites

- Python 3.6+
- Nmap
- SQLmap
- Colorama (Python package)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/mikropsoft/Security-Scan-Automator.git
cd Security-Scan-Automator
```

2. Install required Python packages:
```bash
pip install colorama
```

3. Ensure Nmap and SQLmap are installed on your system:

For Debian/Ubuntu:
```bash
sudo apt update
sudo apt install nmap
sudo apt install sqlmap
```

For CentOS/RHEL:
```bash
sudo yum install nmap
sudo yum install sqlmap
```

For macOS (using Homebrew):
```bash
brew install nmap
brew install sqlmap
```

## Usage

Run the tool with:

```bash
python secscan_automator.py
```

### Main Menu Options:

1. **Nmap Scanning Options** - Perform various network reconnaissance scans
2. **SQLmap Attack Options** - Perform SQL injection tests and attacks
3. **Log Management** - View, rename, or delete scan logs

### Nmap Scanning Options:

The tool offers 22 different Nmap scan options including:
- Quick scans
- Intense scans
- Service detection
- OS fingerprinting
- Vulnerability scanning
- Firewall evasion techniques
- And more...

### SQLmap Attack Options:

Various SQLmap attack options including:
- Basic GET/POST request scans
- Database enumeration
- Table dumping
- WAF bypass techniques
- Advanced injection techniques
- Shell access attempts
- And more...

## Important Security Note

This tool is intended for legitimate security testing only. Always ensure you have proper authorization before scanning any systems or networks. Unauthorized scanning may be illegal and is against ethical guidelines.

## Log Management

All scan results are automatically saved to timestamped log files in the `security_tool_logs` directory. The tool provides options to:
- View logs
- Rename log files
- Delete log files

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and legitimate security testing purposes only. The authors are not responsible for any misuse or damage caused by this program.

## Author

Holi - [GitHub Profile](https://github.com/mikropsoft)

## Acknowledgments

- The Nmap Security Scanner team
- The SQLmap development team
- Contributors to the Colorama Python package

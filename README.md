## SecScan Automator

A powerful, modular, and user-friendly Python tool for managing, automating, and reporting on security scans with advanced configuration, validation, and reporting capabilities.

---

**Features**

- **Robust Input Validation:** Comprehensive validation for IPs, URLs, domains, and filenames to prevent user errors and ensure data integrity.
- **Persistent Configuration Management:** Easily customizable settings with auto-backup and advanced options (themes, concurrent scans, report formats, etc.).
- **Integrated SQLite Database:** Tracks scan histories, reports, vulnerabilities, targets, and error logs for full auditability.
- **Scan Templates:** Predefined and categorized scan templates for Nmap and SQLMap (easy, medium, hard), supporting both quick and advanced security assessments.
- **Advanced Progress Bar:** Real-time, visually appealing progress feedback with ETA and sub-step tracking.
- **Comprehensive Reporting:** Generates HTML, TXT, and JSON reports with metadata, scan results, and statistics.
- **Quote of the Day:** Motivational and security-related daily quotes for a touch of inspiration.
- **Error Logging and Data Cleanup:** Automatic error tracking and periodic cleanup of old data for smooth operation.
- **Thread-Safe Operations:** All critical operations are thread-safe, supporting concurrent scans and database access.

---

## Installation

```bash
git clone https://github.com/mikropsoft/Security-Scan-Automator.git
cd Security-Scan-Automator
```

---

## Usage

```bash
python3 secscan_automator.py
```

- Configure your preferences in `secscan_config.json` or via the interactive menu.
- Start a scan, select a scan template (Nmap or SQLMap), and monitor progress in real time.
- View or export reports from the `reports/` directory.
- All scan history, targets, and vulnerabilities are tracked in `secscan.db`.

---

## Main Modules

| Module             | Description                                                             |
|--------------------|-------------------------------------------------------------------------|
| `InputValidator`   | Validates user inputs for menu, IP, URL, domains, and filenames         |
| `ConfigManager`    | Manages persistent and backup-able configuration settings               |
| `DatabaseManager`  | Handles all database operations (scans, reports, targets, errors, etc.) |
| `ScanTemplates`    | Provides categorized Nmap/SQLMap scan templates                        |
| `AdvancedProgressBar` | Displays animated, colored progress bar with ETA and sub-steps       |
| `ReportManager`    | Generates HTML, TXT, and JSON reports                                   |
| `QuoteGenerator`   | Displays a daily security quote                                         |

---

## Reporting

- Reports are automatically generated after each scan and saved in the `reports/` directory.
- Supports HTML, TXT, and JSON formats for easy sharing and integration.
- All report metadata and statistics are stored in the database for future reference.

---

## Requirements

- Python 3.7+
- Standard Python libraries (sqlite3, threading, json, etc.)
- Nmap, SQLMap (if using scan templates)

---

## License

MIT License 

---

## Contributing

Pull requests are welcome! Please open an issue first to discuss your ideas.

---

## Acknowledgements

- Inspired by best practices in penetration testing and security automation.
- Uses open-source tools and libraries for maximum flexibility and reliability.

---

**Stay secure and keep testing!**

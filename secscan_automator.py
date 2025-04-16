#!/usr/bin/env python3

import os
import sys
import subprocess
import datetime
import time
import random
import shutil
import re
from colorama import init, Fore, Back, Style

init(autoreset=True)

class SecurityTool:
    def __init__(self):
        self.logs_dir = "security_tool_logs"
        self.create_logs_directory()
        self.terminal_width = shutil.get_terminal_size().columns
        self._last_header = None
        self._last_prompt = None
        
        self.security_tips = [
            "Always keep your systems and tools updated to the latest version.",
            "Use strong, unique passwords for all your accounts.",
            "Implement network segmentation to limit the impact of breaches.",
            "Regularly back up your important data and test your backups.",
            "Always perform security testing with proper authorization.",
            "Use VPNs when connecting to public networks.",
            "Be cautious of phishing attempts and suspicious emails.",
            "Implement multi-factor authentication where possible.",
            "Regularly audit your systems for vulnerabilities.",
            "Educate yourself and your team about security best practices.",
            "Keep your security tools and signatures up to date.",
            "Document your network configuration and changes.",
            "Use the principle of least privilege for access control.",
            "Encrypt sensitive data both at rest and in transit.",
            "Monitor your network for unusual activities.",
            "Have an incident response plan ready before you need it.",
            "Perform regular penetration testing on your infrastructure.",
            "Be aware of social engineering techniques used by attackers.",
            "Disable unnecessary services and close unused ports.",
            "Remember that security is a continuous process, not a one-time task."
        ]
    
    def create_logs_directory(self):
        if not os.path.exists(self.logs_dir):
            os.makedirs(self.logs_dir)
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def check_dependencies(self):
        missing_tools = []
        
        try:
            nmap_version = subprocess.check_output(["nmap", "--version"], 
                                                stderr=subprocess.STDOUT,
                                                text=True)
            print(f"{Fore.GREEN}✓ Nmap found: {nmap_version.split()[2]}{Style.RESET_ALL}")
        except (subprocess.SubprocessError, FileNotFoundError):
            missing_tools.append("Nmap")
        
        try:
            sqlmap_process = subprocess.Popen(["sqlmap", "--version"],
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           text=True)
            sqlmap_out, _ = sqlmap_process.communicate()
            print(f"{Fore.GREEN}✓ SQLmap found{Style.RESET_ALL}")
        except (subprocess.SubprocessError, FileNotFoundError):
            missing_tools.append("SQLmap")
        
        if missing_tools:
            print(f"{Fore.RED}Error: The following required tools are missing:{Style.RESET_ALL}")
            for tool in missing_tools:
                print(f"{Fore.RED}  - {tool}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please install the missing tools and try again.{Style.RESET_ALL}")
            return False
        return True
    
    def print_banner(self):
        self.clear_screen()
        banner = f"""
{Fore.CYAN}███████╗███████╗ ██████╗███████╗ ██████╗ █████╗ ███╗   ██╗{Style.RESET_ALL}
{Fore.CYAN}██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║{Style.RESET_ALL}
{Fore.CYAN}███████╗█████╗  ██║     ███████╗██║     ███████║██╔██╗ ██║{Style.RESET_ALL}
{Fore.CYAN}╚════██║██╔══╝  ██║     ╚════██║██║     ██╔══██║██║╚██╗██║{Style.RESET_ALL}
{Fore.CYAN}███████║███████╗╚██████╗███████║╚██████╗██║  ██║██║ ╚████║{Style.RESET_ALL}
{Fore.CYAN}╚══════╝╚══════╝ ╚═════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Style.RESET_ALL}
                                                                
{Fore.GREEN}█████╗ ██╗   ██╗████████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗ ██████╗ ██████╗ {Style.RESET_ALL}
{Fore.GREEN}██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗{Style.RESET_ALL}
{Fore.GREEN}███████║██║   ██║   ██║   ██║   ██║██╔████╔██║███████║   ██║   ██║   ██║██████╔╝{Style.RESET_ALL}
{Fore.GREEN}██╔══██║██║   ██║   ██║   ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██║   ██║██╔══██╗{Style.RESET_ALL}
{Fore.GREEN}██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║ ╚═╝ ██║██║  ██║   ██║   ╚██████╔╝██║  ██║{Style.RESET_ALL}
{Fore.GREEN}╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝{Style.RESET_ALL}
        """
        print(banner)
        print(f"{Fore.YELLOW}{'=' * self.terminal_width}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{Style.BRIGHT}A comprehensive security scanning tool combining Nmap and SQLmap{Style.RESET_ALL}".center(self.terminal_width))
        print(f"{Fore.YELLOW}{'=' * self.terminal_width}{Style.RESET_ALL}")
        print()
    
    def show_security_tip(self):
        tip = random.choice(self.security_tips)
        print(f"\n{Fore.YELLOW}[TIP] {Fore.CYAN}{tip}{Style.RESET_ALL}\n")
        time.sleep(2)
    
    def print_section_header(self, title):
        print(f"\n{Fore.BLUE}{'=' * self.terminal_width}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{Style.BRIGHT}{title.center(self.terminal_width)}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'=' * self.terminal_width}{Style.RESET_ALL}\n")
    
    def print_menu(self, title, options):
        self.print_section_header(title)
        
        for i, option in enumerate(options, 1):
            print(f"{Fore.GREEN}[{i}] {Fore.WHITE}{option}{Style.RESET_ALL}")
        
        if title != "Main Menu":
            print(f"\n{Fore.RED}[0] {Fore.WHITE}Return to previous menu{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[0] {Fore.WHITE}Exit{Style.RESET_ALL}")
    
    def get_user_choice(self, max_choice):
        while True:
            try:
                choice = input(f"\n{Fore.YELLOW}Enter your choice (0-{max_choice}): {Style.RESET_ALL}")
                choice = int(choice)
                if 0 <= choice <= max_choice:
                    return choice
                else:
                    print(f"{Fore.RED}Error: Please enter a number between 0 and {max_choice}.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}Error: Please enter a valid number.{Style.RESET_ALL}")
    
    def get_user_input(self, prompt, validate=None, error_msg=None):
        while True:
            user_input = input(f"{Fore.YELLOW}{prompt}: {Style.RESET_ALL}")
            if validate is None or validate(user_input):
                return user_input
            print(f"{Fore.RED}{error_msg or 'Invalid input. Please try again.'}{Style.RESET_ALL}")
    
    def validate_ip(self, ip):
        pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return re.match(pattern, ip) is not None
    
    def validate_ip_or_hostname(self, target):
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        hostname_pattern = r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
        return re.match(ip_pattern, target) is not None or re.match(hostname_pattern, target) is not None
    
    def validate_url(self, url):
        pattern = r"^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$"
        return re.match(pattern, url) is not None
    
    def run_command(self, command, log_file, tool_type="generic"):
        try:
            if tool_type == "sqlmap":
                if "--batch" in command and "-v" not in command:
                    command.extend(["-v", "0"])  
                
                if "--output-dir" not in " ".join(command):
                    command.extend(["--output-dir", self.logs_dir])
            
            print(f"{Fore.CYAN}Running command: {Fore.WHITE}{' '.join(command)}{Style.RESET_ALL}\n")
            
            with open(log_file, 'a') as f:
                f.write(f"Command: {' '.join(command)}\n")
                f.write(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 50 + "\n")
                
                if tool_type == "sqlmap":
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1
                    )
                    
                    seen_lines = set()  
                    for line in process.stdout:
                        if "Enter target URL with parameters" in line:
                            if "Enter target URL with parameters" in seen_lines:
                                continue
                            seen_lines.add("Enter target URL with parameters")
                        
                        if "SQLmap Attack:" in line and "SQLmap Attack:" in seen_lines:
                            continue
                        elif "SQLmap Attack:" in line:
                            seen_lines.add("SQLmap Attack:")
                        
                        print(line, end='')
                        f.write(line)
                    
                    for line in process.stderr:
                        print(f"{Fore.RED}{line}{Style.RESET_ALL}", end='')
                        f.write(f"ERROR: {line}")
                else:
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1
                    )
                    
                    for line in process.stdout:
                        print(line, end='')
                        f.write(line)
                    
                    for line in process.stderr:
                        print(f"{Fore.RED}{line}{Style.RESET_ALL}", end='')
                        f.write(f"ERROR: {line}")
                
                process.wait()
                
                if process.returncode != 0:
                    f.write(f"Command completed with exit code: {process.returncode}\n")
                    print(f"\n{Fore.RED}Command completed with exit code: {process.returncode}{Style.RESET_ALL}")
                else:
                    f.write("Command completed successfully.\n")
                    print(f"\n{Fore.GREEN}Command completed successfully.{Style.RESET_ALL}")
                
                f.write("-" * 50 + "\n\n")
            
            return process.returncode
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Command interrupted by user.{Style.RESET_ALL}")
            with open(log_file, 'a') as f:
                f.write("Command interrupted by user.\n")
                f.write("-" * 50 + "\n\n")
            return 130 
        except Exception as e:
            with open(log_file, 'a') as f:
                f.write(f"ERROR: {str(e)}\n")
                f.write("-" * 50 + "\n\n")
            print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
            return 1
    
    def handle_log_file(self, log_file):
        print(f"\n{Fore.CYAN}Scan results have been saved to: {Fore.WHITE}{log_file}{Style.RESET_ALL}")
        
        options = [
            "Keep log file with current name",
            "Rename log file",
            "Delete log file"
        ]
        
        print(f"\n{Fore.YELLOW}What would you like to do with the log file?{Style.RESET_ALL}")
        for i, option in enumerate(options, 1):
            print(f"{Fore.GREEN}[{i}] {Fore.WHITE}{option}{Style.RESET_ALL}")
        
        choice = self.get_user_choice(len(options))
        
        if choice == 2:
            new_name = self.get_user_input("Enter new file name (without path)")
            new_file = os.path.join(self.logs_dir, new_name)
            
            try:
                os.rename(log_file, new_file)
                print(f"{Fore.GREEN}Log file renamed to: {new_file}{Style.RESET_ALL}")
                return new_file
            except Exception as e:
                print(f"{Fore.RED}Error renaming file: {str(e)}{Style.RESET_ALL}")
                return log_file
        
        elif choice == 3:
            confirm = self.get_user_input("Are you sure you want to delete this log file? (y/n)")
            if confirm.lower() == 'y':
                try:
                    os.remove(log_file)
                    print(f"{Fore.GREEN}Log file deleted.{Style.RESET_ALL}")
                    return None
                except Exception as e:
                    print(f"{Fore.RED}Error deleting file: {str(e)}{Style.RESET_ALL}")
                    return log_file
            else:
                print(f"{Fore.GREEN}Log file kept.{Style.RESET_ALL}")
        
        return log_file
    
    def list_logs(self):
        self.print_section_header("Log Management")
        
        log_files = [f for f in os.listdir(self.logs_dir) if os.path.isfile(os.path.join(self.logs_dir, f))]
        
        if not log_files:
            print(f"{Fore.YELLOW}No log files found.{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}Available log files:{Style.RESET_ALL}\n")
        for i, log_file in enumerate(log_files, 1):
            size = os.path.getsize(os.path.join(self.logs_dir, log_file))
            modified = datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(self.logs_dir, log_file)))
            print(f"{Fore.GREEN}[{i}]{Fore.WHITE} {log_file} {Fore.CYAN}({size/1024:.1f} KB, {modified.strftime('%Y-%m-%d %H:%M:%S')}){Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[0]{Fore.WHITE} Return to previous menu{Style.RESET_ALL}")
        
        choice = self.get_user_choice(len(log_files))
        
        if choice == 0:
            return
        
        selected_log = os.path.join(self.logs_dir, log_files[choice-1])
        
        log_options = [
            "View log file",
            "Delete log file",
            "Rename log file"
        ]
        
        self.print_menu(f"Selected: {log_files[choice-1]}", log_options)
        log_choice = self.get_user_choice(len(log_options))
        
        if log_choice == 0:
            self.list_logs()
        elif log_choice == 1:
            self.view_log_file(selected_log)
        elif log_choice == 2:
            self.delete_log_file(selected_log)
        elif log_choice == 3:
            self.rename_log_file(selected_log)
    
    def view_log_file(self, log_file):
        self.clear_screen()
        self.print_section_header(f"Log File: {os.path.basename(log_file)}")
        
        try:
            with open(log_file, 'r') as f:
                content = f.read()
                
                if os.name == 'nt':
                    print(content)
                else:
                    pager = os.environ.get('PAGER', 'less')
                    pager_process = subprocess.Popen([pager], stdin=subprocess.PIPE, text=True)
                    pager_process.communicate(input=content)
        except Exception as e:
            print(f"{Fore.RED}Error reading log file: {str(e)}{Style.RESET_ALL}")
        
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
    
    def delete_log_file(self, log_file):
        confirm = self.get_user_input(f"Are you sure you want to delete {os.path.basename(log_file)}? (y/n)")
        
        if confirm.lower() == 'y':
            try:
                os.remove(log_file)
                print(f"{Fore.GREEN}Log file deleted successfully.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error deleting log file: {str(e)}{Style.RESET_ALL}")
        
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
        self.list_logs()
    
    def rename_log_file(self, log_file):
        new_name = self.get_user_input("Enter new file name (without path)")
        new_file = os.path.join(self.logs_dir, new_name)
        
        try:
            os.rename(log_file, new_file)
            print(f"{Fore.GREEN}Log file renamed to: {new_name}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error renaming file: {str(e)}{Style.RESET_ALL}")
        
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
        self.list_logs()
    
    def nmap_menu(self):
        nmap_options = [
            "Quick scan (-T4 -F)",
            "Regular scan (default settings)",
            "Intense scan (-T4 -A -v)",
            "Intense scan plus UDP (-T4 -A -v -sU)",
            "Intense scan with all TCP ports (-T4 -A -v -p-)",
            "Ping scan (disable port scan, -sn)",
            "Quick scan plus (-T4 -sV -O -F --version-light)",
            "Quick traceroute (-sn --traceroute)",
            "Regular scan with OS detection (-O)",
            "Regular scan with service detection (-sV)",
            "Regular scan with script scanning (-sC)",
            "Comprehensive scan (-T4 -A -v -p- -sC)",
            "Vulnerability scan (--script vuln)",
            "HTTP vulnerability scan (--script http-vuln*)",
            "SMB vulnerability scan (--script smb-vuln*)",
            "SSL/TLS vulnerability scan (--script ssl-*)",
            "Stealth scan (SYN scan, -sS)",
            "Version detection scan (aggressive, -sV --version-all)",
            "Comprehensive firewall evasion scan (-f -t 0 -n -Pn --data-length 200)",
            "Advanced service detection (-A -T4 -sV)",
            "Complete network scan (-p 1-65535 -sV -sS -T4)",
            "Aggressive comprehensive scan (-T5 -A -p-)"
        ]
        
        self.print_menu("Nmap Scanning Options", nmap_options)
        choice = self.get_user_choice(len(nmap_options))
        
        if choice == 0:
            return
        
        self.clear_screen()
        self.print_section_header(f"Nmap Scan: {nmap_options[choice-1]}")
        
        target = self.get_user_input(
            "Enter target (IP address, hostname, or network range)",
            self.validate_ip_or_hostname,
            "Please enter a valid IP address, hostname, or network range (e.g., 192.168.1.1, example.com, 192.168.1.0/24)"
        )
        
        additional_args = self.get_user_input("Enter any additional arguments (optional)")
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(self.logs_dir, f"nmap_scan_{timestamp}.log")
        
        command = ["nmap"]
        
        if choice == 1:
            command.extend(["-T4", "-F", target])
        elif choice == 2:
            command.append(target)
        elif choice == 3:
            command.extend(["-T4", "-A", "-v", target])
        elif choice == 4:
            command.extend(["-T4", "-A", "-v", "-sU", target])
        elif choice == 5:
            command.extend(["-T4", "-A", "-v", "-p-", target])
        elif choice == 6:
            command.extend(["-sn", target])
        elif choice == 7:
            command.extend(["-T4", "-sV", "-O", "-F", "--version-light", target])
        elif choice == 8:
            command.extend(["-sn", "--traceroute", target])
        elif choice == 9:
            command.extend(["-O", target])
        elif choice == 10:
            command.extend(["-sV", target])
        elif choice == 11:
            command.extend(["-sC", target])
        elif choice == 12:
            command.extend(["-T4", "-A", "-v", "-p-", "-sC", target])
        elif choice == 13:
            command.extend(["--script", "vuln", target])
        elif choice == 14:
            command.extend(["--script", "http-vuln*", target])
        elif choice == 15:
            command.extend(["--script", "smb-vuln*", target])
        elif choice == 16:
            command.extend(["--script", "ssl-*", target])
        elif choice == 17:
            command.extend(["-sS", target])
        elif choice == 18:
            command.extend(["-sV", "--version-all", target])
        elif choice == 19:
            command.extend(["-f", "-t", "0", "-n", "-Pn", "--data-length", "200", target])
        elif choice == 20:
            command.extend(["-A", "-T4", "-sV", target])
        elif choice == 21:
            command.extend(["-p", "1-65535", "-sV", "-sS", "-T4", target])
        elif choice == 22:
            command.extend(["-T5", "-A", "-p-", target])
        
        if additional_args:
            command.extend(additional_args.split())
        
        print(f"{Fore.YELLOW}Starting Nmap scan. Please wait...{Style.RESET_ALL}\n")
        
        with open(log_file, 'w') as f:
            f.write(f"Nmap Scan: {nmap_options[choice-1]}\n")
            f.write(f"Target: {target}\n")
            f.write(f"Additional Arguments: {additional_args}\n")
            f.write(f"Start Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("-" * 50 + "\n\n")
        
        retcode = self.run_command(command, log_file, "nmap")
        
        if retcode == 0:
            print(f"\n{Fore.GREEN}Nmap scan completed successfully!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}Nmap scan completed with errors. Check the log file for details.{Style.RESET_ALL}")
        
        self.handle_log_file(log_file)
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
    
    def sqlmap_menu(self):
        sqlmap_options = [
            "Basic GET request scan",
            "Basic POST request scan",
            "Database fingerprint (--fingerprint)",
            "List databases (--dbs)",
            "List tables (--tables)",
            "List columns (--columns)",
            "Dump table data (--dump)",
            "Dump all databases (--dump-all)",
            "OS Shell (--os-shell)",
            "SQL Shell (--sql-shell)",
            "Find admin login pages (--forms --crawl=3)",
            "Test all parameters (--level=5 --risk=3)",
            "Advanced injection techniques (--technique=BEUSTQ)",
            "Time-based blind injection test (--technique=T)",
            "Error-based injection test (--technique=E)",
            "UNION query injection test (--technique=U)",
            "Stacked queries test (--technique=S)",
            "Boolean-based blind injection test (--technique=B)",
            "Use TOR for anonymity (--tor --tor-type=socks5)",
            "WAF bypass attempt (--tamper=space2comment)",
            "Advanced WAF bypass techniques (--tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces)",
            "Check for DBA privileges (--is-dba)"
        ]
        
        self.print_menu("SQLmap Attack Options", sqlmap_options)
        choice = self.get_user_choice(len(sqlmap_options))
        
        if choice == 0:
            return
        
        self.clear_screen()
        target_selection = f"SQLmap Attack: {sqlmap_options[choice-1]}"
        self.print_section_header(target_selection)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(self.logs_dir, f"sqlmap_attack_{timestamp}.log")
        
        with open(log_file, 'w') as f:
            f.write(f"SQLmap Attack: {sqlmap_options[choice-1]}\n")
            f.write(f"Start Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("-" * 50 + "\n\n")
        
        command = ["sqlmap"]
        
        if choice == 1:
            url = self.get_user_input(
                "Enter target URL with parameters (e.g., http://example.com/vuln.php?id=1)",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--batch"])
        
        elif choice == 2:
            url = self.get_user_input(
                "Enter target URL (e.g., http://example.com/login.php)",
                self.validate_url,
                "Please enter a valid URL"
            )
            data = self.get_user_input("Enter POST data (e.g., username=admin&password=test)")
            command.extend(["-u", url, "--data", data, "--batch"])
        
        elif choice == 3:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--fingerprint", "--batch"])
        
        elif choice == 4:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--dbs", "--batch"])
        
        elif choice == 5:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            db = self.get_user_input("Enter database name")
            command.extend(["-u", url, "-D", db, "--tables", "--batch"])
        
        elif choice == 6:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            db = self.get_user_input("Enter database name")
            table = self.get_user_input("Enter table name")
            command.extend(["-u", url, "-D", db, "-T", table, "--columns", "--batch"])
        
        elif choice == 7:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            db = self.get_user_input("Enter database name")
            table = self.get_user_input("Enter table name")
            command.extend(["-u", url, "-D", db, "-T", table, "--dump", "--batch"])
        
        elif choice == 8:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--dump-all", "--batch"])
        
        elif choice == 9:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--os-shell", "--batch"])
        
        elif choice == 10:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--sql-shell", "--batch"])
        
        elif choice == 11:
            url = self.get_user_input(
                "Enter target URL (base domain)",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--forms", "--crawl=3", "--batch"])
        
        elif choice == 12:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--level=5", "--risk=3", "--batch"])
        
        elif choice == 13:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--technique=BEUSTQ", "--batch"])
        
        elif choice == 14:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--technique=T", "--batch"])
        
        elif choice == 15:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--technique=E", "--batch"])
        
        elif choice == 16:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--technique=U", "--batch"])
        
        elif choice == 17:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--technique=S", "--batch"])
        
        elif choice == 18:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--technique=B", "--batch"])
        
        elif choice == 19:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--tor", "--tor-type=socks5", "--batch"])
        
        elif choice == 20:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--tamper=space2comment", "--batch"])
        
        elif choice == 21:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces", "--batch"])
        
        elif choice == 22:
            url = self.get_user_input(
                "Enter target URL with parameters",
                self.validate_url,
                "Please enter a valid URL"
            )
            command.extend(["-u", url, "--is-dba", "--batch"])
        
        additional_args = self.get_user_input("Enter any additional arguments (optional)")
        
        if additional_args:
            command.extend(additional_args.split())

        if "--batch" in command and "-v" not in " ".join(command):
            command.extend(["-v", "0"])  
            
        if "--no-colour" not in " ".join(command):
            command.append("--no-colour")  
        
        print(f"{Fore.YELLOW}Starting SQLmap attack. Please wait...{Style.RESET_ALL}\n")
        
        with open(log_file, 'a') as f:
            f.write(f"Command: {' '.join(command)}\n")
            f.write("-" * 50 + "\n\n")
        
        retcode = self.run_command(command, log_file, "sqlmap")
        
        if retcode == 0:
            print(f"\n{Fore.GREEN}SQLmap attack completed successfully!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}SQLmap attack completed with errors. Check the log file for details.{Style.RESET_ALL}")
        
        self.handle_log_file(log_file)
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
    
    def main_menu(self):
        main_options = [
            "Nmap Scanning Options",
            "SQLmap Attack Options",
            "Log Management"
        ]
        
        while True:
            self.print_banner()
            self.show_security_tip()
            self.print_menu("Main Menu", main_options)
            choice = self.get_user_choice(len(main_options))
            
            if choice == 0:
                self.clear_screen()
                print(f"\n{Fore.GREEN}Thank you for using the Security Scan Automator!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Goodbye!{Style.RESET_ALL}\n")
                sys.exit(0)
            
            if choice == 1:
                self.clear_screen()
                self.nmap_menu()
            elif choice == 2:
                self.clear_screen()
                self.sqlmap_menu()
            elif choice == 3:
                self.clear_screen()
                self.list_logs()
    
    def run(self):
        try:
            self.print_banner()
            
            if not self.check_dependencies():
                return
                
            print(f"{Fore.CYAN}Welcome to the Security Scan Automator!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}This tool combines the power of Nmap and SQLmap for comprehensive security scanning.{Style.RESET_ALL}")
            print(f"{Fore.RED}IMPORTANT: Always ensure you have proper authorization before scanning any systems or networks.{Style.RESET_ALL}")
            print(f"{Fore.RED}Unauthorized scanning may be illegal and is against ethical guidelines.{Style.RESET_ALL}")
            
            confirm = input(f"\n{Fore.YELLOW}Do you confirm that you have authorization to perform security scanning? (y/n): {Style.RESET_ALL}")
            
            if confirm.lower() != 'y':
                print(f"\n{Fore.RED}Confirmation denied. Exiting program.{Style.RESET_ALL}")
                sys.exit(1)
            
            self.main_menu()
        
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}Program interrupted by user. Exiting gracefully...{Style.RESET_ALL}")
            sys.exit(0)
        except Exception as e:
            print(f"\n{Fore.RED}An unexpected error occurred: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

if __name__ == "__main__":
    tool = SecurityTool()
    tool.run()

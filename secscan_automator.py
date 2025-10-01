#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import datetime
import json
import csv
import shutil
from pathlib import Path
from collections import defaultdict

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt, Confirm
    from rich.markdown import Markdown
    from rich.text import Text
    from rich import box
    from rich.align import Align
    from rich.columns import Columns
    from rich.live import Live
except ImportError:
    print("Installing required packages...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich"])
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt, Confirm
    from rich.markdown import Markdown
    from rich.text import Text
    from rich import box
    from rich.align import Align
    from rich.columns import Columns
    from rich.live import Live

console = Console()

class SecurityScanner:
    def __init__(self):
        self.author = "@mikropsoft"
        self.log_dir = Path("logs")
        self.export_dir = Path("exports")
        self.profiles_dir = Path("profiles")
        self.log_dir.mkdir(exist_ok=True)
        self.export_dir.mkdir(exist_ok=True)
        self.profiles_dir.mkdir(exist_ok=True)
        self.nmap_installed = False
        self.sqlmap_installed = False
        self.nmap_version = ""
        self.sqlmap_version = ""
        self.scan_history = []
        self.load_history()
        
    def clear_screen(self):
        os.system('clear' if os.name != 'nt' else 'cls')
        
    def animate_loading(self, message, duration=0.8):
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(message, total=100)
            for _ in range(100):
                time.sleep(duration/100)
                progress.update(task, advance=1)
    
    def show_banner(self):
        banner_text = Text()
        banner_text.append("\n")
        banner_text.append("     ███████╗███████╗ ██████╗███████╗ ██████╗ █████╗ ███╗   ██╗\n", style="bold cyan")
        banner_text.append("     ██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║\n", style="bold cyan")
        banner_text.append("     ███████╗█████╗  ██║     ███████╗██║     ███████║██╔██╗ ██║\n", style="bold cyan")
        banner_text.append("     ╚════██║██╔══╝  ██║     ╚════██║██║     ██╔══██║██║╚██╗██║\n", style="bold cyan")
        banner_text.append("     ███████║███████╗╚██████╗███████║╚██████╗██║  ██║██║ ╚████║\n", style="bold cyan")
        banner_text.append("     ╚══════╝╚══════╝ ╚═════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n", style="bold cyan")
        banner_text.append("\n")
        banner_text.append("              🛡️  Security Scan Automator  🛡️\n", style="bold white")
        banner_text.append("         Advanced Penetration Testing Framework\n", style="dim white")
        banner_text.append(f"\n                  Created by {self.author}\n", style="bold yellow")
        
        console.print(Align.center(banner_text))
        
    def validate_input(self, prompt_text, valid_choices=None, allow_empty=False):
        while True:
            user_input = Prompt.ask(prompt_text).strip()
            
            if not user_input and not allow_empty:
                console.print("[red]❌ Input cannot be empty[/red]")
                time.sleep(0.5)
                continue
                
            if user_input and len(user_input) > 500:
                console.print("[red]❌ Input too long (max 500 characters)[/red]")
                time.sleep(0.5)
                continue
            
            if valid_choices and user_input not in valid_choices:
                console.print(f"[red]❌ Invalid choice. Please select from: {', '.join(valid_choices)}[/red]")
                time.sleep(0.5)
                continue
                
            return user_input
    
    def check_command_installed(self, command):
        try:
            result = subprocess.run(
                [command, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return True, result.stdout.strip().split('\n')[0] if result.returncode == 0 else ""
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False, ""
    
    def get_network_info(self):
        try:
            if os.name != 'nt':
                result = subprocess.run(
                    ["ip", "addr"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                return result.stdout if result.returncode == 0 else "Network info unavailable"
            else:
                result = subprocess.run(
                    ["ipconfig"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                return result.stdout if result.returncode == 0 else "Network info unavailable"
        except Exception:
            return "Network info unavailable"
    
    def check_dependencies(self):
        self.clear_screen()
        self.show_banner()
        
        console.print("\n")
        console.print(Align.center("[bold yellow]🔍 System Dependency Check[/bold yellow]"))
        console.print("\n")
        
        dep_table = Table(show_header=True, header_style="bold magenta", box=box.DOUBLE, expand=True)
        dep_table.add_column("🔧 Tool", style="cyan", width=20, justify="center")
        dep_table.add_column("📊 Status", width=20, justify="center")
        dep_table.add_column("📌 Version", width=50)
        
        self.nmap_installed, self.nmap_version = self.check_command_installed("nmap")
        nmap_status = "[bold green]✅ Installed[/bold green]" if self.nmap_installed else "[bold red]❌ Missing[/bold red]"
        dep_table.add_row("Nmap", nmap_status, self.nmap_version if self.nmap_installed else "Not Found")
        
        self.sqlmap_installed, self.sqlmap_version = self.check_command_installed("sqlmap")
        sqlmap_status = "[bold green]✅ Installed[/bold green]" if self.sqlmap_installed else "[bold red]❌ Missing[/bold red]"
        dep_table.add_row("SQLMap", sqlmap_status, self.sqlmap_version if self.sqlmap_installed else "Not Found")
        
        python_version = sys.version.split()[0]
        dep_table.add_row("Python", "[bold green]✅ Running[/bold green]", f"Python {python_version}")
        
        console.print(dep_table)
        
        if not self.nmap_installed or not self.sqlmap_installed:
            console.print("\n")
            console.print(Panel(
                "[bold red]⚠️  Warning: Some dependencies are missing![/bold red]\n\n"
                "[yellow]Installation Commands:[/yellow]\n"
                "  • Nmap: [cyan]sudo apt-get install nmap[/cyan] (Debian/Ubuntu)\n"
                "          [cyan]brew install nmap[/cyan] (macOS)\n"
                "  • SQLMap: [cyan]sudo apt-get install sqlmap[/cyan] (Debian/Ubuntu)\n"
                "            [cyan]pip install sqlmap[/cyan]",
                title="[bold red]Missing Dependencies[/bold red]",
                border_style="red"
            ))
            if not Confirm.ask("\n[yellow]Continue anyway?[/yellow]", default=False):
                sys.exit(0)
        else:
            console.print("\n")
            console.print(Align.center("[bold green]✅ All dependencies are installed and ready![/bold green]"))
        
        time.sleep(2)
    
    def load_history(self):
        history_file = self.log_dir / "scan_history.json"
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    self.scan_history = json.load(f)
            except Exception:
                self.scan_history = []
    
    def save_history(self, scan_data):
        self.scan_history.append(scan_data)
        history_file = self.log_dir / "scan_history.json"
        with open(history_file, 'w') as f:
            json.dump(self.scan_history, f, indent=2)
    
    def log_scan(self, scan_type, command, output, target="", duration=0):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"{scan_type}_{timestamp}.log"
        log_path = self.log_dir / log_filename
        
        log_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "scan_type": scan_type,
            "target": target,
            "command": command,
            "output": output,
            "duration": duration,
            "status": "completed",
            "log_file": str(log_path)
        }
        
        with open(log_path, 'w') as f:
            json.dump(log_data, f, indent=2)
            f.write("\n\n" + "="*80 + "\n")
            f.write("COMMAND OUTPUT:\n")
            f.write("="*80 + "\n\n")
            f.write(output)
        
        self.save_history(log_data)
        
        return log_path, log_data
    
    def execute_command(self, command, scan_type, target=""):
        try:
            console.print("\n")
            console.print(Panel(
                f"[bold yellow]Command:[/bold yellow] [cyan]{command}[/cyan]\n"
                f"[bold yellow]Target:[/bold yellow] [cyan]{target}[/cyan]",
                title="[bold green]🚀 Executing Scan[/bold green]",
                border_style="green"
            ))
            
            start_time = time.time()
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold green]{task.description}"),
                BarColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning in progress...", total=None)
                
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=600
                )
            
            duration = time.time() - start_time
            output = result.stdout + result.stderr
            
            log_path, log_data = self.log_scan(scan_type, command, output, target, duration)
            
            preview_length = 1500
            output_preview = output[:preview_length] + "\n\n[yellow]...(output truncated)[/yellow]" if len(output) > preview_length else output
            
            console.print("\n")
            console.print(Panel(
                output_preview,
                title="[bold green]✅ Scan Results[/bold green]",
                border_style="green",
                expand=False
            ))
            
            console.print("\n")
            stats = Text()
            stats.append("📊 Scan Statistics\n\n", style="bold cyan")
            stats.append(f"⏱️  Duration: {duration:.2f} seconds\n", style="green")
            stats.append(f"📁 Log File: {log_path.name}\n", style="cyan")
            stats.append(f"📦 Output Size: {len(output)} bytes\n", style="yellow")
            console.print(Panel(stats, border_style="blue"))
            
            if Confirm.ask("\n[cyan]Export results?[/cyan]", default=False):
                self.export_scan_results(log_data)
            
            return True
            
        except subprocess.TimeoutExpired:
            console.print("\n[bold red]❌ Error: Scan timeout (>10 minutes)[/bold red]")
            return False
        except KeyboardInterrupt:
            console.print("\n[bold yellow]⚠️  Scan interrupted by user[/bold yellow]")
            return False
        except Exception as e:
            console.print(f"\n[bold red]❌ Error: {str(e)}[/bold red]")
            return False
    
    def export_scan_results(self, log_data):
        export_formats = ["1", "2", "3", "0"]
        
        console.print("\n[bold cyan]📤 Export Options:[/bold cyan]")
        console.print("  1. JSON Format")
        console.print("  2. CSV Format")
        console.print("  3. HTML Report")
        console.print("  0. Cancel")
        
        choice = self.validate_input("\n[yellow]Select export format[/yellow]", export_formats)
        
        if choice == "0":
            return
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            if choice == "1":
                export_path = self.export_dir / f"scan_export_{timestamp}.json"
                with open(export_path, 'w') as f:
                    json.dump(log_data, f, indent=2)
                console.print(f"\n[green]✅ Exported to: {export_path}[/green]")
                
            elif choice == "2":
                export_path = self.export_dir / f"scan_export_{timestamp}.csv"
                with open(export_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Field', 'Value'])
                    for key, value in log_data.items():
                        if key != 'output':
                            writer.writerow([key, value])
                console.print(f"\n[green]✅ Exported to: {export_path}[/green]")
                
            elif choice == "3":
                export_path = self.export_dir / f"scan_report_{timestamp}.html"
                html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Scan Report - {log_data['scan_type']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        .info {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .label {{ font-weight: bold; color: #34495e; }}
        .value {{ color: #16a085; }}
        pre {{ background: #2c3e50; color: #ecf0f1; padding: 20px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Scan Report</h1>
        <div class="info">
            <p><span class="label">Scan Type:</span> <span class="value">{log_data['scan_type']}</span></p>
            <p><span class="label">Target:</span> <span class="value">{log_data['target']}</span></p>
            <p><span class="label">Timestamp:</span> <span class="value">{log_data['timestamp']}</span></p>
            <p><span class="label">Duration:</span> <span class="value">{log_data.get('duration', 0):.2f} seconds</span></p>
            <p><span class="label">Status:</span> <span class="value">{log_data['status']}</span></p>
        </div>
        <h2>Command Executed</h2>
        <pre>{log_data['command']}</pre>
        <h2>Scan Output</h2>
        <pre>{log_data['output'][:5000]}</pre>
    </div>
</body>
</html>
                """
                with open(export_path, 'w') as f:
                    f.write(html_content)
                console.print(f"\n[green]✅ HTML report generated: {export_path}[/green]")
                
        except Exception as e:
            console.print(f"[red]❌ Export failed: {str(e)}[/red]")
    
    def nmap_scanner_menu(self):
        while True:
            self.clear_screen()
            self.show_banner()
            
            console.print("\n")
            console.print(Align.center("[bold cyan]🔍 NMAP NETWORK SCANNER[/bold cyan]"))
            console.print("\n")
            
            level_table = Table(show_header=True, header_style="bold magenta", box=box.HEAVY, expand=True)
            level_table.add_column("🎯 Level", style="cyan", width=15, justify="center")
            level_table.add_column("📝 Description", width=50)
            level_table.add_column("⏱️  Speed", width=15, justify="center")
            
            level_table.add_row("1", "⚡ Easy - Quick & Basic Scans", "[green]Fast[/green]")
            level_table.add_row("2", "🔧 Medium - Standard Scans", "[yellow]Moderate[/yellow]")
            level_table.add_row("3", "🔥 Hard - Advanced & Comprehensive", "[red]Slow[/red]")
            level_table.add_row("4", "⭐ Quick Profiles - Predefined Scans", "[cyan]Varies[/cyan]")
            level_table.add_row("0", "⬅️  Back to Main Menu", "")
            
            console.print(level_table)
            
            choice = self.validate_input("\n[bold yellow]Select scan level[/bold yellow]", ["1", "2", "3", "4", "0"])
            
            if choice == "0":
                break
            elif choice == "1":
                self.nmap_easy_scans()
            elif choice == "2":
                self.nmap_medium_scans()
            elif choice == "3":
                self.nmap_hard_scans()
            elif choice == "4":
                self.quick_scan_profiles("nmap")
    
    def nmap_easy_scans(self):
        self.clear_screen()
        self.show_banner()
        
        console.print("\n")
        console.print(Align.center("[bold green]⚡ NMAP EASY SCANS[/bold green]"))
        console.print("\n")
        
        scans = {
            "1": {"name": "Quick Ping Sweep", "desc": "Check if hosts are alive", "cmd": "nmap -sn {target}", "time": "~5 sec"},
            "2": {"name": "Fast Port Scan", "desc": "Scan top 100 ports", "cmd": "nmap -F {target}", "time": "~10 sec"},
            "3": {"name": "Basic TCP Scan", "desc": "Simple TCP connect", "cmd": "nmap -sT {target}", "time": "~30 sec"},
            "4": {"name": "Top 1000 Ports", "desc": "Most common ports", "cmd": "nmap --top-ports 1000 {target}", "time": "~1 min"},
            "5": {"name": "Version Detection Light", "desc": "Quick service versions", "cmd": "nmap -sV --version-light {target}", "time": "~45 sec"},
            "6": {"name": "Basic OS Detection", "desc": "Simple fingerprinting", "cmd": "nmap -O --osscan-guess {target}", "time": "~40 sec"},
            "7": {"name": "Default Scripts", "desc": "Safe NSE scripts", "cmd": "nmap -sC {target}", "time": "~1 min"},
            "8": {"name": "UDP Quick Scan", "desc": "Top 20 UDP ports", "cmd": "nmap -sU --top-ports 20 {target}", "time": "~30 sec"},
            "9": {"name": "Web Server Scan", "desc": "HTTP/HTTPS quick check", "cmd": "nmap -p 80,443,8080,8443 -sV {target}", "time": "~15 sec"},
            "10": {"name": "Network Discovery", "desc": "Discover local network", "cmd": "nmap -sn {target}/24", "time": "~20 sec"},
        }
        
        self.display_scan_menu(scans, "nmap_easy")
    
    def nmap_medium_scans(self):
        self.clear_screen()
        self.show_banner()
        
        console.print("\n")
        console.print(Align.center("[bold yellow]🔧 NMAP MEDIUM SCANS[/bold yellow]"))
        console.print("\n")
        
        scans = {
            "1": {"name": "SYN Stealth Scan", "desc": "Half-open TCP scan", "cmd": "sudo nmap -sS {target}", "time": "~2 min"},
            "2": {"name": "Service & Version Full", "desc": "Detailed version detect", "cmd": "nmap -sV --version-all {target}", "time": "~3 min"},
            "3": {"name": "OS Detection Enhanced", "desc": "Aggressive OS detection", "cmd": "sudo nmap -O --osscan-limit {target}", "time": "~2 min"},
            "4": {"name": "Aggressive Scan", "desc": "OS, version, scripts", "cmd": "nmap -A -T4 {target}", "time": "~5 min"},
            "5": {"name": "Vulnerability Scan", "desc": "Common vulnerabilities", "cmd": "nmap --script vuln {target}", "time": "~4 min"},
            "6": {"name": "Full TCP Port Scan", "desc": "All 65535 ports", "cmd": "nmap -p- -T4 {target}", "time": "~10 min"},
            "7": {"name": "UDP Common Ports", "desc": "Top 100 UDP services", "cmd": "sudo nmap -sU --top-ports 100 {target}", "time": "~5 min"},
            "8": {"name": "Firewall Detection", "desc": "Detect firewall/IDS", "cmd": "nmap -sA -T4 {target}", "time": "~3 min"},
            "9": {"name": "Service Scripts", "desc": "Service-specific NSE", "cmd": "nmap -sV --script=default {target}", "time": "~4 min"},
            "10": {"name": "Fast Comprehensive", "desc": "Quick but thorough", "cmd": "nmap -T4 -F -sV -sC {target}", "time": "~2 min"},
            "11": {"name": "SMB Enumeration", "desc": "Windows SMB scan", "cmd": "nmap --script smb-enum* -p 445,139 {target}", "time": "~3 min"},
            "12": {"name": "DNS Enumeration", "desc": "DNS information", "cmd": "nmap --script dns-brute {target}", "time": "~2 min"},
        }
        
        self.display_scan_menu(scans, "nmap_medium")
    
    def nmap_hard_scans(self):
        self.clear_screen()
        self.show_banner()
        
        console.print("\n")
        console.print(Align.center("[bold red]🔥 NMAP HARD SCANS[/bold red]"))
        console.print(Align.center("[yellow]⚠️  Warning: Intensive scans that may take significant time[/yellow]"))
        console.print("\n")
        
        scans = {
            "1": {"name": "Full Comprehensive", "desc": "Complete analysis", "cmd": "sudo nmap -sS -sV -O -A -p- --script=default,vuln {target}", "time": "~30 min"},
            "2": {"name": "Deep Vulnerability", "desc": "All vuln scripts", "cmd": "nmap -sV --script=vuln,exploit,auth -p- {target}", "time": "~25 min"},
            "3": {"name": "Slow Stealth", "desc": "IDS evasion", "cmd": "sudo nmap -sS -T2 -f --data-length 200 -p- {target}", "time": "~60 min"},
            "4": {"name": "Full UDP & TCP", "desc": "All ports both protocols", "cmd": "sudo nmap -sS -sU -p- {target}", "time": "~90 min"},
            "5": {"name": "NSE Full Suite", "desc": "All NSE scripts", "cmd": "nmap --script=all -p- {target}", "time": "~45 min"},
            "6": {"name": "Advanced OS Fingerprint", "desc": "Deep OS detection", "cmd": "sudo nmap -O --osscan-guess --fuzzy -sV -p- {target}", "time": "~35 min"},
            "7": {"name": "Malware Detection", "desc": "Check backdoors", "cmd": "nmap --script=malware,backdoor -p- {target}", "time": "~20 min"},
            "8": {"name": "Web Vulnerability", "desc": "HTTP/HTTPS vulns", "cmd": "nmap --script=http-vuln* -p 80,443,8080,8443 {target}", "time": "~15 min"},
            "9": {"name": "Database Enumeration", "desc": "All DB services", "cmd": "nmap --script=mysql*,oracle*,ms-sql*,mongodb*,postgresql* -p 1433,1521,3306,5432,27017 {target}", "time": "~10 min"},
            "10": {"name": "SSL/TLS Deep Analysis", "desc": "Complete SSL audit", "cmd": "nmap --script=ssl*,tls* -p 443,8443,465,993,995 {target}", "time": "~12 min"},
            "11": {"name": "SMB Full Enumeration", "desc": "Complete Windows scan", "cmd": "nmap --script=smb-enum*,smb-vuln*,smb-os-discovery -p 445,139 {target}", "time": "~15 min"},
            "12": {"name": "Network Topology", "desc": "Full network map", "cmd": "nmap -sn --traceroute --script=targets-traceroute {target}", "time": "~8 min"},
            "13": {"name": "Banner Grabbing Advanced", "desc": "Detailed service info", "cmd": "nmap -sV --version-intensity 9 --script=banner -p- {target}", "time": "~25 min"},
            "14": {"name": "Wireless Audit", "desc": "Wireless AP enum", "cmd": "nmap --script=broadcast-dhcp-discover,broadcast-wpad-discover {target}", "time": "~5 min"},
            "15": {"name": "Firewall/IDS Evasion", "desc": "Fragmentation & decoys", "cmd": "sudo nmap -sS -f -D RND:10 --randomize-hosts -p- {target}", "time": "~40 min"},
            "16": {"name": "IPv6 Full Scan", "desc": "Complete IPv6 scan", "cmd": "nmap -6 -sS -sV -O -p- {target}", "time": "~30 min"},
            "17": {"name": "Ultimate Scan", "desc": "Everything enabled", "cmd": "sudo nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=all -p- {target}", "time": "~120 min"},
        }
        
        self.display_scan_menu(scans, "nmap_hard")
    
    def sqlmap_scanner_menu(self):
        while True:
            self.clear_screen()
            self.show_banner()
            
            console.print("\n")
            console.print(Align.center("[bold cyan]💉 SQLMAP INJECTION SCANNER[/bold cyan]"))
            console.print("\n")
            
            level_table = Table(show_header=True, header_style="bold magenta", box=box.HEAVY, expand=True)
            level_table.add_column("🎯 Level", style="cyan", width=15, justify="center")
            level_table.add_column("📝 Description", width=50)
            level_table.add_column("⚡ Risk", width=15, justify="center")
            
            level_table.add_row("1", "⚡ Easy - Quick & Basic Tests", "[green]Low[/green]")
            level_table.add_row("2", "🔧 Medium - Standard Tests", "[yellow]Medium[/yellow]")
            level_table.add_row("3", "🔥 Hard - Advanced & Aggressive", "[red]High[/red]")
            level_table.add_row("4", "⭐ Quick Profiles - Predefined Tests", "[cyan]Varies[/cyan]")
            level_table.add_row("0", "⬅️  Back to Main Menu", "")
            
            console.print(level_table)
            
            choice = self.validate_input("\n[bold yellow]Select scan level[/bold yellow]", ["1", "2", "3", "4", "0"])
            
            if choice == "0":
                break
            elif choice == "1":
                self.sqlmap_easy_scans()
            elif choice == "2":
                self.sqlmap_medium_scans()
            elif choice == "3":
                self.sqlmap_hard_scans()
            elif choice == "4":
                self.quick_scan_profiles("sqlmap")
    
    def sqlmap_easy_scans(self):
        self.clear_screen()
        self.show_banner()
        
        console.print("\n")
        console.print(Align.center("[bold green]⚡ SQLMAP EASY SCANS[/bold green]"))
        console.print("\n")
        
        scans = {
            "1": {"name": "Basic SQL Injection", "desc": "Quick vulnerability check", "cmd": "sqlmap -u {url} --batch --smart", "time": "~2 min"},
            "2": {"name": "GET Parameter Test", "desc": "Test GET params", "cmd": "sqlmap -u {url} --batch --level=1 --risk=1", "time": "~3 min"},
            "3": {"name": "List Databases", "desc": "Enumerate databases", "cmd": "sqlmap -u {url} --batch --dbs", "time": "~2 min"},
            "4": {"name": "Current Database", "desc": "Get current DB name", "cmd": "sqlmap -u {url} --batch --current-db", "time": "~1 min"},
            "5": {"name": "Current User", "desc": "Get DB user info", "cmd": "sqlmap -u {url} --batch --current-user", "time": "~1 min"},
            "6": {"name": "Form Auto-Test", "desc": "Test HTML forms", "cmd": "sqlmap -u {url} --batch --forms", "time": "~3 min"},
            "7": {"name": "Cookie Testing", "desc": "Test cookies", "cmd": "sqlmap -u {url} --batch --cookie={cookie}", "time": "~2 min"},
            "8": {"name": "Quick Crawl", "desc": "Crawl & test site", "cmd": "sqlmap -u {url} --batch --crawl=2", "time": "~5 min"},
            "9": {"name": "Check WAF", "desc": "Detect WAF/IPS", "cmd": "sqlmap -u {url} --batch --identify-waf", "time": "~1 min"},
            "10": {"name": "Basic Banner Grab", "desc": "Get DB banner", "cmd": "sqlmap -u {url} --batch --banner", "time": "~1 min"},
        }
        
        self.display_scan_menu(scans, "sqlmap_easy")
    
    def sqlmap_medium_scans(self):
        self.clear_screen()
        self.show_banner()
        
        console.print("\n")
        console.print(Align.center("[bold yellow]🔧 SQLMAP MEDIUM SCANS[/bold yellow]"))
        console.print("\n")
        
        scans = {
            "1": {"name": "Standard Injection", "desc": "Level 2, Risk 2", "cmd": "sqlmap -u {url} --batch --level=2 --risk=2", "time": "~5 min"},
            "2": {"name": "Enumerate Tables", "desc": "List all tables", "cmd": "sqlmap -u {url} --batch -D {db} --tables", "time": "~3 min"},
            "3": {"name": "Table Columns", "desc": "Get table structure", "cmd": "sqlmap -u {url} --batch -D {db} -T {table} --columns", "time": "~2 min"},
            "4": {"name": "Dump Table Data", "desc": "Extract table data", "cmd": "sqlmap -u {url} --batch -D {db} -T {table} --dump", "time": "~5 min"},
            "5": {"name": "POST Data Test", "desc": "Test POST params", "cmd": "sqlmap -u {url} --batch --data={postdata}", "time": "~4 min"},
            "6": {"name": "Dump All Databases", "desc": "Extract all DBs", "cmd": "sqlmap -u {url} --batch --dump-all --exclude-sysdbs", "time": "~10 min"},
            "7": {"name": "User Privileges", "desc": "Check permissions", "cmd": "sqlmap -u {url} --batch --privileges", "time": "~2 min"},
            "8": {"name": "List DB Users", "desc": "Enumerate users", "cmd": "sqlmap -u {url} --batch --users", "time": "~2 min"},
            "9": {"name": "Password Hashes", "desc": "Extract hashes", "cmd": "sqlmap -u {url} --batch --passwords", "time": "~3 min"},
            "10": {"name": "SQL Queries", "desc": "Execute custom SQL", "cmd": "sqlmap -u {url} --batch --sql-query=\"SELECT @@version\"", "time": "~1 min"},
            "11": {"name": "Bypass WAF", "desc": "Use tamper scripts", "cmd": "sqlmap -u {url} --batch --tamper=space2comment", "time": "~4 min"},
            "12": {"name": "JSON Injection", "desc": "Test JSON params", "cmd": "sqlmap -u {url} --batch --json={jsondata}", "time": "~3 min"},
        }
        
        self.display_scan_menu(scans, "sqlmap_medium")
    
    def sqlmap_hard_scans(self):
        self.clear_screen()
        self.show_banner()
        
        console.print("\n")
        console.print(Align.center("[bold red]🔥 SQLMAP HARD SCANS[/bold red]"))
        console.print(Align.center("[yellow]⚠️  Warning: Aggressive scans may trigger WAF/IDS[/yellow]"))
        console.print("\n")
        
        scans = {
            "1": {"name": "Maximum Level", "desc": "Level 5, Risk 3", "cmd": "sqlmap -u {url} --batch --level=5 --risk=3", "time": "~15 min"},
            "2": {"name": "All Techniques", "desc": "Test all injection types", "cmd": "sqlmap -u {url} --batch --level=3 --risk=2 --technique=BEUSTQ", "time": "~10 min"},
            "3": {"name": "Time-Based Blind", "desc": "Heavy time-based tests", "cmd": "sqlmap -u {url} --batch --level=4 --risk=3 --technique=T --time-sec=10", "time": "~20 min"},
            "4": {"name": "Union-Based Advanced", "desc": "Advanced union queries", "cmd": "sqlmap -u {url} --batch --level=3 --risk=2 --technique=U --union-cols=15", "time": "~12 min"},
            "5": {"name": "OS Shell Access", "desc": "Get system shell", "cmd": "sqlmap -u {url} --batch --os-shell", "time": "~8 min"},
            "6": {"name": "SQL Shell Access", "desc": "Interactive SQL", "cmd": "sqlmap -u {url} --batch --sql-shell", "time": "~5 min"},
            "7": {"name": "File Read", "desc": "Read server files", "cmd": "sqlmap -u {url} --batch --file-read={file}", "time": "~5 min"},
            "8": {"name": "File Write", "desc": "Write to server", "cmd": "sqlmap -u {url} --batch --file-write={local} --file-dest={remote}", "time": "~5 min"},
            "9": {"name": "Complete Dump", "desc": "Dump everything", "cmd": "sqlmap -u {url} --batch --dump-all --threads=10", "time": "~30 min"},
            "10": {"name": "Advanced WAF Bypass", "desc": "Multiple tampers", "cmd": "sqlmap -u {url} --batch --level=3 --risk=2 --tamper=space2comment,between,randomcase", "time": "~10 min"},
            "11": {"name": "Tor Anonymity", "desc": "Scan through Tor", "cmd": "sqlmap -u {url} --batch --tor --tor-type=SOCKS5 --check-tor", "time": "~15 min"},
            "12": {"name": "Search Columns", "desc": "Search specific data", "cmd": "sqlmap -u {url} --batch --search -C {column}", "time": "~8 min"},
            "13": {"name": "Registry Access", "desc": "Windows registry", "cmd": "sqlmap -u {url} --batch --reg-read", "time": "~5 min"},
            "14": {"name": "Full Enumeration", "desc": "Complete enum", "cmd": "sqlmap -u {url} --batch --level=4 --risk=3 --banner --users --passwords --dbs --tables", "time": "~20 min"},
            "15": {"name": "Second Order Injection", "desc": "Advanced technique", "cmd": "sqlmap -u {url} --batch --second-url={secondurl}", "time": "~10 min"},
            "16": {"name": "Custom Injection Point", "desc": "Manual injection", "cmd": "sqlmap -u {url} --batch --prefix=\"')\" --suffix=\"--\"", "time": "~8 min"},
            "17": {"name": "Ultimate Exploitation", "desc": "All options", "cmd": "sqlmap -u {url} --batch --level=5 --risk=3 --threads=10 --tamper=space2comment --technique=BEUSTQ --dump-all", "time": "~45 min"},
        }
        
        self.display_scan_menu(scans, "sqlmap_hard")
    
    def display_scan_menu(self, scans, scan_prefix):
        scan_table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED, expand=True)
        scan_table.add_column("#", style="yellow", width=5, justify="center")
        scan_table.add_column("🎯 Scan Name", style="green", width=30)
        scan_table.add_column("📝 Description", width=35)
        scan_table.add_column("⏱️  Est. Time", width=12, justify="center")
        
        for key, value in scans.items():
            scan_table.add_row(key, value["name"], value["desc"], value.get("time", "varies"))
        scan_table.add_row("0", "⬅️  Back", "Return to level selection", "")
        
        console.print(scan_table)
        
        valid_choices = list(scans.keys()) + ["0"]
        choice = self.validate_input("\n[bold yellow]Select scan type[/bold yellow]", valid_choices)
        
        if choice == "0":
            return
        
        if choice in scans:
            if "nmap" in scan_prefix:
                target = self.validate_input("\n[bold cyan]Enter target (IP/Domain/Range)[/bold cyan]")
                command = scans[choice]["cmd"].format(target=target)
                
                if "nmap_hard" in scan_prefix:
                    if not Confirm.ask(f"\n[yellow]⚠️  Estimated time: {scans[choice].get('time', 'unknown')}. Continue?[/yellow]", default=True):
                        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
                        return
                
                self.execute_command(command, f"{scan_prefix}_{scans[choice]['name'].replace(' ', '_')}", target)
                
            elif "sqlmap" in scan_prefix:
                url = self.validate_input("\n[bold cyan]Enter target URL[/bold cyan]")
                command = scans[choice]["cmd"]
                
                if "{cookie}" in command:
                    cookie = self.validate_input("[cyan]Enter cookie value[/cyan]", allow_empty=True)
                    command = command.format(url=url, cookie=cookie)
                elif "{db}" in command:
                    db = self.validate_input("[cyan]Enter database name[/cyan]")
                    if "{table}" in command:
                        table = self.validate_input("[cyan]Enter table name[/cyan]")
                        command = command.format(url=url, db=db, table=table)
                    else:
                        command = command.format(url=url, db=db)
                elif "{postdata}" in command:
                    postdata = self.validate_input("[cyan]Enter POST data (e.g., 'id=1&name=test')[/cyan]")
                    command = command.format(url=url, postdata=postdata)
                elif "{jsondata}" in command:
                    jsondata = self.validate_input("[cyan]Enter JSON data[/cyan]")
                    command = command.format(url=url, jsondata=jsondata)
                elif "{file}" in command:
                    file = self.validate_input("[cyan]Enter file path to read[/cyan]")
                    command = command.format(url=url, file=file)
                elif "{local}" in command and "{remote}" in command:
                    local = self.validate_input("[cyan]Enter local file path[/cyan]")
                    remote = self.validate_input("[cyan]Enter remote destination[/cyan]")
                    command = command.format(url=url, local=local, remote=remote)
                elif "{column}" in command:
                    column = self.validate_input("[cyan]Enter column name to search[/cyan]")
                    command = command.format(url=url, column=column)
                elif "{secondurl}" in command:
                    secondurl = self.validate_input("[cyan]Enter second-order URL[/cyan]")
                    command = command.format(url=url, secondurl=secondurl)
                else:
                    command = command.format(url=url)
                
                if "sqlmap_hard" in scan_prefix:
                    if not Confirm.ask(f"\n[yellow]⚠️  This is aggressive. Estimated time: {scans[choice].get('time', 'unknown')}. Continue?[/yellow]", default=False):
                        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
                        return
                
                self.execute_command(command, f"{scan_prefix}_{scans[choice]['name'].replace(' ', '_')}", url)
            
            Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
    
    def quick_scan_profiles(self, scan_type):
        self.clear_screen()
        self.show_banner()
        
        console.print("\n")
        console.print(Align.center(f"[bold cyan]⭐ QUICK SCAN PROFILES - {scan_type.upper()}[/bold cyan]"))
        console.print("\n")
        
        if scan_type == "nmap":
            profiles = {
                "1": {"name": "Web Server Audit", "desc": "Complete web server scan", "cmd": "nmap -sS -sV -p 80,443,8080,8443 --script=http-* {target}"},
                "2": {"name": "Database Server Audit", "desc": "All database ports", "cmd": "nmap -sV -p 1433,1521,3306,5432,27017 --script=*sql*,mongodb* {target}"},
                "3": {"name": "Mail Server Audit", "desc": "Email server scan", "cmd": "nmap -sV -p 25,110,143,465,587,993,995 --script=smtp-*,pop3-*,imap-* {target}"},
                "4": {"name": "Windows Domain Audit", "desc": "AD and SMB scan", "cmd": "nmap -sV -p 88,135,139,389,445,636 --script=smb-*,ldap-* {target}"},
                "5": {"name": "Network Infrastructure", "desc": "Routers and switches", "cmd": "nmap -sU -sV -p 161,162,514 --script=snmp-* {target}"},
                "6": {"name": "Cloud Services", "desc": "Common cloud ports", "cmd": "nmap -sV -p 22,80,443,3389,5985,5986 {target}"},
            }
        else:
            profiles = {
                "1": {"name": "WordPress Audit", "desc": "WordPress SQL injection", "cmd": "sqlmap -u {url} --batch --level=2 --risk=2 --random-agent"},
                "2": {"name": "REST API Test", "desc": "API injection test", "cmd": "sqlmap -u {url} --batch --method=POST --headers=\"Content-Type: application/json\""},
                "3": {"name": "Login Form Test", "desc": "Authentication bypass", "cmd": "sqlmap -u {url} --batch --forms --level=3 --risk=2"},
                "4": {"name": "Cookie Injection", "desc": "Session cookie test", "cmd": "sqlmap -u {url} --batch --cookie={cookie} --level=2"},
                "5": {"name": "Blind SQL Test", "desc": "Time-based blind", "cmd": "sqlmap -u {url} --batch --technique=T --level=3"},
                "6": {"name": "Error-Based Quick", "desc": "Error-based injection", "cmd": "sqlmap -u {url} --batch --technique=E --level=2"},
            }
        
        profile_table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED, expand=True)
        profile_table.add_column("#", style="yellow", width=5, justify="center")
        profile_table.add_column("⭐ Profile Name", style="green", width=30)
        profile_table.add_column("📝 Description", width=40)
        
        for key, value in profiles.items():
            profile_table.add_row(key, value["name"], value["desc"])
        profile_table.add_row("0", "⬅️  Back", "Return to menu")
        
        console.print(profile_table)
        
        valid_choices = list(profiles.keys()) + ["0"]
        choice = self.validate_input("\n[bold yellow]Select profile[/bold yellow]", valid_choices)
        
        if choice == "0":
            return
        
        if choice in profiles:
            if scan_type == "nmap":
                target = self.validate_input("\n[bold cyan]Enter target[/bold cyan]")
                command = profiles[choice]["cmd"].format(target=target)
                self.execute_command(command, f"nmap_profile_{profiles[choice]['name'].replace(' ', '_')}", target)
            else:
                url = self.validate_input("\n[bold cyan]Enter target URL[/bold cyan]")
                command = profiles[choice]["cmd"]
                if "{cookie}" in command:
                    cookie = self.validate_input("[cyan]Enter cookie value[/cyan]", allow_empty=True)
                    command = command.format(url=url, cookie=cookie)
                else:
                    command = command.format(url=url)
                self.execute_command(command, f"sqlmap_profile_{profiles[choice]['name'].replace(' ', '_')}", url)
            
            Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
    
    def show_user_guide(self):
        self.clear_screen()
        self.show_banner()
        
        guide_md = """
# 📚 User Guide

## 🎯 Overview
Security Scan Automator is a comprehensive penetration testing tool that automates network scanning and SQL injection testing.

## 🔍 Scan Levels

### ⚡ Easy Level
- **Purpose**: Quick reconnaissance and basic testing
- **Speed**: Fast execution (seconds to minutes)
- **Risk**: Low detection risk
- **Best For**: Initial assessment, network discovery

### 🔧 Medium Level
- **Purpose**: Standard penetration testing
- **Speed**: Moderate execution (minutes)
- **Risk**: Medium detection risk
- **Best For**: Regular security assessments

### 🔥 Hard Level
- **Purpose**: Deep security analysis
- **Speed**: Slow execution (tens of minutes to hours)
- **Risk**: High detection risk, may trigger IDS/IPS
- **Best For**: Comprehensive security audits

## 🔧 Features

### Network Scanning (Nmap)
- Port scanning and service detection
- Operating system fingerprinting
- Vulnerability assessment
- Network topology mapping
- SSL/TLS analysis
- Web server enumeration

### SQL Injection Testing (SQLMap)
- Automated injection detection
- Database enumeration
- Data extraction
- Privilege escalation testing
- WAF bypass techniques

### Export Options
- **JSON**: Machine-readable format
- **CSV**: Spreadsheet-compatible
- **HTML**: Professional reports

### Quick Profiles
Pre-configured scan combinations for:
- Web servers
- Database servers
- Mail servers
- Windows domains
- Cloud infrastructure

## 📁 Log Management
All scans are logged to `logs/` directory:
- JSON format with metadata
- Complete command output
- Timestamp and duration tracking
- Searchable history

## ⚠️ Best Practices
1. **Always get authorization** before scanning
2. Start with Easy level scans
3. Review logs after each scan
4. Be aware of scan duration estimates
5. Use Hard level only when necessary
6. Consider legal and ethical implications

## 🚀 Quick Start
1. Check dependencies in main menu
2. Select scanner type (Nmap/SQLMap)
3. Choose difficulty level
4. Enter target information
5. Review results and export if needed

## 🔐 Security Notes
- Some scans require root/sudo privileges
- Aggressive scans may trigger security systems
- Always scan responsibly and ethically
- Keep your tools updated

## 🐛 Troubleshooting
- **Permission denied**: Use sudo for privileged scans
- **Command not found**: Install nmap/sqlmap
- **Scan timeout**: Increase timeout or use faster timing
- **Network issues**: Check connectivity and firewall rules

## 📞 Support
Created by @mikropsoft
Use responsibly and ethically!
        """
        
        console.print(Panel(Markdown(guide_md), title="[bold cyan]📚 User Guide[/bold cyan]", border_style="cyan", expand=False))
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
    
    def view_logs(self):
        self.clear_screen()
        self.show_banner()
        
        console.print("\n")
        console.print(Align.center("[bold cyan]📁 SCAN LOGS & HISTORY[/bold cyan]"))
        console.print("\n")
        
        log_files = sorted(self.log_dir.glob("*.log"), key=os.path.getmtime, reverse=True)
        
        if not log_files:
            console.print(Panel(
                "[yellow]No scan logs found yet.[/yellow]\n\n"
                "Run some scans to see results here!",
                title="[bold yellow]Empty History[/bold yellow]",
                border_style="yellow"
            ))
            Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
            return
        
        log_table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED, expand=True)
        log_table.add_column("#", style="yellow", width=5, justify="center")
        log_table.add_column("📄 Filename", style="cyan", width=35)
        log_table.add_column("📅 Date", style="green", width=20)
        log_table.add_column("📦 Size", style="white", width=12, justify="right")
        
        for idx, log_file in enumerate(log_files[:25], 1):
            mod_time = datetime.datetime.fromtimestamp(log_file.stat().st_mtime)
            size = log_file.stat().st_size
            size_str = f"{size/1024:.1f} KB" if size > 1024 else f"{size} B"
            log_table.add_row(str(idx), log_file.name, mod_time.strftime("%Y-%m-%d %H:%M:%S"), size_str)
        
        console.print(log_table)
        console.print(f"\n[cyan]📊 Total logs: {len(log_files)}[/cyan]")
        console.print("[cyan]📋 Showing latest 25 logs[/cyan]" if len(log_files) > 25 else "")
        
        if Confirm.ask("\n[yellow]View a specific log?[/yellow]", default=False):
            try:
                log_num = self.validate_input("[cyan]Enter log number[/cyan]")
                log_num = int(log_num)
                if 1 <= log_num <= min(len(log_files), 25):
                    log_file = log_files[log_num - 1]
                    with open(log_file, 'r') as f:
                        content = f.read()
                    
                    preview_length = 3000
                    content_preview = content[:preview_length] + "\n\n[yellow]...(content truncated, check file for full output)[/yellow]" if len(content) > preview_length else content
                    
                    console.print("\n")
                    console.print(Panel(
                        content_preview,
                        title=f"[bold green]📄 {log_file.name}[/bold green]",
                        border_style="green",
                        expand=False
                    ))
                else:
                    console.print("[red]❌ Invalid log number[/red]")
            except (ValueError, Exception) as e:
                console.print(f"[red]❌ Error: {str(e)}[/red]")
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
    
    def scan_statistics(self):
        self.clear_screen()
        self.show_banner()
        
        console.print("\n")
        console.print(Align.center("[bold cyan]📊 SCAN STATISTICS[/bold cyan]"))
        console.print("\n")
        
        if not self.scan_history:
            console.print(Panel(
                "[yellow]No scan history available.[/yellow]\n\n"
                "Statistics will appear after you run some scans.",
                title="[bold yellow]No Data[/bold yellow]",
                border_style="yellow"
            ))
            Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
            return
        
        scan_types = defaultdict(int)
        total_duration = 0
        targets = set()
        
        for scan in self.scan_history:
            scan_types[scan.get('scan_type', 'unknown')] += 1
            total_duration += scan.get('duration', 0)
            if scan.get('target'):
                targets.add(scan['target'])
        
        stats_table = Table(show_header=True, header_style="bold magenta", box=box.HEAVY, expand=True)
        stats_table.add_column("📊 Metric", style="cyan", width=30)
        stats_table.add_column("📈 Value", style="green", width=40)
        
        stats_table.add_row("Total Scans", str(len(self.scan_history)))
        stats_table.add_row("Unique Targets", str(len(targets)))
        stats_table.add_row("Total Duration", f"{total_duration:.2f} seconds ({total_duration/60:.1f} minutes)")
        stats_table.add_row("Average Duration", f"{total_duration/len(self.scan_history):.2f} seconds" if self.scan_history else "0")
        stats_table.add_row("Most Recent Scan", self.scan_history[-1].get('timestamp', 'Unknown')[:19] if self.scan_history else "None")
        
        console.print(stats_table)
        
        console.print("\n")
        console.print("[bold cyan]🎯 Scan Type Distribution:[/bold cyan]\n")
        
        type_table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED, expand=True)
        type_table.add_column("Scan Type", style="cyan", width=40)
        type_table.add_column("Count", style="green", width=20, justify="center")
        
        for scan_type, count in sorted(scan_types.items(), key=lambda x: x[1], reverse=True):
            type_table.add_row(scan_type, str(count))
        
        console.print(type_table)
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
    
    def network_info(self):
        self.clear_screen()
        self.show_banner()
        
        console.print("\n")
        console.print(Align.center("[bold cyan]🌐 NETWORK INFORMATION[/bold cyan]"))
        console.print("\n")
        
        self.animate_loading("Gathering network information...", 1)
        
        network_data = self.get_network_info()
        
        console.print(Panel(
            network_data,
            title="[bold green]Network Configuration[/bold green]",
            border_style="green",
            expand=False
        ))
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
    
    def install_system_command(self):
        self.clear_screen()
        self.show_banner()
        
        console.print("\n")
        console.print(Align.center("[bold cyan]🔧 SYSTEM INSTALLATION[/bold cyan]"))
        console.print("\n")
        
        console.print(Panel(
            "[bold yellow]This will install the tool system-wide[/bold yellow]\n\n"
            "After installation, you can run the tool from anywhere using:\n"
            "[bold cyan]secscan[/bold cyan]\n\n"
            "[yellow]Installation steps:[/yellow]\n"
            "1. Create executable script\n"
            "2. Copy to /usr/local/bin/ (requires sudo)\n"
            "3. Set execute permissions\n\n"
            "[red]Note: Requires sudo privileges[/red]",
            title="[bold cyan]Installation Guide[/bold cyan]",
            border_style="cyan"
        ))
        
        if not Confirm.ask("\n[yellow]Proceed with installation?[/yellow]", default=False):
            return
        
        try:
            current_file = Path(__file__).resolve()
            target_path = Path("/usr/local/bin/secscan")
            
            console.print("\n[cyan]📋 Copying file...[/cyan]")
            result = subprocess.run(
                ["sudo", "cp", str(current_file), str(target_path)],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                console.print(f"[red]❌ Copy failed: {result.stderr}[/red]")
                Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
                return
            
            console.print("[green]✅ File copied successfully[/green]")
            
            console.print("\n[cyan]🔐 Setting permissions...[/cyan]")
            result = subprocess.run(
                ["sudo", "chmod", "+x", str(target_path)],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                console.print(f"[red]❌ Permission setting failed: {result.stderr}[/red]")
                Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
                return
            
            console.print("[green]✅ Permissions set successfully[/green]")
            
            console.print("\n")
            console.print(Panel(
                "[bold green]✅ Installation completed successfully![/bold green]\n\n"
                "You can now run the tool from anywhere using:\n"
                "[bold cyan]secscan[/bold cyan]\n\n"
                "[yellow]To uninstall:[/yellow]\n"
                "[cyan]sudo rm /usr/local/bin/secscan[/cyan]",
                title="[bold green]Success![/bold green]",
                border_style="green"
            ))
            
        except Exception as e:
            console.print(f"\n[bold red]❌ Installation failed: {str(e)}[/bold red]")
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]")
    
    def main_menu(self):
        while True:
            self.clear_screen()
            self.show_banner()
            
            status_text = Text()
            status_text.append("🔍 System Status: ", style="bold white")
            if self.nmap_installed and self.sqlmap_installed:
                status_text.append("✅ All Tools Ready", style="bold green")
            elif self.nmap_installed or self.sqlmap_installed:
                status_text.append("⚠️  Partial Installation", style="bold yellow")
            else:
                status_text.append("❌ Tools Missing", style="bold red")
            
            status_text.append(f"  |  📊 Total Scans: {len(self.scan_history)}", style="bold cyan")
            
            console.print("\n")
            console.print(Panel(status_text, border_style="blue", expand=False))
            console.print("\n")
            
            menu_table = Table(show_header=True, header_style="bold magenta", box=box.HEAVY, show_lines=True, expand=True)
            menu_table.add_column("Option", style="yellow", width=10, justify="center")
            menu_table.add_column("🎯 Feature", style="cyan", width=30)
            menu_table.add_column("📝 Description", width=45)
            
            menu_table.add_row("1", "🔍 Nmap Scanner", "Network scanning and security auditing")
            menu_table.add_row("2", "💉 SQLMap Scanner", "SQL injection detection and exploitation")
            menu_table.add_row("3", "📚 User Guide", "Comprehensive documentation and help")
            menu_table.add_row("4", "📁 View Logs", "Browse scan results and history")
            menu_table.add_row("5", "📊 Statistics", "View scan statistics and analytics")
            menu_table.add_row("6", "🌐 Network Info", "Display network configuration")
            menu_table.add_row("7", "🔧 Check Dependencies", "Verify tool installation and versions")
            menu_table.add_row("8", "⚙️  System Install", "Install secscan command system-wide")
            menu_table.add_row("0", "🚪 Exit", "Close the application")
            
            console.print(menu_table)
            
            valid_choices = ["1", "2", "3", "4", "5", "6", "7", "8", "0"]
            choice = self.validate_input("\n[bold yellow]Select an option[/bold yellow]", valid_choices)
            
            if choice == "1":
                if not self.nmap_installed:
                    console.print("\n[bold red]❌ Nmap is not installed![/bold red]")
                    time.sleep(1)
                else:
                    self.nmap_scanner_menu()
            elif choice == "2":
                if not self.sqlmap_installed:
                    console.print("\n[bold red]❌ SQLMap is not installed![/bold red]")
                    time.sleep(1)
                else:
                    self.sqlmap_scanner_menu()
            elif choice == "3":
                self.show_user_guide()
            elif choice == "4":
                self.view_logs()
            elif choice == "5":
                self.scan_statistics()
            elif choice == "6":
                self.network_info()
            elif choice == "7":
                self.check_dependencies()
            elif choice == "8":
                self.install_system_command()
            elif choice == "0":
                self.clear_screen()
                console.print("\n")
                goodbye_text = Text()
                goodbye_text.append("🛡️  ", style="bold cyan")
                goodbye_text.append("Thank you for using Security Scan Automator!", style="bold cyan")
                goodbye_text.append("  🛡️", style="bold cyan")
                console.print(Align.center(goodbye_text))
                console.print(Align.center("[cyan]Stay secure and hack responsibly![/cyan]"))
                console.print(Align.center(f"[dim]Created by {self.author}[/dim]"))
                console.print("\n")
                sys.exit(0)
    
    def run(self):
        try:
            self.check_dependencies()
            self.main_menu()
        except KeyboardInterrupt:
            console.print("\n\n[bold yellow]⚠️  Interrupted by user[/bold yellow]")
            console.print("[cyan]Exiting gracefully...[/cyan]\n")
            sys.exit(0)
        except Exception as e:
            console.print(f"\n[bold red]❌ Fatal Error: {str(e)}[/bold red]")
            console.print("[yellow]Check logs for details[/yellow]\n")
            sys.exit(1)

if __name__ == "__main__":
    scanner = SecurityScanner()
    scanner.run()

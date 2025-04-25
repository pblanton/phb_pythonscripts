"""
This script is used to generate a directory tree structure.
Created by Phillip H. Blanton
Copyright ©2025, Phillip H. Blanton, All rights reversed.

Usage:
python directoryparser.py -o output.txt -d 3 -t 60 -f --workers 10 -a

-o: Output file to save the tree structure
-d: Maximum depth to scan (default: unlimited)
-t: Timeout in seconds for each directory scan (default: 60)
-f: Follow symbolic links (default: ignore them)
--workers: Number of worker threads for parallel scanning (default: 10)
-a: Show hidden directories (default: hide them)
-s: Show security findings (default: hide them)

Launch script with '-h' for help.
"""

import os
import argparse
import concurrent.futures
import time
from pathlib import Path
import threading
import subprocess
import platform
import sys
import ctypes

# Security-related keywords to look for in directory names
SECURITY_KEYWORDS = [
    'secret', 'private', 'secure', 'security', 'password',
    'credential', 'cert', 'certificate', 'key', 'token',
    'auth', 'oauth', 'ssh', 'ssl', 'tls', 'confidential',
    'sensitive', 'restricted', '.env', 'vault'
]

def is_windows_terminal():
    """Check if running in Windows Terminal or similar modern terminal."""
    if platform.system() != 'Windows':
        return False
    try:
        # Check if we're in Windows Terminal or similar
        kernel32 = ctypes.windll.kernel32
        return kernel32.GetConsoleMode(kernel32.GetStdHandle(-11), ctypes.byref(ctypes.c_ulong())) != 0
    except:
        return False

class DirectoryScanner:
    def __init__(self, max_depth=None, timeout=60, follow_symlinks=False, max_workers=10, show_hidden=False, show_security=False):
        self.max_depth = max_depth
        self.timeout = timeout
        self.follow_symlinks = follow_symlinks  
        self.max_workers = max_workers
        self.show_hidden = show_hidden
        self.show_security = show_security
        self._stop_event = threading.Event()
        self._progress = 0
        self._total = 0
        self._lock = threading.Lock()
        self.security_findings = []  # New list to store security findings
        # Use ASCII characters for Windows cmd, Unicode for others
        self.use_unicode = not platform.system() == 'Windows' or is_windows_terminal()
        self.tree_chars = {
            'branch': '├─ ' if self.use_unicode else '+--',
            'last': '└─ ' if self.use_unicode else '\\--',
            'vertical': '│  ' if self.use_unicode else '|  ',
            'space': '   '
        }

    def check_security_keywords(self, path_name):
        """Check if the directory name contains any security-related keywords."""
        path_lower = path_name.lower()
        return any(keyword in path_lower for keyword in SECURITY_KEYWORDS)

    def scan_directory(self, start_path, current_depth=0, prefix=''):
        """Recursively scan directory with timeout and depth limit."""
        if self._stop_event.is_set():
            return []
        
        if self.max_depth is not None and current_depth > self.max_depth:
            return []

        try:
            # Use pathlib for better path handling
            path = Path(start_path)
            if not path.exists():
                return []

            tree = []
            try:
                entries = sorted(path.iterdir())
                if not self.show_hidden:
                    entries = [e for e in entries if not e.name.startswith('.')]
            except (PermissionError, OSError):
                return []

            with self._lock:
                self._total += 1

            for i, entry in enumerate(entries):
                if self._stop_event.is_set():
                    return tree

                is_last = i == len(entries) - 1
                entry_path = entry

                # Handle symlinks based on follow_symlinks setting
                if entry_path.is_symlink():
                    if not self.follow_symlinks:
                        tree.append(f"{prefix}{self.tree_chars['last' if is_last else 'branch']}{entry_path.name}/ [symlink]")
                        continue
                    else:
                        try:
                            resolved_path = entry_path.resolve()
                            if not resolved_path.exists():
                                tree.append(f"{prefix}{self.tree_chars['last' if is_last else 'branch']}{entry_path.name}/ [broken symlink]")
                                continue
                            entry_path = resolved_path
                        except Exception:
                            tree.append(f"{prefix}{self.tree_chars['last' if is_last else 'branch']}{entry_path.name}/ [unresolvable symlink]")
                            continue

                if entry_path.is_dir():
                    # Check for security-related keywords in directory name
                    if self.show_security and self.check_security_keywords(entry_path.name):
                        self.security_findings.append(str(entry_path))
                    
                    # Add directory to tree
                    tree.append(f"{prefix}{self.tree_chars['last' if is_last else 'branch']}{entry_path.name}/")
                    
                    # Recursively get subdirectories
                    extension = self.tree_chars['space'] if is_last else self.tree_chars['vertical']
                    try:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                            future = executor.submit(
                                self.scan_directory,
                                str(entry_path),
                                current_depth + 1,
                                prefix + extension
                            )
                            try:
                                sub_tree = future.result(timeout=self.timeout)
                                tree.extend(sub_tree)
                            except concurrent.futures.TimeoutError:
                                tree.append(f"{prefix + extension}{self.tree_chars['last']}[Scan timeout]")
                                self._stop_event.set()
                    except Exception as e:
                        tree.append(f"{prefix + extension}{self.tree_chars['last']}[Error: {str(e)}]")

                with self._lock:
                    self._progress += 1

            return tree
        except Exception as e:
            return [f"{prefix}{self.tree_chars['last']}[Error: {str(e)}]"]

    def get_progress(self):
        """Get current scan progress in terms of directories found."""
        with self._lock:
            return self._progress

    def get_total_directories(self):
        """Get total number of directories found."""
        with self._lock:
            return self._progress

def display_with_more(text):
    """Display text using more command in a cross-platform way."""
    if platform.system() == 'Windows':
        # On Windows, use more command with specific options
        process = subprocess.Popen(['more'], stdin=subprocess.PIPE, shell=True)
        process.communicate(input=text.encode('utf-8', errors='replace'))
    else:
        # On Unix-like systems, use more or less if available
        try:
            process = subprocess.Popen(['less'], stdin=subprocess.PIPE)
            process.communicate(input=text.encode('utf-8', errors='replace'))
        except FileNotFoundError:
            # Fallback to more if less is not available
            process = subprocess.Popen(['more'], stdin=subprocess.PIPE)
            process.communicate(input=text.encode('utf-8', errors='replace'))

def main():
    # Set console output encoding to UTF-8 on Windows
    use_unicode = True
    if platform.system() == 'Windows':
        if sys.stdout.encoding != 'utf-8':
            try:
                sys.stdout.reconfigure(encoding='utf-8')
            except:
                use_unicode = False
                pass  # Ignore if reconfiguration fails

    parser = argparse.ArgumentParser(description='Generate a directory tree structure')
    parser.add_argument('-o', '--output', help='Output file to save the tree structure')
    parser.add_argument('-d', '--depth', type=int, help='Maximum depth to scan (default: unlimited)')
    parser.add_argument('-t', '--timeout', type=int, default=60, help='Timeout in seconds for each directory scan (default: 60)')
    parser.add_argument('-f', '--follow-symlinks', action='store_true', help='Follow symbolic links (default: ignore them)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of worker threads for parallel scanning (default: 10)')
    parser.add_argument('-a', '--all', action='store_true', help='Show hidden directories (default: hide them)')
    parser.add_argument('-s', '--security', action='store_true', help='Show security findings (default: hide them)')
    args = parser.parse_args()
    
    # Get current directory
    current_dir = os.getcwd()
    
    # Create scanner instance
    scanner = DirectoryScanner(
        max_depth=args.depth,
        timeout=args.timeout,
        follow_symlinks=args.follow_symlinks,
        max_workers=args.workers,
        show_hidden=args.all,
        show_security=args.security
    )
    
    # Force ASCII mode if Unicode encoding failed
    if not use_unicode:
        scanner.use_unicode = False
        scanner.tree_chars = {
            'branch': '+--',
            'last': '\\--',
            'vertical': '|  ',
            'space': '   '
        }
    
    # Start progress display thread
    def show_progress():
        while not scanner._stop_event.is_set():
            directories_found = scanner.get_progress()
            print(f"\rDirectories found: {directories_found}", end='')
            time.sleep(0.1)
    
    progress_thread = threading.Thread(target=show_progress)
    progress_thread.daemon = True
    progress_thread.start()
    
    # Generate tree structure
    tree = [current_dir + os.sep]  # Use os.sep for platform-specific separator
    tree.extend(scanner.scan_directory(current_dir))
    
    # Stop progress display
    scanner._stop_event.set()
    progress_thread.join()
    print("\r" + " " * 30 + "\r", end='')  # Clear progress line
    
    # Get total directory count
    total_directories = scanner.get_total_directories()
    
    # Join tree elements with newlines
    tree_str = '\n'.join(tree)
    
    # Write to file if specified
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(f"Total directories found: {total_directories}\n\n")

                # Write security findings if any...
                if scanner.security_findings:
                    f.write("POTENTIAL SECURITY FINDINGS\n")
                    f.write("=========================\n")
                    for finding in scanner.security_findings:
                        f.write(f"- {finding}\n")
                    f.write("\n\n")
                
                # Write directory tree...
                f.write("DIRECTORY TREE\n")
                f.write("==============\n")
                f.write(tree_str)

            print(f"\nTree structure has been written to {args.output}")
        except Exception as e:
            print(f"Error writing to file: {e}")
    else:
        print(f"Total directories found: {total_directories}\n\n")
        # Display security findings first
        if scanner.security_findings:
            print("POTENTIAL SECURITY FINDINGS")
            print("=========================")
            for finding in scanner.security_findings:
                print(f"- {finding}")
            print("\n\n")
        
        # Display tree with more command
        display_with_more(tree_str)

if __name__ == '__main__':
    main() 
    
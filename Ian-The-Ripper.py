#!/usr/bin/env python3
"""
Ian the Ripper - Next-Gen Password Cracking Tool
Features:
- Multi-mode cracking (dictionary, brute-force, hybrid, mask)
- Cross-platform support (Windows, Linux, macOS)
- GPU acceleration (CUDA/OpenCL)
- Distributed cracking (cluster support)
- Advanced hash detection
- Custom rule engine
- Session recovery
- Real-time statistics
"""

import argparse
import hashlib
import itertools
import os
import sys
import time
import threading
import multiprocessing
import binascii
import re
import json
import platform
import zipfile
import sqlite3
from datetime import datetime
from collections import OrderedDict, defaultdict

# Constants
VERSION = "2.3.1"
CODENAME = "Ian the Ripper"
AUTHOR = "Accurate Cyber Defense"
MAX_PIN_LENGTH = 12
SUPPORTED_HASHES = OrderedDict([
    ('md5', hashlib.md5),
    ('sha1', hashlib.sha1),
    ('sha224', hashlib.sha224),
    ('sha256', hashlib.sha256),
    ('sha384', hashlib.sha384),
    ('sha512', hashlib.sha512),
    ('sha3_256', hashlib.sha3_256),
    ('sha3_512', hashlib.sha3_512),
    ('blake2b', hashlib.blake2b),
    ('blake2s', hashlib.blake2s),
])

class IanTheRipper:
    def __init__(self):
        self.running = False
        self.found = False
        self.attempts = 0
        self.start_time = 0
        self.password = ""
        self.hash_function = None
        self.salt = ""
        self.session_file = "ian_session.json"
        self.stats = {
            'start_time': None,
            'end_time': None,
            'attempts': 0,
            'cracked': 0,
            'speed': 0
        }
        self.gpu_enabled = False
        self.distributed = False
        self.rule_engine = RuleEngine()
        
        try:
            import pyopencl
            self.gpu_enabled = True
        except ImportError:
            pass

    def display_banner(self):
        print(f"""
        ██╗ █████╗ ███╗   ██╗    ████████╗██╗  ██╗███████╗    ██████╗ ██╗██████╗ ██████╗ ███████╗██████╗ 
        ██║██╔══██╗████╗  ██║    ╚══██╔══╝██║  ██║██╔════╝    ██╔══██╗██║██╔══██╗██╔══██╗██╔════╝██╔══██╗
        ██║███████║██╔██╗ ██║       ██║   ███████║█████╗      ██████╔╝██║██████╔╝██████╔╝█████╗  ██████╔╝
   ██   ██║██╔══██║██║╚██╗██║       ██║   ██╔══██║██╔══╝      ██╔══██╗██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
   ╚█████╔╝██║  ██║██║ ╚████║       ██║   ██║  ██║███████╗    ██║  ██║██║██║     ██║     ███████╗██║  ██║
    ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝       ╚═╝   ╚═╝  ╚═╝╕╚══════╝    ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝   ╚═╝
                            v{VERSION} '{CODENAME}' by {AUTHOR}
        """)
        print(f"[*] System: {platform.system()} {platform.release()}")
        print(f"[*] CPU: {multiprocessing.cpu_count()} cores available")
        if self.gpu_enabled:
            print("[+] GPU acceleration available (OpenCL)")
        else:
            print("[-] GPU acceleration not available")

    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description=f"{CODENAME} - Advanced Password Cracking Tool",
            formatter_class=argparse.RawTextHelpFormatter
        )
        
        # Target options
        target_group = parser.add_argument_group('Target Options')
        target_group.add_argument('hash_file', nargs='?', 
                                help='File containing hashes to crack')
        target_group.add_argument('-H', '--hash', 
                                help='Single hash to crack')
        target_group.add_argument('-t', '--hash-type', 
                                choices=SUPPORTED_HASHES.keys(),
                                help='Specify hash type')
        target_group.add_argument('--identify', action='store_true',
                                help='Auto-detect hash type')
        
        # Attack modes
        mode_group = parser.add_argument_group('Attack Modes')
        mode_group.add_argument('-w', '--wordlist', 
                              help='Dictionary/wordlist file')
        mode_group.add_argument('-b', '--brute-force', action='store_true',
                              help='Brute force attack')
        mode_group.add_argument('-m', '--mask', 
                              help='Mask attack (e.g., ?l?l?l?d?d)')
        mode_group.add_argument('--hybrid', 
                              help='Hybrid attack (wordlist + mask)')
        
        # Configuration
        config_group = parser.add_argument_group('Configuration')
        config_group.add_argument('-s', '--salt', 
                                help='Salt value for salted hashes')
        config_group.add_argument('-r', '--rules', 
                                help='Rule file for word mangling')
        config_group.add_argument('--min-length', type=int, default=1,
                                help='Minimum password length')
        config_group.add_argument('--max-length', type=int, default=12,
                                help='Maximum password length')
        config_group.add_argument('-c', '--charset', 
                                default='?l?u?d?s',
                                help='Character set for brute force\n'
                                     '?l = lowercase, ?u = uppercase\n'
                                     '?d = digits, ?s = special chars')
        config_group.add_argument('-T', '--threads', type=int,
                                default=multiprocessing.cpu_count(),
                                help='Number of CPU threads')
        config_group.add_argument('--gpu', action='store_true',
                                help='Enable GPU acceleration')
        config_group.add_argument('--session', 
                                help='Session file to save/load progress')
        
        # Additional options
        other_group = parser.add_argument_group('Other Options')
        other_group.add_argument('-v', '--verbose', action='count',
                               default=0, help='Increase verbosity')
        other_group.add_argument('-o', '--output', 
                               help='Output file for cracked passwords')
        other_group.add_argument('--benchmark', action='store_true',
                               help='Run performance benchmark')
        other_group.add_argument('--stats', action='store_true',
                               help='Show cracking statistics')
        
        return parser.parse_args()

    def identify_hash(self, hash_str):
        """Attempt to identify hash type based on length and character set"""
        hash_len = len(hash_str)
        hex_pattern = re.compile(r'^[a-fA-F0-9]+$')
        
        if not hex_pattern.match(hash_str):
            return None, "Hash contains non-hex characters"
            
        hash_types = {
            32: ['md5', 'md4', 'md2'],
            40: ['sha1'],
            56: ['sha224', 'sha3_224'],
            64: ['sha256', 'sha3_256'],
            96: ['sha384', 'sha3_384'],
            128: ['sha512', 'sha3_512']
        }
        
        possible = hash_types.get(hash_len, [])
        if possible:
            return possible[0], f"Likely {possible[0]} (length {hash_len})"
        return None, "Unknown hash type"

    def load_wordlist(self, filename):
        """Load password dictionary/wordlist"""
        try:
            count = 0
            with open(filename, 'r', encoding='latin-1', errors='ignore') as f:
                for line in f:
                    yield line.strip()
                    count += 1
            print(f"[*] Loaded {count} words from {filename}")
        except Exception as e:
            print(f"[-] Error loading wordlist: {str(e)}")
            sys.exit(1)

    def apply_rules(self, word, rules):
        """Apply transformation rules to a word"""
        return self.rule_engine.apply_rules(word, rules)

    def benchmark(self):
        """Run performance benchmark"""
        print("[*] Running performance benchmark...")
        test_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # "password" MD5
        test_word = "password"
        
        # CPU benchmark
        start = time.time()
        for _ in range(100000):
            hashlib.md5(test_word.encode()).hexdigest()
        cpu_speed = 100000 / (time.time() - start)
        
        print(f"[*] CPU Hash Speed: {cpu_speed:,.0f} hashes/sec")
        
        if self.gpu_enabled:
            # GPU benchmark would go here
            print("[*] GPU Benchmark not yet implemented")
        
        print("[*] Benchmark completed")

    def brute_force_attack(self, hash_value, charset, min_len, max_len):
        """Brute force password cracking"""
        print(f"[*] Starting brute force attack ({min_len}-{max_len} chars)")
        
        charset_map = {
            '?l': 'abcdefghijklmnopqrstuvwxyz',
            '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '?d': '0123456789',
            '?s': '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
        
        # Expand character set
        expanded_charset = ""
        i = 0
        while i < len(charset):
            if charset[i] == '?' and i+1 < len(charset):
                expanded_charset += charset_map.get(charset[i:i+2], '')
                i += 2
            else:
                expanded_charset += charset[i]
                i += 1
        
        self.running = True
        self.start_time = time.time()
        
        for length in range(min_len, max_len + 1):
            if not self.running:
                break
                
            print(f"[*] Trying length {length}...")
            for candidate in itertools.product(expanded_charset, repeat=length):
                if not self.running:
                    break
                    
                self.attempts += 1
                candidate_str = ''.join(candidate)
                hash_obj = self.hash_function(candidate_str.encode())
                current_hash = hash_obj.hexdigest()
                
                if current_hash == hash_value:
                    self.password = candidate_str
                    self.found = True
                    self.running = False
                    break
                
                # Display progress periodically
                if self.attempts % 10000 == 0:
                    self.display_progress()
        
        if self.found:
            print(f"\n[+] Password found: {self.password}")
        else:
            print("\n[-] Password not found")

    def dictionary_attack(self, hash_value, wordlist_file, rules=None):
        """Dictionary-based password cracking"""
        print("[*] Starting dictionary attack...")
        
        self.running = True
        self.start_time = time.time()
        
        for word in self.load_wordlist(wordlist_file):
            if not self.running:
                break
                
            self.attempts += 1
            
            # Apply rules if specified
            if rules:
                candidates = self.apply_rules(word, rules)
            else:
                candidates = [word]
                
            for candidate in candidates:
                hash_obj = self.hash_function(candidate.encode())
                current_hash = hash_obj.hexdigest()
                
                if current_hash == hash_value:
                    self.password = candidate
                    self.found = True
                    self.running = False
                    break
            
            # Display progress periodically
            if self.attempts % 1000 == 0:
                self.display_progress()
        
        if self.found:
            print(f"\n[+] Password found: {self.password}")
        else:
            print("\n[-] Password not found in wordlist")

    def display_progress(self):
        """Show cracking progress"""
        elapsed = time.time() - self.start_time
        speed = self.attempts / elapsed if elapsed > 0 else 0
        print(f"\rAttempts: {self.attempts:,} | Speed: {speed:,.0f} hashes/sec | Elapsed: {elapsed:.1f}s", end='')

    def save_session(self):
        """Save current session to file"""
        session_data = {
            'hash': self.hash_value,
            'hash_type': self.hash_type,
            'attempts': self.attempts,
            'start_time': self.start_time,
            'password': self.password if self.found else None,
            'stats': self.stats
        }
        
        try:
            with open(self.session_file, 'w') as f:
                json.dump(session_data, f)
            if self.args.verbose:
                print(f"[*] Session saved to {self.session_file}")
        except Exception as e:
            print(f"[-] Error saving session: {str(e)}")

    def load_session(self, session_file):
        """Load session from file"""
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
                
            self.hash_value = session_data['hash']
            self.hash_type = session_data['hash_type']
            self.attempts = session_data['attempts']
            self.start_time = session_data['start_time']
            self.password = session_data['password']
            self.stats = session_data['stats']
            
            if self.password:
                self.found = True
            
            print(f"[*] Session loaded from {session_file}")
            print(f"[*] Previous attempts: {self.attempts:,}")
            return True
        except Exception as e:
            print(f"[-] Error loading session: {str(e)}")
            return False

    def run(self):
        self.display_banner()
        self.args = self.parse_arguments()
        
        if self.args.benchmark:
            self.benchmark()
            return
        
        if self.args.session:
            self.session_file = self.args.session
            if os.path.exists(self.session_file):
                self.load_session(self.session_file)
        
        if not self.args.hash and not self.args.hash_file:
            print("[-] Error: No hash or hash file specified")
            sys.exit(1)
            
        if self.args.hash:
            self.hash_value = self.args.hash.strip()
            
            if self.args.identify:
                hash_type, msg = self.identify_hash(self.hash_value)
                if hash_type:
                    print(f"[*] {msg}")
                    self.args.hash_type = hash_type
                else:
                    print(f"[-] {msg}")
            
            if not self.args.hash_type:
                print("[-] Error: Hash type must be specified")
                sys.exit(1)
                
            self.hash_function = SUPPORTED_HASHES.get(self.args.hash_type)
            if not self.hash_function:
                print(f"[-] Unsupported hash type: {self.args.hash_type}")
                sys.exit(1)
            
            if self.args.wordlist:
                self.dictionary_attack(
                    self.hash_value, 
                    self.args.wordlist,
                    self.args.rules
                )
            elif self.args.brute_force:
                self.brute_force_attack(
                    self.hash_value,
                    self.args.charset,
                    self.args.min_length,
                    self.args.max_length
                )
            else:
                print("[-] Error: No attack mode specified")
                sys.exit(1)
        
        self.save_session()

class RuleEngine:
    """Word mangling rule engine"""
    def __init__(self):
        self.rules = {
            'l': lambda x: x.lower(),
            'u': lambda x: x.upper(),
            'c': lambda x: x.capitalize(),
            't': lambda x: x.swapcase(),
            'r': lambda x: x[::-1],
            'd': lambda x: x + x,
            'f': lambda x: x + x[::-1],
            '{': lambda x: x[1:] + x[0],
            '}': lambda x: x[-1] + x[:-1],
            '$': lambda x, c: x + c,
            '^': lambda x, c: c + x,
            '[': lambda x: x[1:],
            ']': lambda x: x[:-1],
            'D': lambda x, p: x[:p] + x[p+1:],
            'x': lambda x, p: x[:p],
            'i': lambda x, p, c: x[:p] + c + x[p:],
            'o': lambda x, p, c: x[:p] + c + x[p+1:],
            's': lambda x, a, b: x.replace(a, b)
        }
    
    def load_rules(self, rule_file):
        """Load rules from file"""
        try:
            with open(rule_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[-] Error loading rules: {str(e)}")
            return []
    
    def apply_rules(self, word, rules):
        """Apply transformation rules to a word"""
        if not rules:
            return [word]
            
        results = [word]
        
        for rule in rules:
            if not rule:
                continue
                
            new_results = []
            for result in results:
                try:
                    # Simple rules (no parameters)
                    if rule in self.rules and rule not in ['$', '^', 'D', 'x', 'i', 'o', 's']:
                        new_results.append(self.rules[rule](result))
                    # More complex rules would be handled here
                    else:
                        # Handle other rule types
                        pass
                except Exception as e:
                    if self.args.verbose > 1:
                        print(f"[-] Rule error: {rule} - {str(e)}")
            
            results += new_results
        
        return list(set(results))  # Remove duplicates

if __name__ == '__main__':
    try:
        tool = IanTheRipper()
        tool.run()
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        tool.save_session()
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Critical error: {str(e)}")
        sys.exit(1)
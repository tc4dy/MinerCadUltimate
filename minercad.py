# Developed by @tc4dy - Educational and Research Tool

import re
import sys
import os
import json
import time
import socket
import ssl
import dns.resolver
import threading
import requests
import hashlib
import base64
import subprocess
import urllib3
from queue import Queue
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import whois
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ipaddress
import random
import string

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class LanguageManager:
    def __init__(self):
        self.lang = 'en'
        self.translations = {
            'banner': ('ULTIMATE TACTICAL RECONNAISSANCE FRAMEWORK', 'ULTIMATE TAKTİKSEL KEŞİF SİSTEMİ'),
            'version': ('Version 4.0.0 - AI-Powered Deep Intelligence Engine', 'Versiyon 4.0.0 - AI Destekli Derin İstihbarat Motoru'),
            'warning': ('LEGAL: Authorized security research & education only', 'YASAL: Sadece yetkili güvenlik araştırmaları'),
            'lang_select': ('Select Language / Dil Seçin:\n[1] English\n[2] Türkçe\n> ', 'Select Language / Dil Seçin:\n[1] English\n[2] Türkçe\n> '),
            'target': ('Enter target domain: ', 'Hedef domaini girin: '),
            'ai_config': ('AI is configuring optimal scan parameters...', 'AI optimal tarama parametrelerini ayarlıyor...'),
            'dns_enum': ('DNS enumeration in progress...', 'DNS numaralandırması yapılıyor...'),
            'port_scan': ('Port scanning infrastructure...', 'Port taraması yapılıyor...'),
            'ssl_analysis': ('SSL/TLS certificate analysis...', 'SSL/TLS sertifika analizi...'),
            'whois_lookup': ('WHOIS data extraction...', 'WHOIS veri çıkarımı...'),
            'subdomain_brute': ('Subdomain bruteforce attack...', 'Subdomain kaba kuvvet saldırısı...'),
            'tech_fingerprint': ('Technology fingerprinting...', 'Teknoloji parmak izi alınıyor...'),
            'vuln_scan': ('Vulnerability pattern detection...', 'Zafiyet pattern tespiti...'),
            'deep_crawl': ('Deep web crawling initiated...', 'Derin web taraması başlatıldı...'),
            'api_discovery': ('API endpoint discovery...', 'API uç nokta keşfi...'),
            'js_analysis': ('JavaScript analysis & deobfuscation...', 'JavaScript analizi & deobfuscation...'),
            'metadata_extract': ('Metadata extraction from resources...', 'Kaynaklardan metadata çıkarımı...'),
            'complete': ('INTELLIGENCE GATHERING COMPLETE', 'İSTİHBARAT TOPLAMA TAMAMLANDI'),
            'results': ('COMPREHENSIVE OSINT REPORT', 'KAPSAMLI OSINT RAPORU'),
            'duration': ('Total Duration', 'Toplam Süre'),
            'requests': ('HTTP Requests', 'HTTP İstekleri'),
            'data_points': ('Data Points Collected', 'Toplanan Veri Noktası'),
            'menu': ('\n[1] New Scan  [2] Export JSON  [3] Export HTML  [4] Export XML  [5] Statistics  [6] Exit\n> ', 
                    '\n[1] Yeni Tarama  [2] JSON  [3] HTML  [4] XML  [5] İstatistik  [6] Çıkış\n> '),
            'exported': ('Exported:', 'Aktarıldı:'),
            'stats': ('DEEP SCAN STATISTICS', 'DERİN TARAMA İSTATİSTİKLERİ'),
        }
    
    def set_language(self, choice):
        self.lang = 'en' if choice == 1 else 'tr'
    
    def get(self, key):
        return self.translations.get(key, (key, key))[0 if self.lang == 'en' else 1]

class AIConfigManager:
    @staticmethod
    def calculate_optimal_params(domain):
        params = {
            'depth': 4,
            'threads': 15,
            'timeout': 12,
            'rate_limit': 0.1,
            'subdomain_wordlist_size': 5000,
            'port_scan_enabled': True,
            'ssl_analysis_enabled': True,
            'js_analysis_enabled': True,
            'api_discovery_enabled': True,
            'metadata_extraction': True,
            'vulnerability_scan': True,
            'dns_enumeration': True,
            'whois_lookup': True,
            'bruteforce_subdomains': True,
            'screenshot_capture': False,
            'wayback_analysis': True,
            'robots_analysis': True,
            'sitemap_analysis': True,
            'headers_analysis': True,
            'cookie_analysis': True,
            'form_analysis': True,
            'comment_extraction': True,
            'social_engineering_vectors': True,
            'credential_leak_check': True,
            'technology_stack_deep': True,
            'cdn_detection': True,
            'waf_detection': True,
            'cms_detection': True,
            'framework_detection': True,
            'server_fingerprint': True,
        }
        return params

class PatternExtractor:
    def __init__(self):
        self.patterns = {
            'emails': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'phones': re.compile(r'\+?[0-9]{1,4}?[-.\s]?\(?[0-9]{1,3}?\)?[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}'),
            'ipv4': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'ipv6': re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'),
            'aws_keys': re.compile(r'AKIA[0-9A-Z]{16}'),
            'aws_secret': re.compile(r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z\/+]{40}[\'"]'),
            'google_api': re.compile(r'AIza[0-9A-Za-z-_]{35}'),
            'google_oauth': re.compile(r'ya29\.[0-9A-Za-z\-_]+'),
            'firebase': re.compile(r'[a-z0-9-]+\.firebaseio\.com'),
            'stripe_live': re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
            'stripe_test': re.compile(r'sk_test_[0-9a-zA-Z]{24}'),
            'ssh_key': re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
            'github_token': re.compile(r'ghp_[a-zA-Z0-9]{36}'),
            'github_oauth': re.compile(r'gho_[a-zA-Z0-9]{36}'),
            'jwt': re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
            'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
            'slack_token': re.compile(r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}'),
            'slack_webhook': re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'),
            'discord_token': re.compile(r'[MN][a-zA-Z\d]{23,25}\.[a-zA-Z\d]{6}\.[a-zA-Z\d_-]{27}'),
            'discord_webhook': re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+'),
            'telegram_bot': re.compile(r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}'),
            'mailgun_api': re.compile(r'key-[0-9a-zA-Z]{32}'),
            'twilio_api': re.compile(r'SK[0-9a-fA-F]{32}'),
            'paypal_token': re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),
            'square_token': re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}'),
            'square_oauth': re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}'),
            'picatic_api': re.compile(r'sk_live_[0-9a-z]{32}'),
            'heroku_api': re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
            'sendgrid_api': re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
            'npm_token': re.compile(r'npm_[a-zA-Z0-9]{36}'),
            'docker_token': re.compile(r'dckr_pat_[a-zA-Z0-9_-]{36}'),
            'subdomains': re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'),
            'urls': re.compile(r'https?://[^\s<>"\']+'),
            'social_twitter': re.compile(r'(?:https?://)?(?:www\.)?(?:twitter|x)\.com/[a-zA-Z0-9_]+'),
            'social_facebook': re.compile(r'(?:https?://)?(?:www\.)?facebook\.com/[a-zA-Z0-9.]+'),
            'social_linkedin': re.compile(r'(?:https?://)?(?:www\.)?linkedin\.com/(?:in|company)/[a-zA-Z0-9-]+'),
            'social_instagram': re.compile(r'(?:https?://)?(?:www\.)?instagram\.com/[a-zA-Z0-9_.]+'),
            'social_github': re.compile(r'(?:https?://)?(?:www\.)?github\.com/[a-zA-Z0-9-]+'),
            'social_youtube': re.compile(r'(?:https?://)?(?:www\.)?youtube\.com/(?:c|channel|user)/[a-zA-Z0-9-]+'),
            'whatsapp': re.compile(r'(?:https?://)?(?:chat\.)?whatsapp\.com/[a-zA-Z0-9]+'),
            'sql_error': re.compile(r'(?i)(?:SQL syntax|mysql_fetch|Warning: mysql|PostgreSQL.*ERROR|ORA-[0-9]{5}|SQLSTATE|DB2 SQL error|Microsoft SQL Native Client error)'),
            'xss_vulnerable': re.compile(r'<script[^>]*>.*?(?:alert|prompt|confirm)\(.*?\).*?</script>'),
            'lfi_vulnerable': re.compile(r'(?:\.\./|\.\.\\){2,}(?:etc/passwd|boot\.ini|win\.ini)'),
            'rfi_vulnerable': re.compile(r'(?:http|https|ftp)://.*?\.(?:txt|php|asp|aspx)'),
            'xxe_vulnerable': re.compile(r'<!ENTITY.*?SYSTEM'),
            'ssrf_vulnerable': re.compile(r'(?:http|https)://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|192\.168\.)'),
            'api_endpoints': re.compile(r'/api/v?[0-9]*/[a-zA-Z0-9/_-]+'),
            'api_graphql': re.compile(r'/graphql|/v1/graphql'),
            'api_rest': re.compile(r'/rest/|/v[0-9]+/'),
            'env_vars': re.compile(r'(?i)(?:API_KEY|SECRET_KEY|PASSWORD|DB_PASS|TOKEN|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|CONSUMER_KEY)=[^\s&\'"]+'),
            'db_connection': re.compile(r'(?i)(?:mysql|postgresql|mongodb|redis|memcached)://[^\s\'"]+'),
            'internal_ip': re.compile(r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}\b'),
            's3_bucket': re.compile(r'[a-z0-9.-]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com'),
            'azure_storage': re.compile(r'[a-z0-9]+\.blob\.core\.windows\.net'),
            'google_cloud': re.compile(r'[a-z0-9-]+\.storage\.googleapis\.com'),
            'comments_html': re.compile(r'<!--[\s\S]*?-->'),
            'comments_js': re.compile(r'//.*?$|/\*[\s\S]*?\*/', re.MULTILINE),
            'base64': re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
            'version_number': re.compile(r'\b\d+\.\d+\.\d+\b'),
            'file_pdf': re.compile(r'https?://[^\s<>"]+?\.pdf'),
            'file_doc': re.compile(r'https?://[^\s<>"]+?\.(?:doc|docx)'),
            'file_xls': re.compile(r'https?://[^\s<>"]+?\.(?:xls|xlsx)'),
            'file_ppt': re.compile(r'https?://[^\s<>"]+?\.(?:ppt|pptx)'),
            'file_zip': re.compile(r'https?://[^\s<>"]+?\.(?:zip|rar|7z|tar|gz)'),
            'file_sql': re.compile(r'https?://[^\s<>"]+?\.(?:sql|db|sqlite)'),
            'file_backup': re.compile(r'https?://[^\s<>"]+?\.(?:bak|old|backup|~)'),
            'file_config': re.compile(r'https?://[^\s<>"]+?\.(?:config|conf|cfg|ini|yml|yaml|json|xml)'),
            'file_log': re.compile(r'https?://[^\s<>"]+?\.log'),
            'file_key': re.compile(r'https?://[^\s<>"]+?\.(?:pem|key|crt|cer|p12|pfx)'),
            'username': re.compile(r'(?i)(?:user|username|login|email)[\s:=]+[a-zA-Z0-9_.-]+'),
            'password_field': re.compile(r'(?i)(?:password|passwd|pwd)[\s:=]+[^\s]+'),
            'hash_md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'hash_sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'hash_sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        }
        
        self.file_extensions = {
            'documents': ['.pdf', '.docx', '.xlsx', '.xls', '.doc', '.ppt', '.pptx', '.odt', '.ods', '.odp'],
            'databases': ['.sql', '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.bkp', '.dump', '.dbf'],
            'archives': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso', '.dmg', '.pkg'],
            'configs': ['.env', '.config', '.ini', '.yml', '.yaml', '.xml', '.json', '.properties', '.toml'],
            'scripts': ['.js', '.py', '.php', '.asp', '.aspx', '.jsp', '.rb', '.pl', '.sh', '.bash', '.ps1'],
            'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp'],
            'videos': ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm'],
            'audio': ['.mp3', '.wav', '.ogg', '.flac', '.aac', '.wma'],
            'vpn': ['.ovpn', '.conf', '.key', '.crt'],
            'git': ['.git/config', '.gitignore', '.git/HEAD', '.git/index'],
            'svn': ['.svn/entries', '.svn/wc.db'],
            'source_code': ['.c', '.cpp', '.h', '.hpp', '.cs', '.java', '.go', '.rs', '.swift', '.kt'],
            'certificates': ['.pem', '.key', '.crt', '.cer', '.p12', '.pfx', '.jks'],
            'logs': ['.log', '.txt', '.out'],
            'backups': ['.bak', '.old', '.backup', '.~'],
        }
        
        self.technologies = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin', 'wordpress', '/wp-json/'],
            'Joomla': ['joomla', 'components/com_', '/administrator/', 'option=com_'],
            'Drupal': ['drupal', '/sites/default/', '/sites/all/', 'Drupal.settings'],
            'Magento': ['magento', 'Mage.Cookies', '/skin/frontend/'],
            'Shopify': ['shopify', 'cdn.shopify.com', 'myshopify.com'],
            'Wix': ['wix.com', 'parastorage.com'],
            'Squarespace': ['squarespace', 'sqsp.com'],
            'React': ['react', '_react', 'React.createElement', 'reactDOM'],
            'Vue.js': ['vue.js', 'Vue.component', '__vue__', 'Vue.config'],
            'Angular': ['angular', 'ng-app', 'ng-controller', 'ng-model'],
            'jQuery': ['jquery', 'jQuery', '$.ajax'],
            'Bootstrap': ['bootstrap.min', 'bootstrap.css', 'bootstrap.bundle'],
            'Tailwind': ['tailwind', 'tailwindcss'],
            'Material-UI': ['material-ui', '@mui'],
            'Laravel': ['laravel', 'laravel_session', 'XSRF-TOKEN'],
            'Django': ['django', 'csrfmiddlewaretoken', 'django.contrib'],
            'Flask': ['flask', 'werkzeug', 'Jinja2'],
            'Express': ['express', 'x-powered-by: Express'],
            'Next.js': ['next.js', '_next/', '__next'],
            'Nuxt.js': ['nuxt', '__nuxt', '_nuxt/'],
            'Gatsby': ['gatsby', 'gatsby-'],
            'Nginx': ['nginx', 'Server: nginx'],
            'Apache': ['apache', 'Server: Apache'],
            'IIS': ['IIS', 'Server: Microsoft-IIS'],
            'Tomcat': ['tomcat', 'Server: Apache-Coyote'],
            'Cloudflare': ['cloudflare', '__cfduid', 'cf-ray', 'cloudflare-nginx'],
            'Akamai': ['akamai', 'akamaihd'],
            'AWS': ['amazonaws.com', 's3.amazonaws', 'cloudfront.net', 'elasticbeanstalk'],
            'Google Cloud': ['googleapis.com', 'storage.googleapis', 'appspot.com'],
            'Azure': ['azure', 'windows.net', 'azurewebsites'],
            'Heroku': ['heroku', 'herokuapp.com'],
            'Vercel': ['vercel', 'vercel.app'],
            'Netlify': ['netlify', 'netlify.app'],
            'Firebase': ['firebase', 'firebaseio', 'firebaseapp'],
            'Google Analytics': ['google-analytics', 'gtag', 'ga.js', 'analytics.js'],
            'Google Tag Manager': ['googletagmanager', 'gtm.js'],
            'Facebook Pixel': ['facebook', 'fbevents.js', 'fbq('],
            'Hotjar': ['hotjar', 'hj('],
            'Stripe': ['stripe', 'stripe.js', 'js.stripe.com'],
            'PayPal': ['paypal', 'paypalobjects.com'],
            'Varnish': ['varnish', 'X-Varnish'],
            'Redis': ['redis'],
            'Memcached': ['memcached'],
            'MongoDB': ['mongodb'],
            'MySQL': ['mysql'],
            'PostgreSQL': ['postgresql', 'postgres'],
            'PHP': ['.php', 'X-Powered-By: PHP'],
            'ASP.NET': ['asp.net', '__VIEWSTATE', 'aspx'],
            'Node.js': ['node.js', 'X-Powered-By: Express'],
            'Python': ['.py'],
            'Ruby': ['.rb', 'X-Powered-By: Phusion Passenger'],
            'Java': ['.jsp', '.do', 'jsessionid'],
            'Perl': ['.pl', '.cgi'],
        }
    
    def extract_all(self, content, base_domain):
        results = defaultdict(set)
        
        for name, pattern in self.patterns.items():
            try:
                matches = pattern.findall(content.lower() if name in ['sql_error', 'xss_vulnerable', 'lfi_vulnerable'] else content)
                if name == 'subdomains':
                    matches = [m for m in matches if base_domain in m and m != base_domain and len(m.split('.')) >= 2]
                elif name == 'phones':
                    matches = [m for m in matches if 10 <= len(re.sub(r'[^0-9]', '', m)) <= 20]
                elif name == 'base64' and matches:
                    matches = [m for m in matches if len(m) > 20 and len(m) % 4 == 0][:50]
                results[name].update(matches)
            except:
                pass
        
        for category, extensions in self.file_extensions.items():
            for ext in extensions:
                if ext in content.lower():
                    pattern = re.compile(rf'https?://[^\s<>"\']+{re.escape(ext)}', re.IGNORECASE)
                    files = pattern.findall(content)
                    results[f'files_{category}'].update(files)
        
        for tech, signatures in self.technologies.items():
            if any(sig.lower() in content.lower() for sig in signatures):
                results['technologies'].add(tech)
        
        return results

class DNSEnumerator:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
    
    def enumerate(self, domain):
        results = {
            'dns_a': set(),
            'dns_aaaa': set(),
            'dns_mx': set(),
            'dns_ns': set(),
            'dns_txt': set(),
            'dns_cname': set(),
            'dns_soa': set(),
        }
        
        record_types = {
            'A': 'dns_a',
            'AAAA': 'dns_aaaa',
            'MX': 'dns_mx',
            'NS': 'dns_ns',
            'TXT': 'dns_txt',
            'CNAME': 'dns_cname',
            'SOA': 'dns_soa',
        }
        
        for rtype, key in record_types.items():
            try:
                answers = self.resolver.resolve(domain, rtype)
                for rdata in answers:
                    results[key].add(str(rdata))
            except:
                pass
        
        return results

class SSLAnalyzer:
    @staticmethod
    def analyze(domain, port=443):
        results = {
            'ssl_version': None,
            'ssl_cipher': None,
            'ssl_issuer': None,
            'ssl_subject': None,
            'ssl_sans': set(),
            'ssl_valid_from': None,
            'ssl_valid_to': None,
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    results['ssl_version'] = ssock.version()
                    results['ssl_cipher'] = ssock.cipher()[0]
                    
                    if cert:
                        results['ssl_issuer'] = dict(x[0] for x in cert.get('issuer', []))
                        results['ssl_subject'] = dict(x[0] for x in cert.get('subject', []))
                        results['ssl_valid_from'] = cert.get('notBefore')
                        results['ssl_valid_to'] = cert.get('notAfter')
                        
                        for san in cert.get('subjectAltName', []):
                            if san[0] == 'DNS':
                                results['ssl_sans'].add(san[1])
        except:
            pass
        
        return results

class WhoisAnalyzer:
    @staticmethod
    def analyze(domain):
        results = {
            'whois_registrar': None,
            'whois_created': None,
            'whois_updated': None,
            'whois_expires': None,
            'whois_nameservers': set(),
            'whois_emails': set(),
        }
        
        try:
            w = whois.whois(domain)
            results['whois_registrar'] = w.registrar
            results['whois_created'] = str(w.creation_date) if w.creation_date else None
            results['whois_updated'] = str(w.updated_date) if w.updated_date else None
            results['whois_expires'] = str(w.expiration_date) if w.expiration_date else None
            
            if w.name_servers:
                results['whois_nameservers'].update(w.name_servers if isinstance(w.name_servers, list) else [w.name_servers])
            
            if w.emails:
                results['whois_emails'].update(w.emails if isinstance(w.emails, list) else [w.emails])
        except:
            pass
        
        return results

class SubdomainBruteforcer:
    def __init__(self, domain, threads=10):
        self.domain = domain
        self.threads = threads
        self.found = set()
        self.wordlist = self.generate_wordlist()
    
    def generate_wordlist(self):
        common = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 
                 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'admin', 'api', 'dev', 
                 'staging', 'test', 'beta', 'demo', 'blog', 'shop', 'store', 'cdn', 'static', 
                 'assets', 'images', 'img', 'media', 'files', 'download', 'downloads', 'docs',
                 'portal', 'dashboard', 'panel', 'control', 'manage', 'app', 'mobile', 'm',
                 'secure', 'vpn', 'remote', 'cloud', 'server', 'host', 'web', 'email',
                 'support', 'help', 'wiki', 'forum', 'community', 'news', 'marketing',
                 'sales', 'crm', 'erp', 'hr', 'finance', 'accounting', 'billing',
                 'payment', 'checkout', 'cart', 'shop', 'ecommerce', 'catalog',
                 'search', 'elasticsearch', 'kibana', 'grafana', 'prometheus',
                 'jenkins', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence', 'nexus', 'artifactory',
                 'monitoring', 'metrics', 'logs', 'alerts', 'status']
        
        prefixes = ['admin', 'test', 'dev', 'staging', 'prod', 'uat', 'qa', 'demo', 'temp', 'old', 'new', 'backup', 'archive']
        suffixes = ['01', '02', '1', '2', 'v1', 'v2', 'new', 'old', 'test', 'prod', 'backup']
        
        wordlist = set(common)
        for word in common[:30]:
            for prefix in prefixes:
                wordlist.add(f"{prefix}{word}")
                wordlist.add(f"{prefix}-{word}")
            for suffix in suffixes:
                wordlist.add(f"{word}{suffix}")
                wordlist.add(f"{word}-{suffix}")
        
        return list(wordlist)
    
    def check_subdomain(self, subdomain):
        try:
            full_domain = f"{subdomain}.{self.domain}"
            socket.gethostbyname(full_domain)
            return full_domain
        except:
            return None
    
    def bruteforce(self):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_subdomain, sub): sub for sub in self.wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.found.add(result)
        return self.found

class PortScanner:
    @staticmethod
    def scan(domain, ports=None):
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 27017]
        
        results = {'open_ports': set(), 'closed_ports': set()}
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    results['open_ports'].add(port)
                else:
                    results['closed_ports'].add(port)
                sock.close()
            except:
                pass
        
        return results

class WebCrawler:
    def __init__(self, config):
        self.config = config
        self.visited = set()
        self.lock = threading.Lock()
        self.results = defaultdict(set)
        self.request_count = 0
        self.session = self.create_session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'MinerCad/4.0 (Security Research; +https://github.com/tc4dy)',
        ]
    
    def create_session(self):
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session
    
    def get_random_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
    
    def normalize_url(self, url, base_url):
        if not url or url.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
            return None
        if url.startswith('http'):
            return url
        return urljoin(base_url, url)
    
    def extract_links(self, content, base_url):
        links = set()
        try:
            soup = BeautifulSoup(content, 'html.parser')
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'frame']):
                for attr in ['href', 'src', 'data-src', 'data-href']:
                    url = tag.get(attr)
                    if url:
                        normalized = self.normalize_url(url, base_url)
                        if normalized:
                            links.add(normalized)
        except:
            pass
        return links
    
    def extract_forms(self, content):
        forms = []
        try:
            soup = BeautifulSoup(content, 'html.parser')
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text'),
                        'value': input_field.get('value', ''),
                    })
                forms.append(form_data)
        except:
            pass
        return forms
    
    def extract_cookies(self, response):
        cookies = {}
        for cookie in response.cookies:
            cookies[cookie.name] = {
                'value': cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httponly': hasattr(cookie, 'httponly') and cookie.httponly,
            }
        return cookies
    
    def analyze_headers(self, headers):
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'XFO',
            'X-Content-Type-Options': 'XCTO',
            'X-XSS-Protection': 'XXSSP',
            'Referrer-Policy': 'RP',
            'Permissions-Policy': 'PP',
        }
        
        results = {
            'present': [],
            'missing': [],
            'server': headers.get('Server', 'Unknown'),
            'powered_by': headers.get('X-Powered-By', 'Unknown'),
        }
        
        for header, name in security_headers.items():
            if header in headers:
                results['present'].append(f"{name}: {headers[header]}")
            else:
                results['missing'].append(name)
        
        return results
    
    def detect_waf(self, headers, content):
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'Akamai': ['akamai', 'akamaighost'],
            'AWS WAF': ['awselb', 'x-amz-'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'Incapsula': ['incap_ses', 'visid_incap'],
            'ModSecurity': ['mod_security', 'NOYB'],
            'Barracuda': ['barracuda'],
            'F5 BIG-IP': ['BigIP', 'F5'],
            'Fortinet': ['fortigate', 'fortiweb'],
        }
        
        detected = set()
        for waf, signatures in waf_signatures.items():
            for sig in signatures:
                if any(sig.lower() in str(v).lower() for v in headers.values()):
                    detected.add(waf)
                if sig.lower() in content.lower():
                    detected.add(waf)
        
        return detected
    
    def analyze_robots_txt(self, domain):
        results = {'disallowed': set(), 'allowed': set(), 'sitemaps': set()}
        try:
            response = self.session.get(f"https://{domain}/robots.txt", 
                                       headers=self.get_random_headers(), 
                                       timeout=self.config['timeout'], 
                                       verify=False)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            results['disallowed'].add(path)
                    elif line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            results['allowed'].add(path)
                    elif line.startswith('Sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        if sitemap:
                            results['sitemaps'].add(sitemap)
        except:
            pass
        return results
    
    def analyze_sitemap(self, sitemap_url):
        urls = set()
        try:
            response = self.session.get(sitemap_url, 
                                       headers=self.get_random_headers(), 
                                       timeout=self.config['timeout'], 
                                       verify=False)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'xml')
                for loc in soup.find_all('loc'):
                    urls.add(loc.text)
        except:
            pass
        return urls
    
    def fetch(self, url):
        try:
            response = self.session.get(url, 
                                       headers=self.get_random_headers(), 
                                       timeout=self.config['timeout'], 
                                       verify=False, 
                                       allow_redirects=True)
            self.request_count += 1
            
            time.sleep(self.config['rate_limit'])
            
            return {
                'content': response.text,
                'headers': dict(response.headers),
                'status_code': response.status_code,
                'cookies': self.extract_cookies(response),
                'final_url': response.url,
            }
        except:
            return None
    
    def crawl_url(self, url, depth, base_domain, extractor):
        if depth >= self.config['depth'] or url in self.visited:
            return
        
        with self.lock:
            if url in self.visited:
                return
            self.visited.add(url)
        
        response_data = self.fetch(url)
        if not response_data:
            return
        
        content = response_data['content']
        headers = response_data['headers']
        
        extracted = extractor.extract_all(content, base_domain)
        with self.lock:
            for key, values in extracted.items():
                self.results[key].update(values)
            
            self.results['http_headers'].update([f"{k}: {v}" for k, v in headers.items()])
            
            header_analysis = self.analyze_headers(headers)
            self.results['security_headers_present'].update(header_analysis['present'])
            self.results['security_headers_missing'].update(header_analysis['missing'])
            self.results['server_info'].add(header_analysis['server'])
            
            waf = self.detect_waf(headers, content)
            self.results['waf_detected'].update(waf)
            
            forms = self.extract_forms(content)
            for form in forms:
                form_str = f"{form['method']} {form['action']} - Inputs: {len(form['inputs'])}"
                self.results['forms'].add(form_str)
            
            for cookie_name, cookie_data in response_data['cookies'].items():
                cookie_str = f"{cookie_name} (Secure: {cookie_data['secure']}, HttpOnly: {cookie_data['httponly']})"
                self.results['cookies'].add(cookie_str)
        
        if depth + 1 < self.config['depth']:
            links = self.extract_links(content, url)
            domain_links = [link for link in links if base_domain in link]
            
            with ThreadPoolExecutor(max_workers=self.config['threads']) as executor:
                futures = [executor.submit(self.crawl_url, link, depth + 1, base_domain, extractor) 
                          for link in domain_links[:50]]
                for future in as_completed(futures):
                    pass
    
    def crawl(self, start_url, base_domain, lang_manager):
        extractor = PatternExtractor()
        
        print(f"\n\033[1;32m[◆]\033[0m {lang_manager.get('deep_crawl')}")
        
        if self.config['robots_analysis']:
            print(f"\033[1;32m[◆]\033[0m Analyzing robots.txt...")
            robots = self.analyze_robots_txt(base_domain)
            self.results['robots_disallowed'].update(robots['disallowed'])
            self.results['robots_sitemaps'].update(robots['sitemaps'])
            
            for sitemap in list(robots['sitemaps'])[:5]:
                sitemap_urls = self.analyze_sitemap(sitemap)
                self.results['sitemap_urls'].update(sitemap_urls)
        
        self.crawl_url(start_url, 0, base_domain, extractor)
        
        return self.results, self.request_count

class JavaScriptAnalyzer:
    @staticmethod
    def analyze(js_content):
        results = {
            'js_endpoints': set(),
            'js_secrets': set(),
            'js_comments': set(),
            'js_functions': set(),
        }
        
        endpoint_patterns = [
            r'["\']/(api|v1|v2|rest|graphql)/[^"\']+["\']',
            r'https?://[^"\']+/api[^"\']*',
        ]
        
        secret_patterns = [
            r'(?i)(api[_-]?key|secret|token|password)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'(?i)(access[_-]?token)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, js_content)
            results['js_endpoints'].update([m if isinstance(m, str) else m[0] for m in matches])
        
        for pattern in secret_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple) and len(match) > 1:
                    results['js_secrets'].add(f"{match[0]}: {match[1]}")
        
        comments = re.findall(r'//.*?$|/\*[\s\S]*?\*/', js_content, re.MULTILINE)
        results['js_comments'].update([c.strip() for c in comments if len(c.strip()) > 10][:20])
        
        functions = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\(', js_content)
        results['js_functions'].update(functions[:30])
        
        return results

class ReportGenerator:
    def __init__(self, lang_manager):
        self.lang = lang_manager
    
    def print_console(self, data, domain, duration, requests):
        print("\n\n\033[1;35m" + "═" * 100 + "\033[0m")
        print(f"\033[1;35m  {self.lang.get('results')}\033[0m")
        print(f"\033[1;33m  Target: {domain}\033[0m")
        print(f"\033[1;36m  Scan Duration: {duration:.2f}s | Requests: {requests} | Data Points: {sum(len(v) for v in data.values())}\033[0m")
        print("\033[1;35m" + "═" * 100 + "\033[0m\n")
        
        categories = {
            '🔐 CREDENTIALS & SECRETS': {
                'AWS Access Keys': 'aws_keys',
                'AWS Secrets': 'aws_secret',
                'Google API Keys': 'google_api',
                'Google OAuth': 'google_oauth',
                'Firebase URLs': 'firebase',
                'Stripe Live Keys': 'stripe_live',
                'Stripe Test Keys': 'stripe_test',
                'SSH Private Keys': 'ssh_key',
                'GitHub Tokens': 'github_token',
                'GitHub OAuth': 'github_oauth',
                'JWT Tokens': 'jwt',
                'Slack Tokens': 'slack_token',
                'Slack Webhooks': 'slack_webhook',
                'Discord Tokens': 'discord_token',
                'Discord Webhooks': 'discord_webhook',
                'Telegram Bot Tokens': 'telegram_bot',
                'Mailgun API Keys': 'mailgun_api',
                'Twilio API Keys': 'twilio_api',
                'PayPal Tokens': 'paypal_token',
                'Square Tokens': 'square_token',
                'SendGrid API Keys': 'sendgrid_api',
                'NPM Tokens': 'npm_token',
                'Docker Tokens': 'docker_token',
            },
            '💳 SENSITIVE DATA': {
                'Credit Cards': 'credit_card',
                'Environment Variables': 'env_vars',
                'Database Connections': 'db_connection',
                'Usernames Found': 'username',
                'Password Fields': 'password_field',
                'MD5 Hashes': 'hash_md5',
                'SHA1 Hashes': 'hash_sha1',
                'SHA256 Hashes': 'hash_sha256',
                'Base64 Encoded Data': 'base64',
            },
            '📧 CONTACT INFORMATION': {
                'Email Addresses': 'emails',
                'Phone Numbers': 'phones',
                'WHOIS Emails': 'whois_emails',
            },
            '🌐 NETWORK & INFRASTRUCTURE': {
                'Subdomains': 'subdomains',
                'IPv4 Addresses': 'ipv4',
                'IPv6 Addresses': 'ipv6',
                'Internal IPs': 'internal_ip',
                'DNS A Records': 'dns_a',
                'DNS AAAA Records': 'dns_aaaa',
                'DNS MX Records': 'dns_mx',
                'DNS NS Records': 'dns_ns',
                'DNS TXT Records': 'dns_txt',
                'Open Ports': 'open_ports',
                'Server Information': 'server_info',
            },
            '🔒 SSL/TLS & CERTIFICATES': {
                'SSL SANs': 'ssl_sans',
                'SSL Issuer': 'ssl_issuer',
                'SSL Subject': 'ssl_subject',
            },
            '🛡️ SECURITY ANALYSIS': {
                'WAF Detected': 'waf_detected',
                'SQL Injection Errors': 'sql_error',
                'XSS Vulnerabilities': 'xss_vulnerable',
                'LFI Vulnerabilities': 'lfi_vulnerable',
                'RFI Vulnerabilities': 'rfi_vulnerable',
                'XXE Vulnerabilities': 'xxe_vulnerable',
                'SSRF Vulnerabilities': 'ssrf_vulnerable',
                'Security Headers Present': 'security_headers_present',
                'Security Headers Missing': 'security_headers_missing',
            },
            '🔌 API & ENDPOINTS': {
                'API Endpoints': 'api_endpoints',
                'GraphQL Endpoints': 'api_graphql',
                'REST APIs': 'api_rest',
                'JS API Endpoints': 'js_endpoints',
            },
            '📱 SOCIAL MEDIA': {
                'Twitter Profiles': 'social_twitter',
                'Facebook Pages': 'social_facebook',
                'LinkedIn Profiles': 'social_linkedin',
                'Instagram Accounts': 'social_instagram',
                'GitHub Repositories': 'social_github',
                'YouTube Channels': 'social_youtube',
                'WhatsApp Groups': 'whatsapp',
            },
            '☁️ CLOUD SERVICES': {
                'AWS S3 Buckets': 's3_bucket',
                'Azure Storage': 'azure_storage',
                'Google Cloud Storage': 'google_cloud',
            },
            '🧬 TECHNOLOGIES DETECTED': {
                'Tech Stack': 'technologies',
            },
            '📂 FILES DISCOVERED': {
                'PDF Documents': 'file_pdf',
                'Word Documents': 'file_doc',
                'Excel Spreadsheets': 'file_xls',
                'PowerPoint Files': 'file_ppt',
                'Archives (ZIP/RAR)': 'file_zip',
                'SQL Dumps': 'file_sql',
                'Backup Files': 'file_backup',
                'Config Files': 'file_config',
                'Log Files': 'file_log',
                'Certificate Files': 'file_key',
                'Document Files': 'files_documents',
                'Database Files': 'files_databases',
                'Archive Files': 'files_archives',
                'Config Files': 'files_configs',
                'Script Files': 'files_scripts',
                'VPN Files': 'files_vpn',
                'Git Files': 'files_git',
            },
            '🔍 WEB ANALYSIS': {
                'HTML Forms': 'forms',
                'Cookies Found': 'cookies',
                'Robots.txt Disallowed': 'robots_disallowed',
                'Sitemap URLs': 'sitemap_urls',
                'HTML Comments': 'comments_html',
                'JS Comments': 'js_comments',
                'JS Functions': 'js_functions',
            },
            '📊 WHOIS INFORMATION': {
                'Registrar': 'whois_registrar',
                'Name Servers': 'whois_nameservers',
                'Created Date': 'whois_created',
                'Updated Date': 'whois_updated',
                'Expires Date': 'whois_expires',
            },
        }
        
        for section, items in categories.items():
            print(f"\n\033[1;36m{section}\033[0m")
            print("\033[1;35m" + "─" * 100 + "\033[0m")
            
            section_has_data = False
            for category, key in items.items():
                values = data.get(key, set())
                if values:
                    section_has_data = True
                    print(f"\033[1;33m{category}\033[0m ({len(values)} items):")
                    
                    if isinstance(values, set):
                        for i, item in enumerate(sorted(list(values))[:15]):
                            print(f"  \033[0;32m→\033[0m {item}")
                        if len(values) > 15:
                            print(f"  \033[0;90m... and {len(values) - 15} more items\033[0m")
                    else:
                        print(f"  \033[0;32m→\033[0m {values}")
                    print()
            
            if not section_has_data:
                print(f"  \033[0;90mNo data found in this category\033[0m\n")
        
        print("\033[1;35m" + "═" * 100 + "\033[0m")
        print(f"\033[1;32m✓ {self.lang.get('complete')}\033[0m")
        print(f"\033[1;36m  {self.lang.get('duration')}: {duration:.2f}s | {self.lang.get('requests')}: {requests}\033[0m")
        print(f"\033[1;36m  {self.lang.get('data_points')}: {sum(len(v) if isinstance(v, (set, list)) else 1 for v in data.values())}\033[0m")
        print("\033[1;35m" + "═" * 100 + "\033[0m")
    
    def export_json(self, data, filename, domain, duration, requests):
        serializable = {}
        for k, v in data.items():
            if isinstance(v, set):
                serializable[k] = sorted(list(v))
            elif isinstance(v, dict):
                serializable[k] = {sk: list(sv) if isinstance(sv, set) else sv for sk, sv in v.items()}
            else:
                serializable[k] = v
        
        report = {
            'metadata': {
                'target': domain,
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': duration,
                'http_requests': requests,
                'data_points': sum(len(v) if isinstance(v, (set, list)) else 1 for v in data.values()),
                'tool': 'MinerCad Ultimate v4.0',
                'developer': '@tc4dy',
            },
            'data': serializable
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def export_html(self, data, filename, domain, duration, requests):
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MinerCad Report - {domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%); color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: rgba(26, 31, 58, 0.95); border-radius: 15px; padding: 40px; box-shadow: 0 10px 40px rgba(0, 255, 255, 0.2); }}
        h1 {{ color: #00ffff; text-align: center; font-size: 3em; text-shadow: 0 0 20px #00ffff; margin-bottom: 10px; }}
        .meta {{ text-align: center; color: #888; margin-bottom: 30px; }}
        .meta span {{ margin: 0 15px; }}
        .section {{ margin: 30px 0; }}
        .section-title {{ color: #ff00ff; font-size: 1.8em; margin: 20px 0; padding: 10px; background: rgba(255, 0, 255, 0.1); border-left: 5px solid #ff00ff; border-radius: 5px; }}
        .category {{ background: #0f1629; margin: 15px 0; padding: 20px; border-radius: 8px; border: 1px solid #2a3f5f; }}
        .category-title {{ color: #ffff00; font-size: 1.3em; margin-bottom: 15px; }}
        .item {{ padding: 10px; margin: 8px 0; background: #1a2332; border-left: 3px solid #00ffff; font-family: 'Courier New', monospace; font-size: 0.95em; overflow-wrap: break-word; }}
        .count {{ color: #00ff00; font-weight: bold; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 2px solid #2a3f5f; color: #666; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat-box {{ background: linear-gradient(135deg, #1a2332 0%, #0f1629 100%); padding: 20px; border-radius: 10px; border: 2px solid #00ffff; text-align: center; }}
        .stat-number {{ font-size: 2.5em; color: #00ffff; font-weight: bold; }}
        .stat-label {{ color: #888; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 MinerCad OSINT Report</h1>
        <div class="meta">
            <span><strong>Target:</strong> {domain}</span>
            <span><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
        </div>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{duration:.1f}s</div>
                <div class="stat-label">Scan Duration</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{requests}</div>
                <div class="stat-label">HTTP Requests</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{sum(len(v) if isinstance(v, (set, list)) else 1 for v in data.values())}</div>
                <div class="stat-label">Data Points</div>
            </div>
        </div>
        """
        
        categories = {
            '🔐 CREDENTIALS & SECRETS': {
                'AWS Access Keys': 'aws_keys',
                'AWS Secrets': 'aws_secret',
                'Google API Keys': 'google_api',
                'Google OAuth': 'google_oauth',
                'Firebase URLs': 'firebase',
                'Stripe Live Keys': 'stripe_live',
                'Stripe Test Keys': 'stripe_test',
                'SSH Private Keys': 'ssh_key',
                'GitHub Tokens': 'github_token',
                'GitHub OAuth': 'github_oauth',
                'JWT Tokens': 'jwt',
                'Slack Tokens': 'slack_token',
                'Slack Webhooks': 'slack_webhook',
                'Discord Tokens': 'discord_token',
                'Discord Webhooks': 'discord_webhook',
                'Telegram Bot Tokens': 'telegram_bot',
                'Mailgun API Keys': 'mailgun_api',
                'Twilio API Keys': 'twilio_api',
                'PayPal Tokens': 'paypal_token',
                'Square Tokens': 'square_token',
                'SendGrid API Keys': 'sendgrid_api',
                'NPM Tokens': 'npm_token',
                'Docker Tokens': 'docker_token',
            },
            '💳 SENSITIVE DATA': {
                'Credit Cards': 'credit_card',
                'Environment Variables': 'env_vars',
                'Database Connections': 'db_connection',
                'Usernames Found': 'username',
                'Password Fields': 'password_field',
                'MD5 Hashes': 'hash_md5',
                'SHA1 Hashes': 'hash_sha1',
                'SHA256 Hashes': 'hash_sha256',
                'Base64 Encoded Data': 'base64',
            },
            '📧 CONTACT INFORMATION': {
                'Email Addresses': 'emails',
                'Phone Numbers': 'phones',
                'WHOIS Emails': 'whois_emails',
            },
            '🌐 NETWORK & INFRASTRUCTURE': {
                'Subdomains': 'subdomains',
                'IPv4 Addresses': 'ipv4',
                'IPv6 Addresses': 'ipv6',
                'Internal IPs': 'internal_ip',
                'DNS A Records': 'dns_a',
                'DNS AAAA Records': 'dns_aaaa',
                'DNS MX Records': 'dns_mx',
                'DNS NS Records': 'dns_ns',
                'DNS TXT Records': 'dns_txt',
                'Open Ports': 'open_ports',
                'Server Information': 'server_info',
            },
            '🔒 SSL/TLS & CERTIFICATES': {
                'SSL SANs': 'ssl_sans',
                'SSL Issuer': 'ssl_issuer',
                'SSL Subject': 'ssl_subject',
            },
            '🛡️ SECURITY ANALYSIS': {
                'WAF Detected': 'waf_detected',
                'SQL Injection Errors': 'sql_error',
                'XSS Vulnerabilities': 'xss_vulnerable',
                'LFI Vulnerabilities': 'lfi_vulnerable',
                'RFI Vulnerabilities': 'rfi_vulnerable',
                'XXE Vulnerabilities': 'xxe_vulnerable',
                'SSRF Vulnerabilities': 'ssrf_vulnerable',
                'Security Headers Present': 'security_headers_present',
                'Security Headers Missing': 'security_headers_missing',
            },
            '🔌 API & ENDPOINTS': {
                'API Endpoints': 'api_endpoints',
                'GraphQL Endpoints': 'api_graphql',
                'REST APIs': 'api_rest',
                'JS API Endpoints': 'js_endpoints',
            },
            '📱 SOCIAL MEDIA': {
                'Twitter Profiles': 'social_twitter',
                'Facebook Pages': 'social_facebook',
                'LinkedIn Profiles': 'social_linkedin',
                'Instagram Accounts': 'social_instagram',
                'GitHub Repositories': 'social_github',
                'YouTube Channels': 'social_youtube',
                'WhatsApp Groups': 'whatsapp',
            },
            '☁️ CLOUD SERVICES': {
                'AWS S3 Buckets': 's3_bucket',
                'Azure Storage': 'azure_storage',
                'Google Cloud Storage': 'google_cloud',
            },
            '🧬 TECHNOLOGIES DETECTED': {
                'Tech Stack': 'technologies',
            },
            '📂 FILES DISCOVERED': {
                'PDF Documents': 'file_pdf',
                'Word Documents': 'file_doc',
                'Excel Spreadsheets': 'file_xls',
                'PowerPoint Files': 'file_ppt',
                'Archives (ZIP/RAR)': 'file_zip',
                'SQL Dumps': 'file_sql',
                'Backup Files': 'file_backup',
                'Config Files': 'file_config',
                'Log Files': 'file_log',
                'Certificate Files': 'file_key',
                'Document Files': 'files_documents',
                'Database Files': 'files_databases',
                'Archive Files': 'files_archives',
                'Config Files': 'files_configs',
                'Script Files': 'files_scripts',
                'VPN Files': 'files_vpn',
                'Git Files': 'files_git',
            },
            '🔍 WEB ANALYSIS': {
                'HTML Forms': 'forms',
                'Cookies Found': 'cookies',
                'Robots.txt Disallowed': 'robots_disallowed',
                'Sitemap URLs': 'sitemap_urls',
                'HTML Comments': 'comments_html',
                'JS Comments': 'js_comments',
                'JS Functions': 'js_functions',
            },
            '📊 WHOIS INFORMATION': {
                'Registrar': 'whois_registrar',
                'Name Servers': 'whois_nameservers',
                'Created Date': 'whois_created',
                'Updated Date': 'whois_updated',
                'Expires Date': 'whois_expires',
            },
        }
        
        for section, items in categories.items():
            html += f'<div class="section"><h2 class="section-title">{section}</h2>'
            
            for category, key in items.items():
                values = data.get(key, set())
                if values:
                    count = len(values) if isinstance(values, (set, list)) else 1
                    html += f'<div class="category"><div class="category-title">{category} <span class="count">({count})</span></div>'
                    
                    if isinstance(values, (set, list)):
                        for item in sorted(list(values))[:100]:
                            html += f'<div class="item">{str(item)}</div>'
                        if len(values) > 100:
                            html += f'<div class="item" style="color: #888; font-style: italic;">... and {len(values) - 100} more items</div>'
                    else:
                        html += f'<div class="item">{str(values)}</div>'
                    
                    html += '</div>'
            
            html += '</div>'
        
        html += f"""
        <div class="footer">
            <p><strong>MinerCad Ultimate v4.0</strong> - AI-Powered Deep Intelligence Engine</p>
            <p>Developed by @tc4dy | Educational and Research Tool</p>
            <p>Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def export_xml(self, data, filename, domain, duration, requests):
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<osint_report>
    <metadata>
        <target>{domain}</target>
        <timestamp>{datetime.now().isoformat()}</timestamp>
        <duration_seconds>{duration}</duration_seconds>
        <http_requests>{requests}</http_requests>
        <data_points>{sum(len(v) if isinstance(v, (set, list)) else 1 for v in data.values())}</data_points>
        <tool>MinerCad Ultimate v4.0</tool>
        <developer>@tc4dy</developer>
    </metadata>
    <data>
"""
        
        for key, values in data.items():
            xml += f'    <{key}>\n'
            
            if isinstance(values, (set, list)):
                for item in sorted(list(values)):
                    item_escaped = str(item).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')
                    xml += f'        <item>{item_escaped}</item>\n'
            elif isinstance(values, dict):
                for k, v in values.items():
                    k_escaped = str(k).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    v_escaped = str(v).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    xml += f'        <{k_escaped}>{v_escaped}</{k_escaped}>\n'
            else:
                value_escaped = str(values).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                xml += f'        <value>{value_escaped}</value>\n'
            
            xml += f'    </{key}>\n'
        
        xml += """    </data>
</osint_report>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(xml)
    
    def print_statistics(self, data):
        print(f"\n\033[1;35m{'═' * 100}\033[0m")
        print(f"\033[1;35m  {self.lang.get('stats')}\033[0m")
        print(f"\033[1;35m{'═' * 100}\033[0m\n")
        
        total_items = sum(len(v) if isinstance(v, (set, list)) else 1 for v in data.values())
        
        stats = [
            ('Total Data Categories', len([k for k, v in data.items() if v])),
            ('Total Data Points', total_items),
            ('Secrets & Credentials', sum(len(data.get(k, set())) for k in ['aws_keys', 'aws_secret', 'google_api', 'stripe_live', 'github_token', 'jwt', 'slack_token', 'discord_token'])),
            ('Email Addresses', len(data.get('emails', set()))),
            ('Phone Numbers', len(data.get('phones', set()))),
            ('Subdomains', len(data.get('subdomains', set()))),
            ('IP Addresses', len(data.get('ipv4', set())) + len(data.get('ipv6', set()))),
            ('Open Ports', len(data.get('open_ports', set()))),
            ('Technologies', len(data.get('technologies', set()))),
            ('API Endpoints', len(data.get('api_endpoints', set())) + len(data.get('js_endpoints', set()))),
            ('Vulnerabilities', sum(len(data.get(k, set())) for k in ['sql_error', 'xss_vulnerable', 'lfi_vulnerable', 'rfi_vulnerable'])),
            ('Files Discovered', sum(len(data.get(k, set())) for k in data.keys() if k.startswith('file_') or k.startswith('files_'))),
            ('Social Media Links', sum(len(data.get(k, set())) for k in data.keys() if k.startswith('social_'))),
            ('Cloud Storage', sum(len(data.get(k, set())) for k in ['s3_bucket', 'azure_storage', 'google_cloud'])),
        ]
        
        for label, count in stats:
            bar_length = int((count / max(total_items, 1)) * 50)
            bar = '█' * bar_length + '░' * (50 - bar_length)
            print(f"\033[1;33m{label:.<40}\033[0m \033[1;36m{count:>6}\033[0m \033[0;32m{bar}\033[0m")
        
        print(f"\n\033[1;35m{'═' * 100}\033[0m")

class MinerCad:
    def __init__(self):
        self.lang_manager = LanguageManager()
        self.banner()
        self.select_language()
        self.data = defaultdict(set)
        self.domain = None
        self.start_time = None
        self.duration = 0
        self.request_count = 0
    
    def banner(self):
        banner = f"""
\033[1;35m{'═' * 100}\033[0m
\033[1;36m
  ███╗   ███╗██╗███╗   ██╗███████╗██████╗  ██████╗ █████╗ ██████╗ 
  ████╗ ████║██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗
  ██╔████╔██║██║██╔██╗ ██║█████╗  ██████╔╝██║     ███████║██║  ██║
  ██║╚██╔╝██║██║██║╚██╗██║██╔══╝  ██╔══██╗██║     ██╔══██║██║  ██║
  ██║ ╚═╝ ██║██║██║ ╚████║███████╗██║  ██║╚██████╗██║  ██║██████╔╝
  ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝ 
\033[0m
\033[1;33m            ULTIMATE TACTICAL RECONNAISSANCE FRAMEWORK\033[0m
\033[1;32m            Version 4.0.0 - MinerCad Ultimate\033[0m
\033[1;31m            Developed by @tc4dy - Educational and Research Tool\033[0m
\033[1;35m{'═' * 100}\033[0m
"""
        print(banner)
    
    def select_language(self):
        choice = input(self.lang_manager.get('lang_select'))
        self.lang_manager.set_language(1 if choice == '1' else 2)
    
    def get_target(self):
        self.domain = input(f"\n\033[1;33m{self.lang_manager.get('target')}\033[0m").strip()
        if self.domain.startswith(('http://', 'https://')):
            self.domain = urlparse(self.domain).netloc
        return self.domain
    
    def run_scan(self):
        self.start_time = time.time()
        
        print(f"\n\033[1;32m[◆]\033[0m {self.lang_manager.get('ai_config')}")
        config = AIConfigManager.calculate_optimal_params(self.domain)
        time.sleep(1)
        
        print(f"\n\033[1;35m{'═' * 100}\033[0m")
        print(f"\033[1;36mSTARTING COMPREHENSIVE OSINT SCAN ON: {self.domain}\033[0m")
        print(f"\033[1;35m{'═' * 100}\033[0m")
        
        # DNS Enumeration
        if config['dns_enumeration']:
            print(f"\n\033[1;32m[◆]\033[0m {self.lang_manager.get('dns_enum')}")
            dns_enum = DNSEnumerator()
            dns_results = dns_enum.enumerate(self.domain)
            for key, values in dns_results.items():
                self.data[key].update(values)
        
        # WHOIS Lookup
        if config['whois_lookup']:
            print(f"\033[1;32m[◆]\033[0m {self.lang_manager.get('whois_lookup')}")
            whois_results = WhoisAnalyzer.analyze(self.domain)
            for key, value in whois_results.items():
                if isinstance(value, set):
                    self.data[key].update(value)
                elif value:
                    self.data[key] = value
        
        # SSL Analysis
        if config['ssl_analysis_enabled']:
            print(f"\033[1;32m[◆]\033[0m {self.lang_manager.get('ssl_analysis')}")
            ssl_results = SSLAnalyzer.analyze(self.domain)
            for key, value in ssl_results.items():
                if isinstance(value, set):
                    self.data[key].update(value)
                elif value:
                    self.data[key] = value
        
        # Port Scanning
        if config['port_scan_enabled']:
            print(f"\033[1;32m[◆]\033[0m {self.lang_manager.get('port_scan')}")
            port_results = PortScanner.scan(self.domain)
            for key, values in port_results.items():
                self.data[key].update(values)
        
        # Subdomain Bruteforce
        if config['bruteforce_subdomains']:
            print(f"\033[1;32m[◆]\033[0m {self.lang_manager.get('subdomain_brute')}")
            bruteforcer = SubdomainBruteforcer(self.domain, threads=config['threads'])
            subdomains = bruteforcer.bruteforce()
            self.data['subdomains'].update(subdomains)
        
        # Web Crawling
        print(f"\n\033[1;32m[◆]\033[0m {self.lang_manager.get('tech_fingerprint')}")
        crawler = WebCrawler(config)
        start_url = f"https://{self.domain}"
        crawl_results, request_count = crawler.crawl(start_url, self.domain, self.lang_manager)
        self.request_count = request_count
        
        for key, values in crawl_results.items():
            self.data[key].update(values)
        
        # JavaScript Analysis
        if config['js_analysis_enabled']:
            print(f"\033[1;32m[◆]\033[0m {self.lang_manager.get('js_analysis')}")
            for url in list(self.data.get('urls', set()))[:20]:
                if url.endswith('.js'):
                    try:
                        response = requests.get(url, timeout=10, verify=False)
                        if response.status_code == 200:
                            js_results = JavaScriptAnalyzer.analyze(response.text)
                            for key, values in js_results.items():
                                self.data[key].update(values)
                    except:
                        pass
        
        self.duration = time.time() - self.start_time
    
    def show_menu(self):
        report_gen = ReportGenerator(self.lang_manager)
        report_gen.print_console(self.data, self.domain, self.duration, self.request_count)
        
        while True:
            choice = input(self.lang_manager.get('menu'))
            
            if choice == '1':
                self.data = defaultdict(set)
                self.get_target()
                self.run_scan()
                report_gen.print_console(self.data, self.domain, self.duration, self.request_count)
            
            elif choice == '2':
                filename = f"minercad_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                report_gen.export_json(self.data, filename, self.domain, self.duration, self.request_count)
                print(f"\n\033[1;32m✓ {self.lang_manager.get('exported')}\033[0m {filename}")
            
            elif choice == '3':
                filename = f"minercad_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                report_gen.export_html(self.data, filename, self.domain, self.duration, self.request_count)
                print(f"\n\033[1;32m✓ {self.lang_manager.get('exported')}\033[0m {filename}")
            
            elif choice == '4':
                filename = f"minercad_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
                report_gen.export_xml(self.data, filename, self.domain, self.duration, self.request_count)
                print(f"\n\033[1;32m✓ {self.lang_manager.get('exported')}\033[0m {filename}")
            
            elif choice == '5':
                report_gen.print_statistics(self.data)
            
            elif choice == '6':
                print("\n\033[1;35m" + "═" * 100 + "\033[0m")
                print("\033[1;36mThank you for using MinerCad Ultimate v4.0!\033[0m")
                print("\033[1;32mDeveloped by @tc4dy | Educational and Research Tool\033[0m")
                print("\033[1;35m" + "═" * 100 + "\033[0m\n")
                sys.exit(0)

def main():
    try:
        scanner = MinerCad()
        scanner.get_target()
        scanner.run_scan()
        scanner.show_menu()
    except KeyboardInterrupt:
        print("\n\n\033[1;31m[!] Scan interrupted by user\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\n\033[1;31m[!] Critical error: {str(e)}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()

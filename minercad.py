import re
import sys
import json
import time
import socket
import ssl
import dns.resolver
import threading
import requests
import urllib3
from datetime import datetime
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import whois
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import random
import html as html_module

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def count_values(values):
    if isinstance(values, (set, list, dict)):
        return len(values)
    return 1


def total_data_points(data):
    return sum(count_values(v) for v in data.values())


def first_or_none(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


class Config:
    DEPTH = 4
    THREADS = 15
    TIMEOUT = 12
    RATE_LIMIT = 0.1
    MAX_LINKS_PER_LEVEL = 100
    JS_ANALYSIS_LIMIT = 20

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432,
        5900, 6379, 8080, 8443, 8888, 9090, 27017
    ]

    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ]


class PatternExtractor:
    def __init__(self):
        self.patterns = {
            'emails': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'ipv4': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'ipv6': re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'),
            'aws_keys': re.compile(r'AKIA[0-9A-Z]{16}'),
            'aws_secret': re.compile(r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]'),
            'google_api': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            'google_oauth': re.compile(r'ya29\.[0-9A-Za-z\-_]+'),
            'firebase': re.compile(r'[a-z0-9-]+\.firebaseio\.com'),
            'stripe_live': re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
            'stripe_test': re.compile(r'sk_test_[0-9a-zA-Z]{24}'),
            'ssh_key': re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
            'github_token': re.compile(r'ghp_[a-zA-Z0-9]{36}'),
            'github_oauth': re.compile(r'gho_[a-zA-Z0-9]{36}'),
            'jwt': re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
            'slack_token': re.compile(r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}'),
            'slack_webhook': re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'),
            'discord_token': re.compile(r'[MN][a-zA-Z\d]{23,25}\.[a-zA-Z\d]{6}\.[a-zA-Z\d_-]{27}'),
            'discord_webhook': re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+'),
            'telegram_bot': re.compile(r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}'),
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
            'sql_error': re.compile(r'(?i)(?:SQL syntax|mysql_fetch|Warning: mysql|PostgreSQL.*ERROR|ORA-[0-9]{5}|SQLSTATE|DB2 SQL error|Microsoft SQL Native Client error)'),
            'xss_vulnerable': re.compile(r'(?i)<script[^>]*>.*?(?:alert|prompt|confirm)\(.*?\).*?</script>'),
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
            'vpn': ['.ovpn', '.conf', '.key', '.crt'],
            'certificates': ['.pem', '.key', '.crt', '.cer', '.p12', '.pfx', '.jks'],
            'backups': ['.bak', '.old', '.backup', '.~'],
        }

        self.technologies = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin', '/wp-json/'],
            'Joomla': ['joomla', 'components/com_', '/administrator/', 'option=com_'],
            'Drupal': ['drupal', '/sites/default/', '/sites/all/', 'Drupal.settings'],
            'Magento': ['magento', 'Mage.Cookies', '/skin/frontend/'],
            'Shopify': ['shopify', 'cdn.shopify.com', 'myshopify.com'],
            'React': ['react.createElement', 'reactdom', '_react'],
            'Vue.js': ['vue.component', '__vue__', 'vue.config'],
            'Angular': ['ng-app', 'ng-controller', 'ng-model'],
            'jQuery': ['jquery', '$.ajax'],
            'Bootstrap': ['bootstrap.min', 'bootstrap.css', 'bootstrap.bundle'],
            'Laravel': ['laravel_session', 'xsrf-token'],
            'Django': ['csrfmiddlewaretoken', 'django.contrib'],
            'Flask': ['werkzeug', 'jinja2'],
            'Express': ['x-powered-by: express'],
            'Next.js': ['_next/', '__next'],
            'Nuxt.js': ['__nuxt', '_nuxt/'],
            'Nginx': ['server: nginx'],
            'Apache': ['server: apache'],
            'IIS': ['server: microsoft-iis'],
            'Tomcat': ['server: apache-coyote'],
            'Cloudflare': ['cf-ray', '__cfduid'],
            'AWS': ['amazonaws.com', 'cloudfront.net', 'elasticbeanstalk'],
            'Google Cloud': ['googleapis.com', 'appspot.com'],
            'Azure': ['windows.net', 'azurewebsites'],
            'Heroku': ['herokuapp.com'],
            'Vercel': ['vercel.app'],
            'Netlify': ['netlify.app'],
            'Firebase': ['firebaseio', 'firebaseapp'],
            'Google Analytics': ['google-analytics', 'gtag', 'analytics.js'],
            'Google Tag Manager': ['googletagmanager', 'gtm.js'],
            'Stripe': ['js.stripe.com'],
            'PayPal': ['paypalobjects.com'],
            'PHP': ['.php', 'x-powered-by: php'],
            'ASP.NET': ['__viewstate', 'aspx'],
            'Node.js': ['x-powered-by: express'],
            'Ruby': ['x-powered-by: phusion passenger'],
            'Java': ['.jsp', 'jsessionid'],
        }

    def extract_all(self, content, base_domain):
        results = defaultdict(set)
        content_lower = content.lower()

        for name, pattern in self.patterns.items():
            try:
                matches = pattern.findall(content)
                if name == 'subdomains':
                    matches = [m for m in matches if base_domain in m and m != base_domain and len(m.split('.')) >= 2]
                results[name].update(matches)
            except re.error:
                pass

        for category, extensions in self.file_extensions.items():
            for ext in extensions:
                if ext in content_lower:
                    pattern = re.compile(rf'https?://[^\s<>"\']+{re.escape(ext)}', re.IGNORECASE)
                    results[f'files_{category}'].update(pattern.findall(content))

        for tech, signatures in self.technologies.items():
            if any(sig in content_lower for sig in signatures):
                results['technologies'].add(tech)

        return results


class DNSEnumerator:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3

    def enumerate(self, domain):
        results = defaultdict(set)
        record_types = {
            'A': 'dns_a', 'AAAA': 'dns_aaaa', 'MX': 'dns_mx', 'NS': 'dns_ns',
            'TXT': 'dns_txt', 'CNAME': 'dns_cname', 'SOA': 'dns_soa',
        }

        for rtype, key in record_types.items():
            try:
                answers = self.resolver.resolve(domain, rtype)
                for rdata in answers:
                    results[key].add(str(rdata))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.Timeout, dns.exception.DNSException):
                continue

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
        except (socket.error, ssl.SSLError, OSError):
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
            results['whois_registrar'] = first_or_none(w.registrar)
            results['whois_created'] = str(first_or_none(w.creation_date)) if w.creation_date else None
            results['whois_updated'] = str(first_or_none(w.updated_date)) if w.updated_date else None
            results['whois_expires'] = str(first_or_none(w.expiration_date)) if w.expiration_date else None

            if w.name_servers:
                ns = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
                results['whois_nameservers'].update(str(x) for x in ns if x)

            if w.emails:
                emails = w.emails if isinstance(w.emails, list) else [w.emails]
                results['whois_emails'].update(str(x) for x in emails if x)
        except Exception:
            pass

        return results


class SubdomainBruteforcer:
    def __init__(self, domain, threads=10):
        self.domain = domain
        self.threads = threads
        self.found = set()
        self.wordlist = self._generate_wordlist()

    def _generate_wordlist(self):
        common = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'admin', 'api',
            'dev', 'staging', 'test', 'beta', 'demo', 'blog', 'shop', 'store',
            'cdn', 'static', 'assets', 'images', 'img', 'media', 'files',
            'download', 'downloads', 'docs', 'portal', 'dashboard', 'panel',
            'manage', 'app', 'mobile', 'secure', 'vpn', 'remote', 'cloud',
            'server', 'host', 'web', 'email', 'support', 'help', 'wiki',
            'forum', 'community', 'news', 'marketing', 'sales', 'crm', 'erp',
            'hr', 'finance', 'billing', 'payment', 'checkout', 'ecommerce',
            'search', 'jenkins', 'gitlab', 'jira', 'confluence', 'nexus',
            'monitoring', 'metrics', 'logs', 'status',
        ]

        prefixes = ['dev', 'test', 'staging', 'prod', 'qa', 'demo', 'old', 'new', 'backup']
        suffixes = ['01', '02', '1', '2', 'v1', 'v2', 'new', 'old']

        wordlist = set(common)
        for word in common[:30]:
            for prefix in prefixes:
                wordlist.add(f"{prefix}{word}")
                wordlist.add(f"{prefix}-{word}")
            for suffix in suffixes:
                wordlist.add(f"{word}{suffix}")
                wordlist.add(f"{word}-{suffix}")

        return list(wordlist)

    def _check_subdomain(self, subdomain):
        try:
            full_domain = f"{subdomain}.{self.domain}"
            socket.gethostbyname(full_domain)
            return full_domain
        except socket.gaierror:
            return None

    def bruteforce(self):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_subdomain, sub): sub for sub in self.wordlist}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.found.add(result)
                except Exception:
                    continue
        return self.found


class PortScanner:
    @staticmethod
    def scan(domain, ports=None):
        if ports is None:
            ports = Config.COMMON_PORTS

        results = {'open_ports': set(), 'closed_ports': set()}

        def probe(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                rc = sock.connect_ex((domain, port))
                sock.close()
                return port, rc == 0
            except (socket.error, OSError):
                return port, False

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(probe, p) for p in ports]
            for future in as_completed(futures):
                try:
                    port, is_open = future.result()
                    key = 'open_ports' if is_open else 'closed_ports'
                    results[key].add(port)
                except Exception:
                    continue

        return results


class WebCrawler:
    def __init__(self):
        self.visited = set()
        self.lock = threading.Lock()
        self.counter_lock = threading.Lock()
        self.results = defaultdict(set)
        self.request_count = 0
        self.session = self._create_session()

    def _create_session(self):
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def _headers(self):
        return {
            'User-Agent': random.choice(Config.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }

    def _normalize_url(self, url, base_url):
        if not url or url.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
            return None
        if url.startswith('http'):
            return url
        return urljoin(base_url, url)

    def _extract_links(self, content, base_url):
        links = set()
        try:
            soup = BeautifulSoup(content, 'html.parser')
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
                for attr in ('href', 'src', 'data-src'):
                    url = tag.get(attr)
                    if url:
                        normalized = self._normalize_url(url, base_url)
                        if normalized:
                            links.add(normalized)
        except Exception:
            pass
        return links

    def _extract_forms(self, content):
        forms = []
        try:
            soup = BeautifulSoup(content, 'html.parser')
            for form in soup.find_all('form'):
                forms.append({
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': len(form.find_all(['input', 'textarea', 'select'])),
                })
        except Exception:
            pass
        return forms

    def _extract_cookies(self, response):
        cookies = {}
        for cookie in response.cookies:
            cookies[cookie.name] = {
                'secure': cookie.secure,
                'httponly': getattr(cookie, 'httponly', False),
            }
        return cookies

    def _analyze_headers(self, headers):
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'XFO',
            'X-Content-Type-Options': 'XCTO',
            'X-XSS-Protection': 'XXSSP',
            'Referrer-Policy': 'RP',
            'Permissions-Policy': 'PP',
        }

        present, missing = [], []
        for header, name in security_headers.items():
            if header in headers:
                present.append(f"{name}: {headers[header]}")
            else:
                missing.append(name)

        return present, missing, headers.get('Server', 'Unknown')

    def _detect_waf(self, headers, content):
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'Akamai': ['akamai', 'akamaighost'],
            'AWS WAF': ['awselb', 'x-amz-'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'Incapsula': ['incap_ses', 'visid_incap'],
            'ModSecurity': ['mod_security', 'noyb'],
            'Barracuda': ['barracuda'],
            'F5 BIG-IP': ['bigip'],
            'Fortinet': ['fortigate', 'fortiweb'],
        }

        detected = set()
        headers_str = ' '.join(str(v) for v in headers.values()).lower()
        content_lower = content.lower()

        for waf, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in headers_str or sig in content_lower:
                    detected.add(waf)
                    break

        return detected

    def _fetch_robots(self, domain):
        results = {'disallowed': set(), 'sitemaps': set()}
        try:
            response = self.session.get(
                f"https://{domain}/robots.txt",
                headers=self._headers(),
                timeout=Config.TIMEOUT,
                verify=False,
            )
            with self.counter_lock:
                self.request_count += 1

            if response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    lower = line.lower()
                    if lower.startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            results['disallowed'].add(path)
                    elif lower.startswith('sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        if sitemap:
                            results['sitemaps'].add(sitemap)
        except requests.RequestException:
            pass
        return results

    def _fetch_sitemap(self, url):
        urls = set()
        try:
            response = self.session.get(
                url, headers=self._headers(),
                timeout=Config.TIMEOUT, verify=False,
            )
            with self.counter_lock:
                self.request_count += 1
            if response.status_code == 200:
                urls.update(re.findall(r'<loc>\s*(.*?)\s*</loc>', response.text, re.DOTALL))
        except requests.RequestException:
            pass
        return urls

    def _fetch(self, url):
        try:
            response = self.session.get(
                url, headers=self._headers(),
                timeout=Config.TIMEOUT, verify=False,
                allow_redirects=True,
            )
            with self.counter_lock:
                self.request_count += 1
            time.sleep(Config.RATE_LIMIT)
            return response
        except requests.RequestException:
            return None

    def _process_url(self, url, base_domain, extractor):
        response = self._fetch(url)
        if not response:
            return set()

        content = response.text
        headers = dict(response.headers)

        extracted = extractor.extract_all(content, base_domain)
        present, missing, server = self._analyze_headers(headers)
        waf = self._detect_waf(headers, content)
        forms = self._extract_forms(content)
        cookies = self._extract_cookies(response)

        with self.lock:
            for key, values in extracted.items():
                self.results[key].update(values)

            self.results['security_headers_present'].update(present)
            self.results['security_headers_missing'].update(missing)
            self.results['server_info'].add(server)
            self.results['waf_detected'].update(waf)

            for form in forms:
                self.results['forms'].add(
                    f"{form['method']} {form['action']} - Inputs: {form['inputs']}"
                )

            for name, data in cookies.items():
                self.results['cookies'].add(
                    f"{name} (Secure: {data['secure']}, HttpOnly: {data['httponly']})"
                )

        links = self._extract_links(content, url)
        return {link for link in links if base_domain in link}

    def _detect_start_url(self, base_domain):
        for scheme in ('https', 'http'):
            candidate = f"{scheme}://{base_domain}"
            try:
                response = self.session.get(
                    candidate, headers=self._headers(),
                    timeout=Config.TIMEOUT, verify=False,
                    allow_redirects=True,
                )
                with self.counter_lock:
                    self.request_count += 1
                if response.status_code < 500:
                    return candidate
            except requests.RequestException:
                continue
        return None

    def crawl(self, base_domain):
        extractor = PatternExtractor()
        print("[+] Crawling target...")

        robots = self._fetch_robots(base_domain)
        self.results['robots_disallowed'].update(robots['disallowed'])
        for sitemap in list(robots['sitemaps'])[:5]:
            self.results['sitemap_urls'].update(self._fetch_sitemap(sitemap))

        start_url = self._detect_start_url(base_domain)
        if not start_url:
            print("[!] Target unreachable via HTTP/HTTPS")
            return self.results, self.request_count

        self.visited.add(start_url)
        current_level = [start_url]

        for _ in range(Config.DEPTH):
            if not current_level:
                break

            with ThreadPoolExecutor(max_workers=Config.THREADS) as executor:
                futures = {
                    executor.submit(self._process_url, url, base_domain, extractor): url
                    for url in current_level
                }

                next_level = []
                for future in as_completed(futures):
                    try:
                        links = future.result()
                    except Exception:
                        links = set()
                    with self.lock:
                        for link in links:
                            if link not in self.visited:
                                self.visited.add(link)
                                next_level.append(link)

            current_level = next_level[:Config.MAX_LINKS_PER_LEVEL]

        return self.results, self.request_count


class JavaScriptAnalyzer:
    @staticmethod
    def analyze(js_content):
        results = {
            'js_endpoints': set(),
            'js_secrets': set(),
            'js_functions': set(),
        }

        endpoint_patterns = [
            r'["\']/(?:api|v1|v2|rest|graphql)/[^"\']+["\']',
            r'https?://[^"\']+/api[^"\']*',
        ]

        secret_patterns = [
            r'(?i)(?:api[_-]?key|secret|token|password)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
        ]

        for pattern in endpoint_patterns:
            for match in re.findall(pattern, js_content):
                results['js_endpoints'].add(match if isinstance(match, str) else match[0])

        for pattern in secret_patterns:
            for match in re.findall(pattern, js_content):
                results['js_secrets'].add(match)

        functions = re.findall(r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(', js_content)
        results['js_functions'].update(functions[:30])

        return results


REPORT_CATEGORIES = {
    'Credentials & Secrets': {
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
        'SendGrid API Keys': 'sendgrid_api',
        'NPM Tokens': 'npm_token',
        'Docker Tokens': 'docker_token',
    },
    'Sensitive Data': {
        'Environment Variables': 'env_vars',
        'Database Connections': 'db_connection',
        'MD5 Hashes': 'hash_md5',
        'SHA1 Hashes': 'hash_sha1',
        'SHA256 Hashes': 'hash_sha256',
    },
    'Contact Information': {
        'Email Addresses': 'emails',
        'WHOIS Emails': 'whois_emails',
    },
    'Network & Infrastructure': {
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
    'SSL/TLS & Certificates': {
        'SSL SANs': 'ssl_sans',
        'SSL Issuer': 'ssl_issuer',
        'SSL Subject': 'ssl_subject',
    },
    'Security Analysis': {
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
    'API & Endpoints': {
        'API Endpoints': 'api_endpoints',
        'GraphQL Endpoints': 'api_graphql',
        'REST APIs': 'api_rest',
        'JS API Endpoints': 'js_endpoints',
    },
    'Social Media': {
        'Twitter Profiles': 'social_twitter',
        'Facebook Pages': 'social_facebook',
        'LinkedIn Profiles': 'social_linkedin',
        'Instagram Accounts': 'social_instagram',
        'GitHub Repositories': 'social_github',
        'YouTube Channels': 'social_youtube',
    },
    'Cloud Services': {
        'AWS S3 Buckets': 's3_bucket',
        'Azure Storage': 'azure_storage',
        'Google Cloud Storage': 'google_cloud',
    },
    'Technologies Detected': {
        'Tech Stack': 'technologies',
    },
    'Files Discovered': {
        'PDF Documents': 'file_pdf',
        'Word Documents': 'file_doc',
        'Excel Spreadsheets': 'file_xls',
        'PowerPoint Files': 'file_ppt',
        'Archives': 'file_zip',
        'SQL Dumps': 'file_sql',
        'Backup Files': 'file_backup',
        'Config Files': 'file_config',
        'Log Files': 'file_log',
        'Certificate Files': 'file_key',
        'Document Files': 'files_documents',
        'Database Files': 'files_databases',
        'Archive Files': 'files_archives',
        'Config Files (extended)': 'files_configs',
        'Script Files': 'files_scripts',
        'VPN Files': 'files_vpn',
    },
    'Web Analysis': {
        'HTML Forms': 'forms',
        'Cookies Found': 'cookies',
        'Robots.txt Disallowed': 'robots_disallowed',
        'Sitemap URLs': 'sitemap_urls',
        'HTML Comments': 'comments_html',
        'JS Functions': 'js_functions',
    },
    'WHOIS Information': {
        'Registrar': 'whois_registrar',
        'Name Servers': 'whois_nameservers',
        'Created Date': 'whois_created',
        'Updated Date': 'whois_updated',
        'Expires Date': 'whois_expires',
    },
}


class ReportGenerator:
    def print_console(self, data, domain, duration, requests):
        total = total_data_points(data)

        print("\n" + "=" * 90)
        print(f"  OSINT REPORT")
        print(f"  Target: {domain}")
        print(f"  Duration: {duration:.2f}s | Requests: {requests} | Data Points: {total}")
        print("=" * 90)

        for section, items in REPORT_CATEGORIES.items():
            print(f"\n--- {section} ---")

            section_has_data = False
            for label, key in items.items():
                values = data.get(key, set())
                if not values:
                    continue

                section_has_data = True
                print(f"\n  {label} ({count_values(values)}):")

                if isinstance(values, (set, list)):
                    for item in sorted(list(values))[:15]:
                        print(f"    {item}")
                    if len(values) > 15:
                        print(f"    ... and {len(values) - 15} more")
                elif isinstance(values, dict):
                    for k, v in list(values.items())[:15]:
                        print(f"    {k}: {v}")
                    if len(values) > 15:
                        print(f"    ... and {len(values) - 15} more")
                else:
                    print(f"    {values}")

            if not section_has_data:
                print("  No data")

        print("\n" + "=" * 90)
        print(f"  Scan complete. Data points: {total}")
        print("=" * 90)

    def export_json(self, data, filename, domain, duration, requests):
        serializable = {}
        for k, v in data.items():
            if isinstance(v, set):
                serializable[k] = sorted(list(v))
            elif isinstance(v, dict):
                serializable[k] = {sk: (list(sv) if isinstance(sv, set) else sv) for sk, sv in v.items()}
            else:
                serializable[k] = v

        report = {
            'metadata': {
                'target': domain,
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': round(duration, 2),
                'http_requests': requests,
                'data_points': total_data_points(data),
            },
            'data': serializable,
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    def export_html(self, data, filename, domain, duration, requests):
        esc = html_module.escape

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report - {esc(domain)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1117; color: #d1d5db; margin: 0; padding: 24px; line-height: 1.5; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #e5e7eb; font-size: 1.5em; margin: 0 0 4px; }}
.meta {{ color: #6b7280; font-size: 0.9em; margin-bottom: 24px; }}
.section {{ margin-top: 32px; }}
.section h2 {{ color: #60a5fa; font-size: 1.1em; border-bottom: 1px solid #1f2937; padding-bottom: 8px; margin-bottom: 12px; }}
.category {{ background: #161b22; border: 1px solid #1f2937; border-radius: 6px; padding: 16px; margin-bottom: 12px; }}
.category-title {{ color: #f3f4f6; font-weight: 600; margin-bottom: 8px; font-size: 0.95em; }}
.count {{ color: #6b7280; font-weight: 400; }}
.item {{ font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.85em; padding: 4px 0; color: #9ca3af; word-break: break-all; border-bottom: 1px solid #1f2937; }}
.item:last-child {{ border-bottom: none; }}
.empty {{ color: #4b5563; font-style: italic; }}
.footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #1f2937; color: #4b5563; font-size: 0.8em; }}
</style>
</head>
<body>
<div class="container">
<h1>Recon Report</h1>
<div class="meta">Target: {esc(domain)} | Duration: {duration:.2f}s | Requests: {requests} | Data Points: {total_data_points(data)} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
"""

        for section, items in REPORT_CATEGORIES.items():
            html += f'<div class="section"><h2>{esc(section)}</h2>'

            section_has_data = False
            for label, key in items.items():
                values = data.get(key, set())
                if not values:
                    continue

                section_has_data = True
                html += f'<div class="category"><div class="category-title">{esc(label)} <span class="count">({count_values(values)})</span></div>'

                if isinstance(values, (set, list)):
                    for item in sorted(list(values))[:100]:
                        html += f'<div class="item">{esc(str(item))}</div>'
                    if len(values) > 100:
                        html += f'<div class="item empty">... and {len(values) - 100} more</div>'
                elif isinstance(values, dict):
                    for k, v in list(values.items())[:100]:
                        html += f'<div class="item">{esc(str(k))}: {esc(str(v))}</div>'
                else:
                    html += f'<div class="item">{esc(str(values))}</div>'

                html += '</div>'

            if not section_has_data:
                html += '<div class="category empty">No data</div>'

            html += '</div>'

        html += f"""
<div class="footer">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</div>
</body>
</html>"""

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

    def export_xml(self, data, filename, domain, duration, requests):
        def xesc(v):
            return (str(v).replace('&', '&amp;').replace('<', '&lt;')
                    .replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;'))

        def safe_tag(name):
            tag = re.sub(r'[^A-Za-z0-9_]', '_', str(name))
            if not tag or tag[0].isdigit():
                tag = 'n_' + tag
            return tag

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<report>
  <metadata>
    <target>{xesc(domain)}</target>
    <timestamp>{datetime.now().isoformat()}</timestamp>
    <duration_seconds>{round(duration, 2)}</duration_seconds>
    <http_requests>{requests}</http_requests>
    <data_points>{total_data_points(data)}</data_points>
  </metadata>
  <findings>
"""

        for key, values in data.items():
            tag = safe_tag(key)
            xml += f'    <{tag}>\n'

            if isinstance(values, (set, list)):
                for item in sorted(list(values)):
                    xml += f'      <item>{xesc(item)}</item>\n'
            elif isinstance(values, dict):
                for k, v in values.items():
                    xml += f'      <{safe_tag(k)}>{xesc(v)}</{safe_tag(k)}>\n'
            else:
                xml += f'      <value>{xesc(values)}</value>\n'

            xml += f'    </{tag}>\n'

        xml += """  </findings>
</report>"""

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(xml)

    def print_statistics(self, data):
        total = max(total_data_points(data), 1)

        print("\n" + "=" * 70)
        print("  Scan Statistics")
        print("=" * 70)

        stats = [
            ('Categories with data', len([k for k, v in data.items() if v])),
            ('Total data points', total_data_points(data)),
            ('Credentials & secrets', sum(count_values(data.get(k, set())) for k in [
                'aws_keys', 'aws_secret', 'google_api', 'stripe_live', 'github_token',
                'jwt', 'slack_token', 'discord_token'])),
            ('Email addresses', count_values(data.get('emails', set()))),
            ('Subdomains', count_values(data.get('subdomains', set()))),
            ('IP addresses', count_values(data.get('ipv4', set())) + count_values(data.get('ipv6', set()))),
            ('Open ports', count_values(data.get('open_ports', set()))),
            ('Technologies', count_values(data.get('technologies', set()))),
            ('API endpoints', count_values(data.get('api_endpoints', set())) + count_values(data.get('js_endpoints', set()))),
            ('Vulnerabilities', sum(count_values(data.get(k, set())) for k in [
                'sql_error', 'xss_vulnerable', 'lfi_vulnerable', 'rfi_vulnerable'])),
            ('Files discovered', sum(count_values(data.get(k, set())) for k in data.keys() if k.startswith('file_') or k.startswith('files_'))),
            ('Social media', sum(count_values(data.get(k, set())) for k in data.keys() if k.startswith('social_'))),
            ('Cloud storage', sum(count_values(data.get(k, set())) for k in ['s3_bucket', 'azure_storage', 'google_cloud'])),
        ]

        for label, count in stats:
            bar_len = min(int((count / total) * 40), 40)
            bar = '#' * bar_len + '.' * (40 - bar_len)
            print(f"  {label:<28} {count:>6}  {bar}")

        print("=" * 70)


class ReconScanner:
    def __init__(self):
        self.data = defaultdict(set)
        self.domain = None
        self.duration = 0
        self.request_count = 0

    def prompt_target(self):
        raw = input("Target domain: ").strip()
        if raw.startswith(('http://', 'https://')):
            raw = urlparse(raw).netloc
        self.domain = raw
        return self.domain

    def run(self):
        start = time.time()

        print(f"\nTarget: {self.domain}")
        print("Starting scan...\n")

        try:
            dns_results = DNSEnumerator().enumerate(self.domain)
            for key, values in dns_results.items():
                self.data[key].update(values)
            print("[+] DNS enumeration complete")
        except Exception as e:
            print(f"[!] DNS enumeration failed: {e}")

        try:
            whois_results = WhoisAnalyzer.analyze(self.domain)
            for key, value in whois_results.items():
                if isinstance(value, set):
                    self.data[key].update(value)
                elif value:
                    self.data[key].add(value)
            print("[+] WHOIS lookup complete")
        except Exception as e:
            print(f"[!] WHOIS lookup failed: {e}")

        try:
            ssl_results = SSLAnalyzer.analyze(self.domain)
            for key, value in ssl_results.items():
                if isinstance(value, set):
                    self.data[key].update(value)
                elif isinstance(value, dict):
                    for k, v in value.items():
                        self.data[key].add(f"{k}: {v}")
                elif value:
                    self.data[key].add(value)
            print("[+] SSL analysis complete")
        except Exception as e:
            print(f"[!] SSL analysis failed: {e}")

        try:
            port_results = PortScanner.scan(self.domain)
            self.data['open_ports'].update(str(p) for p in port_results['open_ports'])
            print(f"[+] Port scan complete ({len(port_results['open_ports'])} open)")
        except Exception as e:
            print(f"[!] Port scan failed: {e}")

        try:
            bruteforcer = SubdomainBruteforcer(self.domain, threads=Config.THREADS)
            subdomains = bruteforcer.bruteforce()
            self.data['subdomains'].update(subdomains)
            print(f"[+] Subdomain brute force complete ({len(subdomains)} found)")
        except Exception as e:
            print(f"[!] Subdomain brute force failed: {e}")

        try:
            crawler = WebCrawler()
            crawl_results, request_count = crawler.crawl(self.domain)
            self.request_count = request_count
            for key, values in crawl_results.items():
                self.data[key].update(values)
            print(f"[+] Crawl complete ({request_count} requests)")
        except Exception as e:
            print(f"[!] Crawl failed: {e}")

        js_urls = [u for u in list(self.data.get('urls', set())) if u.endswith('.js')][:Config.JS_ANALYSIS_LIMIT]
        if js_urls:
            for url in js_urls:
                try:
                    response = requests.get(
                        url, timeout=10, verify=False,
                        headers={'User-Agent': random.choice(Config.USER_AGENTS)},
                    )
                    if response.status_code == 200:
                        js_results = JavaScriptAnalyzer.analyze(response.text)
                        for key, values in js_results.items():
                            self.data[key].update(values)
                except requests.RequestException:
                    continue
            print(f"[+] JS analysis complete ({len(js_urls)} files)")

        self.duration = time.time() - start

    def menu(self):
        reporter = ReportGenerator()
        reporter.print_console(self.data, self.domain, self.duration, self.request_count)

        while True:
            choice = input("\n[1] New scan  [2] JSON  [3] HTML  [4] XML  [5] Stats  [6] Exit\n> ").strip()

            if choice == '1':
                self.data = defaultdict(set)
                self.request_count = 0
                self.prompt_target()
                self.run()
                reporter.print_console(self.data, self.domain, self.duration, self.request_count)

            elif choice == '2':
                filename = f"recon_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                reporter.export_json(self.data, filename, self.domain, self.duration, self.request_count)
                print(f"[+] Saved: {filename}")

            elif choice == '3':
                filename = f"recon_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                reporter.export_html(self.data, filename, self.domain, self.duration, self.request_count)
                print(f"[+] Saved: {filename}")

            elif choice == '4':
                filename = f"recon_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
                reporter.export_xml(self.data, filename, self.domain, self.duration, self.request_count)
                print(f"[+] Saved: {filename}")

            elif choice == '5':
                reporter.print_statistics(self.data)

            elif choice == '6':
                sys.exit(0)


def main():
    try:
        scanner = ReconScanner()
        scanner.prompt_target()
        scanner.run()
        scanner.menu()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

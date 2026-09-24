import re
import sys
import json
import time
import threading
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()


class Config:
    DEFAULT_DEPTH = 2
    DEFAULT_THREADS = 8
    DEFAULT_TIMEOUT = 10
    MAX_DEPTH = 5
    MAX_THREADS = 20
    MIN_TIMEOUT = 5
    MAX_TIMEOUT = 30
    RATE_LIMIT = 0.05


class PatternExtractor:
    def __init__(self):
        self.patterns = {
            'emails': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'ipv4': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'ipv6': re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'),
            'aws_keys': re.compile(r'AKIA[0-9A-Z]{16}'),
            'google_api': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            'firebase': re.compile(r'[a-z0-9-]+\.firebaseio\.com'),
            'stripe': re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
            'ssh_key': re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
            'github_token': re.compile(r'ghp_[a-zA-Z0-9]{36}'),
            'jwt': re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
            'subdomains': re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'),
            'urls': re.compile(r'https?://[^\s<>"\']+'),
            'social_media': re.compile(r'(?:https?://)?(?:www\.)?(?:twitter|facebook|linkedin|instagram|github|youtube|telegram|discord)\.(?:com|org)/[^\s<>"\']+'),
            'discord_webhook': re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+'),
            'telegram_bot': re.compile(r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}'),
            'sql_error': re.compile(r'(?i)(?:SQL syntax|mysql_fetch|Warning: mysql|PostgreSQL.*ERROR|ORA-[0-9]{5})'),
            'xss_vulnerable': re.compile(r'(?i)<script[^>]*>[^<]*(?:alert|prompt|confirm)\([^)]*\)[^<]*</script>'),
            'api_endpoints': re.compile(r'/api/v?[0-9]*/[a-zA-Z0-9/_-]+'),
            'env_vars': re.compile(r'(?i)(?:API_KEY|SECRET_KEY|PASSWORD|DB_PASS|TOKEN)=[^\s&]+'),
            'comments': re.compile(r'<!--[\s\S]*?-->'),
        }

        self.file_extensions = {
            'documents': ['.pdf', '.docx', '.xlsx', '.xls', '.doc', '.ppt', '.pptx'],
            'databases': ['.sql', '.db', '.sqlite', '.sqlite3', '.mdb', '.bkp', '.dump'],
            'archives': ['.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.bz2'],
            'configs': ['.env', '.config', '.ini', '.yml', '.yaml'],
            'scripts': ['.js', '.py', '.php', '.asp', '.jsp', '.sh', '.bash'],
            'vpn': ['.ovpn'],
            'git': ['.git/config', '.git/HEAD'],
        }

        self.technologies = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin'],
            'Joomla': ['joomla', 'components/com_'],
            'Drupal': ['drupal', '/sites/default/'],
            'React': ['react.createElement', 'reactdom'],
            'Vue.js': ['vue.component', '__vue__'],
            'Angular': ['ng-app', 'ng-controller'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap.min', 'bootstrap.css'],
            'Laravel': ['laravel_session'],
            'Django': ['csrfmiddlewaretoken'],
            'Express': ['x-powered-by: express'],
            'Flask': ['werkzeug'],
            'Nginx': ['server: nginx'],
            'Apache': ['server: apache'],
            'Cloudflare': ['cf-ray', '__cfduid'],
            'Google Analytics': ['google-analytics', 'gtag', 'analytics.js'],
            'Firebase': ['firebaseio'],
            'AWS': ['amazonaws.com'],
        }

    def extract_all(self, content, base_domain):
        results = defaultdict(set)
        content_lower = content.lower()

        for name, pattern in self.patterns.items():
            try:
                matches = pattern.findall(content)
            except re.error:
                continue

            if name == 'subdomains':
                matches = [m for m in matches if base_domain in m and m != base_domain]
            results[name].update(matches)

        for category, extensions in self.file_extensions.items():
            for ext in extensions:
                if ext in content_lower:
                    pattern = re.compile(rf'https?://[^\s<>"\']+{re.escape(ext)}', re.IGNORECASE)
                    results[f'files_{category}'].update(pattern.findall(content))

        for tech, signatures in self.technologies.items():
            if any(sig in content_lower for sig in signatures):
                results['technologies'].add(tech)

        return results


class WebCrawler:
    def __init__(self, depth=Config.DEFAULT_DEPTH, threads=Config.DEFAULT_THREADS,
                 timeout=Config.DEFAULT_TIMEOUT):
        self.depth = depth
        self.threads = threads
        self.timeout = timeout
        self.visited = set()
        self.lock = threading.Lock()
        self.counter_lock = threading.Lock()
        self.results = defaultdict(set)
        self.request_count = 0
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; ReconBot/3.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })

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
                for attr in ('href', 'src'):
                    url = tag.get(attr)
                    if url:
                        normalized = self._normalize_url(url, base_url)
                        if normalized:
                            links.add(normalized)
        except Exception:
            pass
        return links

    def _fetch(self, url):
        try:
            response = self.session.get(
                url, timeout=self.timeout, verify=False, allow_redirects=True,
            )
            with self.counter_lock:
                self.request_count += 1
            time.sleep(Config.RATE_LIMIT)
            return response.text, dict(response.headers)
        except requests.RequestException:
            return None, None

    def _process_url(self, url, base_domain, extractor):
        content, headers = self._fetch(url)
        if not content:
            return set()

        extracted = extractor.extract_all(content, base_domain)

        with self.lock:
            for key, values in extracted.items():
                self.results[key].update(values)

            if headers:
                self.results['server_info'].add(headers.get('Server', 'Unknown'))

        links = self._extract_links(content, url)
        return {link for link in links if base_domain in link}

    def _detect_start_url(self, base_domain):
        for scheme in ('https', 'http'):
            candidate = f"{scheme}://{base_domain}"
            try:
                response = self.session.get(
                    candidate, timeout=self.timeout, verify=False, allow_redirects=True,
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
        print("[+] Starting crawl")

        start_url = self._detect_start_url(base_domain)
        if not start_url:
            print("[!] Target unreachable via HTTP/HTTPS")
            return self.results, self.request_count

        self.visited.add(start_url)
        current_level = [start_url]

        for _ in range(self.depth):
            if not current_level:
                break

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
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

            current_level = next_level[:100]

        print(f"[+] Crawl complete ({self.request_count} requests)")
        return self.results, self.request_count


REPORT_CATEGORIES = {
    'Credentials & Secrets': {
        'AWS Keys': 'aws_keys',
        'Google API Keys': 'google_api',
        'Firebase URLs': 'firebase',
        'Stripe Keys': 'stripe',
        'SSH Private Keys': 'ssh_key',
        'GitHub Tokens': 'github_token',
        'JWT Tokens': 'jwt',
        'Environment Variables': 'env_vars',
    },
    'Contact Information': {
        'Email Addresses': 'emails',
    },
    'Network': {
        'IPv4 Addresses': 'ipv4',
        'IPv6 Addresses': 'ipv6',
        'Subdomains': 'subdomains',
        'Server Information': 'server_info',
    },
    'Social Media': {
        'Social Media Links': 'social_media',
        'Discord Webhooks': 'discord_webhook',
        'Telegram Bots': 'telegram_bot',
    },
    'API & Endpoints': {
        'API Endpoints': 'api_endpoints',
    },
    'Security Indicators': {
        'SQL Errors': 'sql_error',
        'XSS Indicators': 'xss_vulnerable',
        'HTML Comments': 'comments',
    },
    'Technologies': {
        'Tech Stack': 'technologies',
    },
    'Files Discovered': {
        'Documents': 'files_documents',
        'Databases': 'files_databases',
        'Archives': 'files_archives',
        'Config Files': 'files_configs',
        'Scripts': 'files_scripts',
        'VPN Files': 'files_vpn',
        'Git Files': 'files_git',
    },
}


class ReportGenerator:
    def print_console(self, data, domain, duration, requests_count):
        total = sum(len(v) for v in data.values())

        print("\n" + "=" * 80)
        print(f"  REPORT - {domain}")
        print(f"  Duration: {duration:.2f}s | Requests: {requests_count} | Data Points: {total}")
        print("=" * 80)

        for section, items in REPORT_CATEGORIES.items():
            print(f"\n--- {section} ---")

            section_has_data = False
            for label, key in items.items():
                values = data.get(key, set())
                if not values:
                    continue
                section_has_data = True
                print(f"\n  {label} ({len(values)}):")
                for item in sorted(list(values))[:10]:
                    print(f"    {item}")
                if len(values) > 10:
                    print(f"    ... and {len(values) - 10} more")

            if not section_has_data:
                print("  No data")

        print("\n" + "=" * 80)
        print(f"  Scan complete. Total data points: {total}")
        print("=" * 80)

    def export_json(self, data, filename, domain, duration, requests_count):
        serializable = {}
        for k, v in data.items():
            serializable[k] = sorted(list(v)) if isinstance(v, set) else v

        report = {
            'metadata': {
                'target': domain,
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': round(duration, 2),
                'http_requests': requests_count,
                'data_points': sum(len(v) for v in data.values()),
            },
            'data': serializable,
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    def export_txt(self, data, filename, domain, duration, requests_count):
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"Recon Report - {domain}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {duration:.2f}s | Requests: {requests_count}\n")
            f.write("=" * 80 + "\n\n")

            for section, items in REPORT_CATEGORIES.items():
                f.write(f"\n[{section}]\n")
                f.write("-" * 80 + "\n")

                section_has_data = False
                for label, key in items.items():
                    values = data.get(key, set())
                    if not values:
                        continue
                    section_has_data = True
                    f.write(f"\n  {label} ({len(values)}):\n")
                    for item in sorted(list(values)):
                        f.write(f"    {item}\n")

                if not section_has_data:
                    f.write("  No data\n")

    def print_statistics(self, data):
        total = sum(len(v) for v in data.values())

        print("\n" + "=" * 60)
        print("  Scan Statistics")
        print("=" * 60)
        print(f"  Total data points: {total}")

        for category, items in sorted(data.items(), key=lambda x: len(x[1]), reverse=True)[:15]:
            print(f"    {category}: {len(items)}")

        print("=" * 60)


class ReconScanner:
    def __init__(self):
        self.data = {}
        self.domain = ""
        self.duration = 0
        self.request_count = 0

    def prompt_target(self):
        raw = input("Target domain: ").strip()
        if raw.startswith(('http://', 'https://')):
            raw = urlparse(raw).netloc
        self.domain = raw
        return self.domain

    def prompt_depth(self):
        try:
            value = int(input(f"Crawl depth (1-{Config.MAX_DEPTH}, default {Config.DEFAULT_DEPTH}): "))
            return max(1, min(Config.MAX_DEPTH, value))
        except (ValueError, EOFError):
            return Config.DEFAULT_DEPTH

    def prompt_threads(self):
        try:
            value = int(input(f"Thread count (1-{Config.MAX_THREADS}, default {Config.DEFAULT_THREADS}): "))
            return max(1, min(Config.MAX_THREADS, value))
        except (ValueError, EOFError):
            return Config.DEFAULT_THREADS

    def prompt_timeout(self):
        try:
            value = int(input(f"Timeout in seconds ({Config.MIN_TIMEOUT}-{Config.MAX_TIMEOUT}, default {Config.DEFAULT_TIMEOUT}): "))
            return max(Config.MIN_TIMEOUT, min(Config.MAX_TIMEOUT, value))
        except (ValueError, EOFError):
            return Config.DEFAULT_TIMEOUT

    def run(self):
        domain = self.prompt_target()
        depth = self.prompt_depth()
        threads = self.prompt_threads()
        timeout = self.prompt_timeout()

        self.domain = domain
        start = time.time()

        crawler = WebCrawler(depth=depth, threads=threads, timeout=timeout)
        self.data, self.request_count = crawler.crawl(domain)

        self.duration = time.time() - start

        reporter = ReportGenerator()
        reporter.print_console(self.data, domain, self.duration, self.request_count)

        while True:
            choice = input("\n[1] New scan  [2] JSON  [3] TXT  [4] Stats  [5] Exit\n> ").strip()

            if choice == '1':
                self.data = {}
                self.request_count = 0
                self.run()
                return

            elif choice == '2':
                filename = f"recon_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                reporter.export_json(self.data, filename, self.domain, self.duration, self.request_count)
                print(f"[+] Saved: {filename}")

            elif choice == '3':
                filename = f"recon_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                reporter.export_txt(self.data, filename, self.domain, self.duration, self.request_count)
                print(f"[+] Saved: {filename}")

            elif choice == '4':
                reporter.print_statistics(self.data)

            elif choice == '5':
                sys.exit(0)


def main():
    try:
        scanner = ReconScanner()
        scanner.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

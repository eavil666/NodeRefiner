import requests
import yaml
import time
import os
import hashlib
import logging
from typing import Optional, Dict, List, Any, Set, Tuple
import json
import csv
import urllib3
import base64
from urllib.parse import urlparse, quote
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OUTPUT_DIR = 'output'
LOG_DIR = 'logs'
os.makedirs(LOG_DIR, exist_ok=True)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'url_processor.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ProxyInfo:
    """代理信息数据类，集成了全协议（含新协议）转换分享链接及Xray配置输出逻辑"""
    name: str
    type: str
    server: str
    port: int
    cipher: str = ""
    password: str = ""
    uuid: str = ""
    network: str = ""
    tls: bool = False
    udp: bool = True
    alterId: int = 0
    sni: str = ""
    host: str = ""
    path: str = ""
    security: str = ""
    protocol: str = ""
    obfs: str = ""
    obfs_host: str = ""
    obfs_path: str = ""
    remarks: str = ""
    group: str = ""
    scy: str = ""
    alpn: Any = ""
    skip_cert_verify: bool = False
    source_url: str = ""
    
    # WireGuard 专属特有属性
    private_key: str = ""
    public_key: str = ""
    preshared_key: str = ""
    reserved: str = ""
    mtu: int = 1420
    
    def get_fingerprint(self) -> str:
        """生成代理的唯一指纹，用于精准去重"""
        ptype = self.type.lower()
        if ptype in ['wireguard', 'wg']:
            key_part = self.private_key or self.public_key
            data = f"wireguard|{self.server}|{self.port}|{key_part}"
        elif ptype in ['vmess', 'vless']:
            data = f"{self.type}|{self.server}|{self.port}|{self.uuid}"
        elif ptype in ['hysteria2', 'hy2']:
            data = f"hysteria2|{self.server}|{self.port}|{self.password}"
        elif ptype == 'hysteria':
            data = f"hysteria|{self.server}|{self.port}|{self.password}"
        elif ptype in ['trojan', 'socks5', 'http']:
            data = f"{ptype}|{self.server}|{self.port}|{self.password}"
        elif ptype in ['tuic', 'anytls']:
            auth = self.uuid or self.password
            data = f"{ptype}|{self.server}|{self.port}|{auth}"
        elif ptype in ['ssr', 'shadowsocksr']:
            data = f"{self.type}|{self.server}|{self.port}|{self.cipher}|{self.password}|{self.protocol}|{self.obfs}|{self.obfs_host}|{self.obfs_path}"
        elif ptype == 'ss':
            data = f"{self.type}|{self.server}|{self.port}|{self.password}|{self.cipher}"
        elif ptype == 'mieru':
            data = f"{ptype}|{self.server}|{self.port}|{self.password}|{self.cipher}"
        else:
            data = f"{self.type}|{self.server}|{self.port}|{self.uuid}|{self.password}"
        
        return hashlib.md5(data.encode('utf-8')).hexdigest()
    
    def to_share_link(self) -> str:
        """将自身属性转换为标准客户端一键导入分享链接"""
        ptype = self.type.lower()
        name_encoded = quote(self.name)
        
        if ptype in ['hysteria2', 'hy2']:
            params = {}
            if self.obfs_host: params['obfs'] = self.obfs_host
            if self.sni: params['sni'] = self.sni
            query = '&'.join([f"{k}={quote(str(v))}" for k, v in params.items() if v])
            return f"hysteria2://{self.password}@{self.server}:{self.port}" + (f"?{query}" if query else "") + f"#{name_encoded}"
        elif ptype == 'hysteria':
            params = {}
            if self.obfs_host: params['obfs'] = self.obfs_host
            if self.sni: params['sni'] = self.sni
            query = '&'.join([f"{k}={quote(str(v))}" for k, v in params.items() if v])
            return f"hysteria://{self.password}@{self.server}:{self.port}" + (f"?{query}" if query else "") + f"#{name_encoded}"
        elif ptype == 'ssr' or ptype == 'shadowsocksr':
            method = self.cipher or 'aes-128-cfb'
            proto = self.protocol or 'origin'
            obfs = self.obfs or 'plain'
            password_b64 = base64.b64encode(self.password.encode('utf-8')).decode('utf-8').rstrip('=')
            auth = f"{self.server}:{self.port}:{proto}:{method}:{obfs}:{password_b64}"
            params = {}
            if self.obfs_host:
                params['obfsparam'] = base64.b64encode(self.obfs_host.encode('utf-8')).decode('utf-8').rstrip('=')
            if self.obfs_path:
                params['protoparam'] = base64.b64encode(self.obfs_path.encode('utf-8')).decode('utf-8').rstrip('=')
            if self.remarks:
                params['remarks'] = base64.b64encode(self.remarks.encode('utf-8')).decode('utf-8').rstrip('=')
            else:
                params['remarks'] = base64.b64encode(self.name.encode('utf-8')).decode('utf-8').rstrip('=')
            if self.group:
                params['group'] = base64.b64encode(self.group.encode('utf-8')).decode('utf-8').rstrip('=')
            query = '&'.join([f"{k}={quote(str(v))}" for k, v in params.items() if v])
            encoded = base64.b64encode(auth.encode('utf-8')).decode('utf-8').rstrip('=')
            return f"ssr://{encoded}/?{query}"

        elif ptype == 'mieru':
            params = {}
            if self.sni: params['sni'] = self.sni
            if self.network: params['network'] = self.network
            if self.path: params['path'] = self.path
            if self.obfs_host: params['host'] = self.obfs_host
            query = '&'.join([f"{k}={quote(str(v))}" for k, v in params.items() if v])
            return f"mieru://{quote(self.password)}@{self.server}:{self.port}" + (f"?{query}" if query else "") + f"#{name_encoded}"

        elif ptype == 'tuic':
            params = {
                'alpn': self.alpn or 'h3',
                'sni': self.sni or self.server
            }
            auth = f"{self.uuid}:{self.password}" if (self.uuid and self.password) else (self.uuid or self.password)
            query = '&'.join([f"{k}={quote(str(v))}" for k, v in params.items() if v])
            return f"tuic://{auth}@{self.server}:{self.port}?{query}#{name_encoded}"
            
        elif ptype == 'anytls':
            params = {
                'sni': self.sni or self.server,
                'allow_insecure': '1' if self.skip_cert_verify else '0'
            }
            auth = f"{self.uuid}:{self.password}" if (self.uuid and self.password) else (self.uuid or self.password)
            query = '&'.join([f"{k}={quote(str(v))}" for k, v in params.items() if v])
            return f"anytls://{auth}@{self.server}:{self.port}?{query}#{name_encoded}"

        elif ptype in ['wireguard', 'wg']:
            params = {
                'privateKey': self.private_key,
                'publicKey': self.public_key,
                'mtu': str(self.mtu)
            }
            if self.preshared_key: params['presharedKey'] = self.preshared_key
            if self.reserved: params['reserved'] = self.reserved
            params['ip'] = self.host if self.host else "10.0.0.2"
            query = '&'.join([f"{k}={quote(str(v))}" for k, v in params.items() if v])
            return f"wireguard://{self.server}:{self.port}?{query}#{name_encoded}"
            
        elif ptype == 'vless':
            params = {
                'encryption': 'none',
                'security': self.security or ('tls' if self.tls else 'none'),
                'sni': self.sni,
                'type': self.network or 'tcp'
            }
            if self.path: params['path'] = self.path
            if self.host: params['host'] = self.host
            query = '&'.join([f"{k}={quote(str(v))}" for k, v in params.items() if v])
            return f"vless://{self.uuid}@{self.server}:{self.port}?{query}#{name_encoded}"
            
        elif ptype == 'vmess':
            vmess_config = {
                "v": "2", "ps": self.name, "add": self.server, "port": str(self.port), "id": self.uuid,
                "aid": str(self.alterId), "net": self.network or 'tcp', "type": "none", 
                "host": self.host, "path": self.path, "tls": "tls" if self.tls else ""
            }
            json_str = json.dumps(vmess_config, sort_keys=True)
            encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
            return f"vmess://{encoded}"
            
        elif ptype == 'trojan':
            params = {}
            if self.sni: params['sni'] = self.sni
            if self.network == 'ws':
                params['type'] = 'ws'
                if self.path: params['path'] = self.path
            query = '&'.join([f"{k}={quote(str(v))}" for k, v in params.items() if v])
            return f"trojan://{self.password}@{self.server}:{self.port}" + (f"?{query}" if query else "") + f"#{name_encoded}"
            
        elif ptype == 'ss':
            auth_str = f"{self.cipher}:{self.password}"
            auth_b64 = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8').rstrip('=')
            return f"ss://{auth_b64}@{self.server}:{self.port}#{name_encoded}"
            
        elif ptype in ['socks5', 'http']:
            auth = f"{self.uuid}:{self.password}@" if (self.uuid and self.password) else ""
            return f"{ptype}://{auth}{self.server}:{self.port}#{name_encoded}"
            
        return f"unknown://{self.server}:{self.port}#{name_encoded}"

    def to_xray_outbound(self) -> Optional[Dict[str, Any]]:
        """生成对应 Xray Outbound 核心 JSON 配置块"""
        ptype = self.type.lower()
        if ptype in ['wireguard', 'wg']:
            ips = [x.strip() for x in self.host.split(',') if x.strip()] if self.host else ["10.0.0.2"]
            config = {
                "protocol": "wireguard",
                "settings": {
                    "secretKey": self.private_key,
                    "address": ips,
                    "peers": [{
                        "publicKey": self.public_key,
                        "endpoint": f"{self.server}:{self.port}"
                    }],
                    "mtu": self.mtu
                }
            }
            if self.preshared_key:
                config["settings"]["peers"][0]["presharedKey"] = self.preshared_key
            return config
        elif ptype == 'vless':
            return {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": self.server,
                        "port": self.port,
                        "users": [{"id": self.uuid, "encryption": "none"}]
                    }]
                }
            }
        elif ptype in ['hysteria2', 'hy2']:
            return {
                "protocol": "hysteria2",
                "settings": {
                    "servers": [{
                        "address": self.server,
                        "port": self.port,
                        "password": self.password
                    }]
                }
            }
        elif ptype == 'hysteria':
            return {
                "protocol": "hysteria",
                "settings": {
                    "servers": [{
                        "address": self.server,
                        "port": self.port,
                        "password": self.password
                    }]
                }
            }
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}

class DuplicateManager:
    """全局增量重复数据管理器"""
    def __init__(self, data_file: str = os.path.join(OUTPUT_DIR, 'processed_proxies.json')):
        self.data_file = data_file
        self.processed_proxies: Dict[str, Dict] = {}  
        self.processed_urls: Set[str] = set()  
        self.load_processed_data()
    
    def load_processed_data(self):
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.processed_proxies = data.get('proxies', {})
                    self.processed_urls = set(data.get('urls', []))
                logger.info(f"已成功读取去重库：载入 {len(self.processed_proxies)} 个历史代理记录")
            except Exception as e:
                logger.error(f"加载去重数据库失败: {e}")
    
    def save_processed_data(self):
        try:
            data = {
                'proxies': self.processed_proxies,
                'urls': list(self.processed_urls),
                'updated_at': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info(f"去重库已更新保存 ── 累计记录: {len(self.processed_proxies)} 条")
        except Exception as e:
            logger.error(f"持久化去重库数据失败: {e}")
    
    def is_url_processed(self, url: str) -> bool:
        return url in self.processed_urls
    
    def is_proxy_duplicate(self, proxy_info: ProxyInfo) -> Tuple[bool, Optional[Dict]]:
        fingerprint = proxy_info.get_fingerprint()
        if fingerprint in self.processed_proxies:
            return True, self.processed_proxies[fingerprint]
        return False, None
    
    def add_processed_url(self, url: str):
        self.processed_urls.add(url)
    
    def add_processed_proxy(self, proxy_info: ProxyInfo):
        self.processed_proxies[proxy_info.get_fingerprint()] = proxy_info.to_dict()
    
    def update_proxy_source(self, fingerprint: str, new_source_url: str):
        if fingerprint in self.processed_proxies:
            proxy_data = self.processed_proxies[fingerprint]
            current_sources = proxy_data.get('source_urls', [])
            if isinstance(current_sources, str):
                current_sources = [current_sources]
            elif not isinstance(current_sources, list):
                current_sources = []
            
            if new_source_url not in current_sources:
                current_sources.append(new_source_url)
            proxy_data['source_urls'] = current_sources
            self.processed_proxies[fingerprint] = proxy_data

class YAMLConfigProcessor:
    """YAML 配置文件处理器（内置并发高智能 HTTP/HTTPS 获取算法）"""
    def __init__(self, timeout: int = 15, retry_count: int = 2, 
                 verify_ssl: bool = False, follow_redirects: bool = True,
                 skip_processed_urls: bool = True, max_workers: int = 15):
        self.timeout = timeout
        self.retry_count = retry_count
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.skip_processed_urls = skip_processed_urls
        self.max_workers = max_workers
        self.dup_manager = DuplicateManager()
        
    def _create_thread_session(self, verify_ssl: bool) -> requests.Session:
        """为每个子线程创建独立的、防冲突的网络会话客户端"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Connection': 'keep-alive'
        })
        adapter = requests.adapters.HTTPAdapter(pool_connections=2, pool_maxsize=2, max_retries=1)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.verify = verify_ssl
        return session
    
    def normalize_url(self, url: str) -> str:
        if not url: return url
        parsed = urlparse(url)
        return url if parsed.scheme else f"http://{url}"
    
    def is_yaml_content(self, content: str) -> bool:
        if not content or not content.strip(): return False
        content_stripped = content.strip()
        try:
            data = yaml.safe_load(content_stripped)
            if isinstance(data, dict) and 'proxies' in data: return True
        except yaml.YAMLError: pass
        
        yaml_indicators = ['proxies:', 'mixed-port:', 'port:', 'mode:', 'rules:']
        if any(indicator in content for indicator in yaml_indicators): return True
        
        proxy_indicators = [
            'type: vmess', 'type: vless', 'type: ss', 'type: ssr', 'type: shadowsocksr', 'type: trojan',
            'type: wireguard', 'type: wg', 'type: hysteria2', 'type: hy2', 'type: hysteria',
            'type: mieru', 'type: tuic', 'type: anytls'
        ]
        return any(indicator in content.lower() for indicator in proxy_indicators)
    
    def fetch_single_url_worker(self, url: str, index_str: str) -> Tuple[str, Optional[str], str]:
        """【并发子任务工作元】负责单个 URL 的弹性下载请求与初筛格式校验"""
        if self.skip_processed_urls and self.dup_manager.is_url_processed(url):
            return url, None, "SKIP"
            
        normalized_url = self.normalize_url(url)
        current_verify = self.verify_ssl
        backoff_delay = 1.5  
        session = self._create_thread_session(current_verify)
        
        for attempt in range(self.retry_count + 1):
            try:
                current_timeout = self.timeout if attempt > 0 else 5.0
                logger.info(f"🔍 [{index_str}][尝试 {attempt + 1}/{self.retry_count + 1}] 正在智能抓取: {normalized_url}")
                
                probe = session.head(
                    normalized_url, 
                    timeout=current_timeout,
                    allow_redirects=self.follow_redirects
                )
                
                if probe.status_code in [404, 410, 502, 504] and attempt == self.retry_count:
                    return url, None, f"HTTP_{probe.status_code}"
                
                response = session.get(
                    normalized_url, 
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects
                )
                
                if response.status_code == 200:
                    content = response.text
                    if self.is_yaml_content(content):
                        return url, content, "SUCCESS"
                    
                    cleaned = self.clean_content(content)
                    if self.is_yaml_content(cleaned):
                        return url, cleaned, "SUCCESS"
                    
                    return url, None, "INVALID_YAML_FORMAT"

            except requests.exceptions.SSLError:
                if current_verify:
                    current_verify = False
                    session.verify = False
                    continue
            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.RequestException:
                if normalized_url.startswith('https://'):
                    normalized_url = normalized_url.replace('https://', 'http://')
                    continue
            
            if attempt < self.retry_count:
                time.sleep(backoff_delay * (1.2 ** attempt))
                
        return url, None, "FAILED_TIMEOUT_OR_NETWORK"
    
    def clean_content(self, content: str) -> str:
        if not content: return content
        lines = content.split('\n')
        cleaned_lines, in_yaml = [], False
        
        for line in lines:
            stripped = line.strip()
            if (stripped.startswith('<') and stripped.endswith('>')) or '<script' in line.lower() or '<style' in line.lower():
                continue
            if any(marker in line for marker in ['proxies:', 'mixed-port:', 'port:', 'mode:']):
                in_yaml = True
            if in_yaml:
                cleaned_lines.append(line)
            if '---' in line and in_yaml:
                break
                
        if not cleaned_lines:
            for line in lines:
                stripped = line.strip()
                if ':' in stripped and not stripped.startswith(('<', '{', '[')) and len(stripped.split(':')) >= 2:
                    cleaned_lines.append(line)
        return '\n'.join(cleaned_lines)

    def validate_and_clean_proxy_dict(self, proxy: dict, idx: int, source_url: str) -> Tuple[bool, Optional[dict]]:
        if not isinstance(proxy, dict):
            return False, None

        ptype = str(proxy.get('type', '')).strip().lower()
        server_addr = str(proxy.get('server', '') or proxy.get('ip', '')).strip()
        name_val = str(proxy.get('name', '')).strip()

        if not ptype or not server_addr or not name_val:
            return False, None

        try:
            port_val = int(proxy.get('port', 0))
            if port_val <= 0 or port_val > 65535: return False, None
            proxy['port'] = port_val
        except:
            return False, None

        if 'obfs' in proxy:
            obfs_val = proxy['obfs']
            if obfs_val and str(obfs_val).lower() != 'none':
                obfs_pass = proxy.get('obfs-password', proxy.get('obfs_password', ''))
                if not obfs_pass and isinstance(proxy.get('plugin-opts'), dict):
                    obfs_pass = proxy['plugin-opts'].get('password', '')
                if not str(obfs_pass).strip():
                    proxy.pop('obfs', None)
                    proxy.pop('obfs-password', None)
                    proxy.pop('obfs_password', None)

        if ptype in ['tuic', 'anytls']:
            uuid_val = str(proxy.get('uuid', '')).strip()
            pass_val = str(proxy.get('password', '')).strip()
            if not uuid_val and not pass_val: return False, None
        elif ptype in ['hysteria2', 'hy2', 'trojan']:
            if not str(proxy.get('password', '')).strip(): return False, None
        elif ptype in ['vless', 'vmess']:
            if not str(proxy.get('uuid', '')).strip(): return False, None

        if ptype in ['wireguard', 'wg']:
            private_key = str(proxy.get('private-key', proxy.get('private_key', ''))).strip()
            if not private_key or private_key.lower() == "none": return False, None
            proxy['private-key'] = private_key 

            ip_field = proxy.get('ip', '10.0.0.2')
            if isinstance(ip_field, list):
                proxy['ip'] = str(ip_field[0]).strip() if len(ip_field) > 0 else "10.0.0.2"
            else:
                proxy['ip'] = str(ip_field).strip()
            if not proxy['ip'] or proxy['ip'].lower() == "none": proxy['ip'] = "10.0.0.2"

        elif ptype == 'vmess':
            try: proxy['alterId'] = int(proxy.get('alterId', 0))
            except: proxy['alterId'] = 0

        if 'alpn' in proxy and proxy['alpn']:
            raw_alpn = proxy['alpn']
            processed_alpn = []
            if isinstance(raw_alpn, list):
                processed_alpn = [str(item).strip() for item in raw_alpn if item]
            elif isinstance(raw_alpn, str):
                if ',' in raw_alpn:
                    processed_alpn = [item.strip() for item in raw_alpn.split(',') if item.strip()]
                else:
                    processed_alpn = [raw_alpn.strip()]
            if processed_alpn: proxy['alpn'] = processed_alpn
            else: proxy.pop('alpn', None)

        for uncompliant_key in ['sni', 'host', 'path']:
            if uncompliant_key in proxy and (proxy[uncompliant_key] == "" or proxy[uncompliant_key] is None):
                del proxy[uncompliant_key]

        return True, proxy
    
    def extract_all_proxies(self, config_content: str, source_url: str) -> List[ProxyInfo]:
        all_proxies = []
        try:
            config_data = None
            try: config_data = yaml.safe_load(config_content)
            except yaml.YAMLError:
                cleaned = self.clean_yaml_content(config_content)
                try: config_data = yaml.safe_load(cleaned)
                except: pass
            
            if not config_data or 'proxies' not in config_data: return all_proxies
            proxies = config_data['proxies']
            if not isinstance(proxies, list): return all_proxies
            
            for idx, proxy in enumerate(proxies):
                try:
                    is_pass, cleaned_proxy = self.validate_and_clean_proxy_dict(proxy, idx, source_url)
                    if not is_pass or not cleaned_proxy: continue

                    ip_field = cleaned_proxy.get('ip', '10.0.0.2')
                    if isinstance(ip_field, list): ip_field = ",".join(ip_field)
                    reserved_field = cleaned_proxy.get('reserved', '')
                    if isinstance(reserved_field, list): reserved_field = ",".join(map(str, reserved_field))
                    
                    proxy_info = ProxyInfo(
                        name=cleaned_proxy['name'],
                        type=cleaned_proxy['type'],
                        server=cleaned_proxy['server'],
                        port=cleaned_proxy['port'],
                        cipher=str(cleaned_proxy.get('cipher', '')),
                        password=str(cleaned_proxy.get('password', '')),
                        uuid=str(cleaned_proxy.get('uuid', '')),
                        network=str(cleaned_proxy.get('network', '')),
                        tls=bool(cleaned_proxy.get('tls', False)),
                        udp=bool(cleaned_proxy.get('udp', True)),
                        alterId=int(cleaned_proxy.get('alterId', 0)),
                        sni=str(cleaned_proxy.get('sni', '')),
                        host=str(ip_field), 
                        path=str(cleaned_proxy.get('path', '')),
                        security=str(cleaned_proxy.get('security', '')),
                        protocol=str(cleaned_proxy.get('protocol', '')),
                        obfs=str(cleaned_proxy.get('obfs', '')),
                        obfs_host=str(cleaned_proxy.get('obfs-host', cleaned_proxy.get('obfs_host', cleaned_proxy.get('host', '')))),
                        obfs_path=str(cleaned_proxy.get('obfs-path', cleaned_proxy.get('obfs_path', ''))),
                        remarks=str(cleaned_proxy.get('remarks', '')),
                        group=str(cleaned_proxy.get('group', '')),
                        scy=str(cleaned_proxy.get('scy', '')),
                        alpn=cleaned_proxy.get('alpn', ''), 
                        skip_cert_verify=bool(cleaned_proxy.get('skip-cert-verify', False)),
                        source_url=source_url,
                        private_key=str(cleaned_proxy.get('private-key', '')),
                        public_key=str(cleaned_proxy.get('public-key', '')),
                        preshared_key=str(cleaned_proxy.get('preshared-key', '')),
                        reserved=str(reserved_field),
                        mtu=int(cleaned_proxy.get('mtu', 1420))
                    )
                    proxy_info.ip = str(ip_field)
                    all_proxies.append(proxy_info)
                except:
                    pass
        except:
            pass
        return all_proxies
    
    def clean_yaml_content(self, content: str) -> str:
        if content.startswith('\ufeff'): content = content[1:]
        return ''.join([c for c in content if ord(c) >= 32 or c in '\n\r\t'])
    
    def read_url_list(self, file_path: str) -> List[str]:
        urls = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'): urls.append(line)
            logger.info(f"成功导入订阅源配置文件，获取待刷入 URL 共: {len(urls)} 条")
        except Exception as e:
            logger.error(f"无法正确读取 URL 载入配置文件: {e}")
        return urls

    def _batch_save_proxies_to_disk(self, valid_results: List[Tuple[str, List[ProxyInfo]]], output_csv: str, output_json: str, output_links: str):
        """【主线程批量串行写入】实现单点磁盘追加，绝对规避文件读写并发冲突"""
        # 1. 预载入现有 JSON 库防覆盖
        existing_json_data = []
        if os.path.exists(output_json):
            try:
                with open(output_json, 'r', encoding='utf-8') as f:
                    existing_json_data = json.load(f)
            except: pass

        csv_exists = os.path.exists(output_csv) and os.path.getsize(output_csv) > 0
        
        with open(output_csv, 'a', encoding='utf-8-sig', newline='') as f_csv, \
             open(output_links, 'a', encoding='utf-8') as f_links:
             
            writer = csv.writer(f_csv)
            if not csv_exists:
                writer.writerow(['来源URL', '名称', '类型', '服务器', '端口', '加密方式', 
                                 '密码', 'UUID', '网络协议', 'TLS', 'UDP', '提取时间', '分享链接'])
            
            for url, proxies in valid_results:
                new_proxies_for_this_url = []
                
                for p in proxies:
                    is_duplicate, _ = self.dup_manager.is_proxy_duplicate(p)
                    if is_duplicate:
                        self.dup_manager.update_proxy_source(p.get_fingerprint(), url)
                    else:
                        new_proxies_for_this_url.append(p)
                        self.dup_manager.add_processed_proxy(p)

                # 写入该 URL 贡献的去重全新节点
                for p in new_proxies_for_this_url:
                    # CSV 追加
                    writer.writerow([url, p.name, p.type, p.server, str(p.port), p.cipher,
                                     p.password, p.uuid, p.network, str(p.tls), str(p.udp),
                                     time.strftime('%Y-%m-%d %H:%M:%S'), p.to_share_link()])
                    # 纯链路追加
                    f_links.write(f"{p.to_share_link()}\n")
                    
                    # 汇编 JSON 对象
                    proxy_data = p.to_dict()
                    proxy_data['fingerprint'] = p.get_fingerprint()
                    proxy_data['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
                    proxy_data['share_link'] = p.to_share_link()
                    proxy_data['xray_config'] = p.to_xray_outbound()
                    existing_json_data.append(proxy_data)
                    
                self.dup_manager.add_processed_url(url)
                if new_proxies_for_this_url:
                    logger.info(f"💾 数据持久化完成 ── 源 {url} 成功录入全新节点 {len(new_proxies_for_this_url)} 个")

        # 重写更新整个 JSON 文件结构
        try:
            with open(output_json, 'w', encoding='utf-8') as f_json:
                json.dump(existing_json_data, f_json, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"同步更新 JSON 全局库文件失败: {e}")
            
    def save_failed_url(self, url: str, reason: str, failed_file: str):
        try:
            with open(failed_file, 'a', encoding='utf-8') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {url} | {reason}\n")
        except:
            pass
    
    def process_urls(self, input_file: str, output_csv: str = 'all_proxies.csv', 
                     output_json: str = 'all_proxies.json', output_links: str = 'all_links.txt',
                     failed_log: str = 'failed_urls.txt'):
        logger.info(f"⚡ 自动化并发节点采集流水线正式启动... 并发线程池数: {self.max_workers}")
        urls = self.read_url_list(input_file)
        if not urls: return
        
        total_urls = len(urls)
        fetched_contents: Dict[str, str] = {}
        failed_tracker: List[Tuple[str, str]] = []
        
        # ✨【高能多线程核心】：使用并发线程池抓取网络数据
        start_fetch_time = time.time()
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {
                executor.submit(self.fetch_single_url_worker, url, f"{i}/{total_urls}"): url 
                for i, url in enumerate(urls, 1)
            }
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    url, content, status = future.result()
                    if status == "SUCCESS" and content:
                        fetched_contents[url] = content
                    elif status == "SKIP":
                        logger.info(f"⏭️ [并发跳过] 该 URL 历史已成功解析，无需重抓: {url}")
                    else:
                        failed_tracker.append((url, status))
                except Exception as e:
                    failed_tracker.append((url, f"THREAD_EXCEPTION_{str(e)}"))

        logger.info(f"⏱️ 并发网页抓取下载彻底跑完，耗时: {time.time() - start_fetch_time:.2f} 秒。开始解析节点数组...")

        # 在主线程安全、无冲突地解析 YAML 并增量写入落盘
        valid_batch_results = []
        failed_count = len(failed_tracker)
        
        for url, content in fetched_contents.items():
            proxies = self.extract_all_proxies(content, url)
            if not proxies:
                failed_tracker.append((url, "PARSED_BUT_ZERO_PROXIES_FOUND"))
                failed_count += 1
                continue
            valid_batch_results.append((url, proxies))
            
        # 记录所有的失败追踪日志
        for url, reason in failed_tracker:
            if reason != "SKIP":
                self.save_failed_url(url, reason, failed_log)
                
        # 批量安全刷入磁盘
        if valid_batch_results:
            self._batch_save_proxies_to_disk(valid_batch_results, output_csv, output_json, output_links)
        
        self.dup_manager.save_processed_data()
        logger.info(f"🏁 自动化流水线并发作业圆满收官!")
        logger.info(f"  全局快报摘要 ──> 成功解析有效源: {len(valid_batch_results)}/{total_urls} | 阻塞或格式异常失效源: {failed_count}")

def main():
    INPUT_FILE = "urls.txt"
    OUTPUT_CSV = os.path.join(OUTPUT_DIR, "all_proxies.csv")
    OUTPUT_JSON = os.path.join(OUTPUT_DIR, "all_proxies.json")
    OUTPUT_LINKS = os.path.join(OUTPUT_DIR, "all_links.txt")
    FAILED_LOG = os.path.join(OUTPUT_DIR, "failed_urls.txt")
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    processor = YAMLConfigProcessor(
        timeout=20,
        retry_count=2,
        verify_ssl=False,        
        follow_redirects=True,    
        skip_processed_urls=True,
        max_workers=15  # 🛠️ 在这里调整并发抓取的线程数量，默认15并发
    )
    
    processor.process_urls(
        input_file=INPUT_FILE,
        output_csv=OUTPUT_CSV,
        output_json=OUTPUT_JSON,
        output_links=OUTPUT_LINKS,
        failed_log=FAILED_LOG
    )

if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists("urls.txt"):
        with open("urls.txt", "w", encoding="utf-8") as f:
            f.write("# 在此填入订阅源链接，每行一个\n")
        print("首次初始化完成！已在当前目录下创建 urls.txt。")
    else:
        main()
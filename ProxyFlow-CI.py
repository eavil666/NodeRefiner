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

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('url_processor.log', encoding='utf-8'),
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
        elif ptype in ['hysteria2', 'hy2', 'trojan', 'socks5', 'http']:
            data = f"{ptype}|{self.server}|{self.port}|{self.password}"
        elif ptype in ['tuic', 'anytls']:
            auth = self.uuid or self.password
            data = f"{ptype}|{self.server}|{self.port}|{auth}"
        elif ptype == 'ss':
            data = f"{self.type}|{self.server}|{self.port}|{self.password}|{self.cipher}"
        else:
            data = f"{self.type}|{self.server}|{self.port}|{self.uuid}|{self.password}"
        
        return hashlib.md5(data.encode('utf-8')).hexdigest()
    
    def to_share_link(self) -> str:
        """将自身属性转换为标准客户端一键导入分享链接"""
        ptype = self.type.lower()
        name_encoded = quote(self.name)
        
        if ptype in ['hysteria2', 'hy2']:
            params = {}
            if self.host: params['obfs'] = self.host  
            if self.sni: params['sni'] = self.sni
            query = '&'.join([f"{k}={quote(str(v))}" for k, v in params.items() if v])
            return f"hysteria2://{self.password}@{self.server}:{self.port}" + (f"?{query}" if query else "") + f"#{name_encoded}"
            
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
            auth = f"{self.uuid}:{self.password}@" if (self.uuid or self.password) else ""
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
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}

class DuplicateManager:
    """全局增量重复数据管理器"""
    def __init__(self, data_file: str = 'processed_proxies.json'):
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
    """YAML 配置文件处理器（内置自适应高智能 HTTP/HTTPS 探测获取算法）"""
    def __init__(self, timeout: int = 15, retry_count: int = 2, 
                 verify_ssl: bool = False, follow_redirects: bool = True,
                 skip_processed_urls: bool = True):
        self.timeout = timeout
        self.retry_count = retry_count
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.skip_processed_urls = skip_processed_urls
        
        self.dup_manager = DuplicateManager()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Connection': 'keep-alive'
        })
        adapter = requests.adapters.HTTPAdapter(pool_connections=15, pool_maxsize=15, max_retries=2)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        if not verify_ssl:
            self.session.verify = False
    
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
        
        proxy_indicators = ['type: vmess', 'type: vless', 'type: ss', 'type: trojan', 'type: wireguard', 'type: wg', 'type: hysteria2', 'type: hy2', 'type: tuic', 'type: anytls']
        return any(indicator in content.lower() for indicator in proxy_indicators)
    
    def get_config_from_url(self, url: str) -> Optional[str]:
        if self.skip_processed_urls and self.dup_manager.is_url_processed(url):
            logger.info(f"⏭️ 跳过历史已成功处理的URL: {url}")
            return None
        
        normalized_url = self.normalize_url(url)
        current_verify = self.verify_ssl
        backoff_delay = 1.5  
        
        for attempt in range(self.retry_count + 1):
            try:
                current_timeout = self.timeout if attempt > 0 else 5.0
                logger.info(f"🔍 [{attempt + 1}/{self.retry_count + 1}] 正在智能探测源: {normalized_url}")
                
                probe = self.session.head(
                    normalized_url, 
                    timeout=current_timeout,
                    allow_redirects=self.follow_redirects, 
                    verify=current_verify
                )
                
                if probe.status_code in [404, 410, 502, 504] and attempt == self.retry_count:
                    logger.warning(f"❌ 明确的死链状态码 ({probe.status_code})，停止处理")
                    return None
                
                if probe.status_code in [200, 301, 302, 307, 308]:
                    content_type = probe.headers.get('Content-Type', '').lower()
                    if 'text/html' in content_type:
                        logger.debug(f"⚠️ 探测到内容类型为 HTML，可能已被重定向到报错或人机验证页")

                response = self.session.get(
                    normalized_url, 
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects, 
                    verify=current_verify
                )
                
                if response.status_code == 200:
                    content = response.text
                    if self.is_yaml_content(content):
                        return content
                    
                    cleaned = self.clean_content(content)
                    if self.is_yaml_content(cleaned):
                        return cleaned
                    
                    logger.warning(f"⚠️ URL 响应成功但内容格式不属于有效的 Clash 配置")
                    return None  

            except requests.exceptions.SSLError as ssl_err:
                if current_verify:
                    logger.warning(f"🔒 捕获 HTTPS 证书安全错误，正在自动降级验证强度并重试... 错误: {ssl_err}")
                    current_verify = False
                    continue
            except requests.exceptions.Timeout:
                logger.warning(f"⏱️ 连接超时 (Timeout) 发生于第 {attempt + 1} 轮尝试")
            except requests.exceptions.RequestException as req_err:
                if normalized_url.startswith('https://'):
                    http_url = normalized_url.replace('https://', 'http://')
                    logger.info(f"🌐 HTTPS 握手失败，尝试平滑降级到纯 HTTP 协议: {http_url}")
                    normalized_url = http_url
                    continue
                logger.warning(f"🌐 网络传输或连接异常: {req_err}")
            
            if attempt < self.retry_count:
                actual_delay = backoff_delay * (1.5 ** attempt)
                logger.info(f"⏳ 触发动态退避机制，等待 {actual_delay:.1f} 秒后发起下一轮弹性重试...")
                time.sleep(actual_delay)
                
        logger.error(f"❌ 历经 {self.retry_count + 1} 轮智能探测后，依然无法成功提取配置: {url}")
        return None
    
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

    # ✨✨✨【核心新规：前置清洗熔断过滤器】✨✨✨
    def validate_and_clean_proxy_dict(self, proxy: dict, idx: int, source_url: str) -> Tuple[bool, Optional[dict]]:
        """
        在提取和组装 ProxyInfo 实体之前进行严格的语法与协议强校验。
        返回 (是否合格, 清洗纠正后的数据字典)
        """
        if not isinstance(proxy, dict):
            return False, None

        ptype = str(proxy.get('type', '')).strip().lower()
        server_addr = str(proxy.get('server', '') or proxy.get('ip', '')).strip()
        name_val = str(proxy.get('name', '')).strip()

        # 1. 必填骨架校验
        if not ptype or not server_addr or not name_val:
            logger.debug(f"⏭️ [源头熔断] 节点(索引:{idx}) 缺少 type, server 或 name 基本属性，予以丢弃。")
            return False, None

        # 2. 端口强合规校验
        try:
            port_val = int(proxy.get('port', 0))
            if port_val <= 0 or port_val > 65535:
                logger.warning(f"⚠️ [源头熔断] 节点 '{name_val}' 端口范围不合法: {port_val}，自动隔离。")
                return False, None
            proxy['port'] = port_val
        except:
            logger.warning(f"⚠️ [源头熔断] 节点 '{name_val}' 端口解析异常，自动隔离。")
            return False, None

        # 3. WireGuard (wg) 专属核心字段熔断与格式收敛
        if ptype in ['wireguard', 'wg']:
            # 兼容带有中划线和下划线的两种写法并收敛
            private_key = str(proxy.get('private-key', proxy.get('private_key', ''))).strip()
            if not private_key or private_key.lower() == "none":
                logger.warning(f"⚠️ [源头熔断] WG节点 '{name_val}' 缺失核心秘钥 private-key，阻止其进入测速流。")
                return False, None
            proxy['private-key'] = private_key # 确保统一使用中划线命名兼容Mihomo

            # 驯服局域网虚拟本端 IP (Clash规范中映射到 'ip' 字段且强校验必须为单字符串)
            ip_field = proxy.get('ip', '10.0.0.2')
            if isinstance(ip_field, list):
                if len(ip_field) > 0:
                    proxy['ip'] = str(ip_field[0]).strip()
                else:
                    proxy['ip'] = "10.0.0.2"
            else:
                proxy['ip'] = str(ip_field).strip()
            
            if not proxy['ip'] or proxy['ip'].lower() == "none":
                proxy['ip'] = "10.0.0.2"

        # 4. Vmess 专属核心字段 alterId 自动对齐强补全
        elif ptype == 'vmess':
            try:
                proxy['alterId'] = int(proxy.get('alterId', 0))
            except:
                proxy['alterId'] = 0

        # 5. 跨协议高危传输层字段 alpn 类型擦除与 Slice 级联对齐
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
            
            if processed_alpn:
                # 转换为标准 Clash/Mihomo 的多元素标量数组格式
                proxy['alpn'] = processed_alpn
            else:
                # 如果转换出来是脏数据列表，直接剔除，使其走内核握手缺省，防止断言闪退
                if 'alpn' in proxy: del proxy['alpn']

        # 6. 清理可能引起内核类型映射失败的空白字符串
        for uncompliant_key in ['sni', 'host', 'path']:
            if uncompliant_key in proxy and (proxy[uncompliant_key] == "" or proxy[uncompliant_key] is None):
                del proxy[uncompliant_key]

        return True, proxy
    
    def extract_all_proxies(self, config_content: str, source_url: str) -> List[ProxyInfo]:
        """从拉取的 YAML 配置中精准提取代理项（已集成前置强校验机制）"""
        all_proxies = []
        try:
            config_data = None
            try:
                config_data = yaml.safe_load(config_content)
            except yaml.YAMLError:
                cleaned = self.clean_yaml_content(config_content)
                try: config_data = yaml.safe_load(cleaned)
                except: pass
            
            if not config_data or 'proxies' not in config_data:
                return all_proxies
            
            proxies = config_data['proxies']
            if not isinstance(proxies, list): return all_proxies
            
            for idx, proxy in enumerate(proxies):
                try:
                    # ✨ [调用前置过滤器] 在这里拦截、清洗与熔断
                    is_pass, cleaned_proxy = self.validate_and_clean_proxy_dict(proxy, idx, source_url)
                    if not is_pass or not cleaned_proxy:
                        continue # 被安全隔离熔断，直接跳过处理下一个节点

                    ptype = cleaned_proxy['type'].lower()
                    server_addr = cleaned_proxy['server']
                    
                    # 局域网虚拟客户端 IP / Reserved 数据集数组处理
                    ip_field = cleaned_proxy.get('ip', '')
                    if isinstance(ip_field, list): ip_field = ",".join(ip_field)
                    reserved_field = cleaned_proxy.get('reserved', '')
                    if isinstance(reserved_field, list): reserved_field = ",".join(map(str, reserved_field))
                    
                    proxy_info = ProxyInfo(
                        name=cleaned_proxy['name'],
                        type=cleaned_proxy['type'],
                        server=server_addr,
                        port=cleaned_proxy['port'],
                        cipher=str(cleaned_proxy.get('cipher', '')),
                        password=str(cleaned_proxy.get('password', '')),
                        uuid=str(cleaned_proxy.get('uuid', '')),
                        network=str(cleaned_proxy.get('network', '')),
                        tls=bool(cleaned_proxy.get('tls', False)),
                        udp=bool(cleaned_proxy.get('udp', True)),
                        alterId=int(cleaned_proxy.get('alterId', 0)),
                        sni=str(cleaned_proxy.get('sni', '')),
                        host=ip_field if ptype in ['wireguard', 'wg'] else str(cleaned_proxy.get('host', '')),
                        path=str(cleaned_proxy.get('path', '')),
                        security=str(cleaned_proxy.get('security', '')),
                        scy=str(cleaned_proxy.get('scy', '')),
                        alpn=cleaned_proxy.get('alpn', ''), # 已在上面规范化为列表或彻底清除
                        skip_cert_verify=bool(cleaned_proxy.get('skip-cert-verify', False)),
                        source_url=source_url,
                        private_key=str(cleaned_proxy.get('private-key', '')),
                        public_key=str(cleaned_proxy.get('public-key', '')),
                        preshared_key=str(cleaned_proxy.get('preshared-key', '')),
                        reserved=str(reserved_field),
                        mtu=int(cleaned_proxy.get('mtu', 1420))
                    )
                    all_proxies.append(proxy_info)
                except Exception as e:
                    logger.error(f"构造代理实体发生细节异常: {e}, 略过损坏节点数据项")
            logger.info(f"节点映射成功 ── 成功安全转化 {len(all_proxies)} 个高规范可用节点实体")
        except Exception as e:
            logger.error(f"提取代理元数据数组发生阻断: {e}")
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
    
    def save_proxies_with_dedup(self, url: str, proxies: List[ProxyInfo], 
                               output_csv: str, output_json: str, output_links: str) -> Dict[str, int]:
        stats = {'total': len(proxies), 'new': 0, 'duplicate': 0, 'error': 0}
        new_proxies = []
        
        for proxy_info in proxies:
            try:
                is_duplicate, _ = self.dup_manager.is_proxy_duplicate(proxy_info)
                if is_duplicate:
                    stats['duplicate'] += 1
                    self.dup_manager.update_proxy_source(proxy_info.get_fingerprint(), url)
                else:
                    stats['new'] += 1
                    new_proxies.append(proxy_info)
                    self.dup_manager.add_processed_proxy(proxy_info)
            except Exception as e:
                stats['error'] += 1
                logger.error(f"分析去重运算错误: {proxy_info.name}, 细节: {e}")
        
        if new_proxies:
            self._save_proxies_to_csv(url, new_proxies, output_csv)
            self._save_proxies_to_json(url, new_proxies, output_json)
            self._save_proxies_to_links(new_proxies, output_links)
            
        self.dup_manager.add_processed_url(url)
        return stats
    
    def _save_proxies_to_csv(self, url: str, proxies: List[ProxyInfo], output_file: str):
        try:
            file_exists = os.path.exists(output_file) and os.path.getsize(output_file) > 0
            with open(output_file, 'a', encoding='utf-8-sig', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    header = ['来源URL', '名称', '类型', '服务器', '端口', '加密方式', 
                            '密码', 'UUID', '网络协议', 'TLS', 'UDP', '提取时间', '分享链接']
                    writer.writerow(header)
                
                for p in proxies:
                    writer.writerow([
                        url, p.name, p.type, p.server, str(p.port), p.cipher,
                        p.password, p.uuid, p.network, str(p.tls), str(p.udp),
                        time.strftime('%Y-%m-%d %H:%M:%S'), p.to_share_link()
                    ])
        except Exception as e:
            logger.error(f"增量写入保存 CSV 格式错误: {e}")
            
    def _save_proxies_to_json(self, url: str, proxies: List[ProxyInfo], output_file: str):
        try:
            all_data = []
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r', encoding='utf-8') as f:
                        all_data = json.load(f)
                except: pass
            
            for p in proxies:
                proxy_data = p.to_dict()
                proxy_data['fingerprint'] = p.get_fingerprint()
                proxy_data['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
                proxy_data['share_link'] = p.to_share_link()
                proxy_data['xray_config'] = p.to_xray_outbound()
                all_data.append(proxy_data)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(all_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"追加写入保存 JSON 数据模型错误: {e}")

    def _save_proxies_to_links(self, proxies: List[ProxyInfo], output_file: str):
        try:
            with open(output_file, 'a', encoding='utf-8') as f:
                for p in proxies:
                    f.write(f"{p.to_share_link()}\n")
        except Exception as e:
            logger.error(f"追加写入纯转换链接纯文本库错误: {e}")
            
    def save_failed_url(self, url: str, reason: str, failed_file: str):
        try:
            with open(failed_file, 'a', encoding='utf-8') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {url} | {reason}\n")
        except Exception as e:
            logger.error(f"记录异常追踪日志失败: {e}")
    
    def process_urls(self, input_file: str, output_csv: str = 'all_proxies.csv', 
                     output_json: str = 'all_proxies.json', output_links: str = 'all_links.txt',
                     failed_log: str = 'failed_urls.txt'):
        logger.info("⚡ 自动化多流智能节点采集与格式转换流水线正式启动...")
        urls = self.read_url_list(input_file)
        if not urls: return
        
        overall_stats = {'total_urls': len(urls), 'processed_urls': 0, 'failed_urls': 0, 'new_proxies': 0, 'duplicate_proxies': 0}
        
        for idx, url in enumerate(urls, 1):
            logger.info(f"⏳ 流水线当前进度 ── [{idx}/{len(urls)}] ── {url}")
            
            config_content = self.get_config_from_url(url)
            if not config_content:
                overall_stats['failed_urls'] += 1
                self.save_failed_url(url, "网络死链/协议不可连/内容格式不属于有效YAML", failed_log)
                continue
            
            proxies = self.extract_all_proxies(config_content, url)
            if not proxies:
                overall_stats['failed_urls'] += 1
                self.save_failed_url(url, "有效拉取成功，但该配置文件内部无 proxies 节点数组数据", failed_log)
                continue
            
            stats = self.save_proxies_with_dedup(url, proxies, output_csv, output_json, output_links)
            overall_stats['new_proxies'] += stats['new']
            overall_stats['duplicate_proxies'] += stats['duplicate']
            overall_stats['processed_urls'] += 1
            
            logger.info(f"✅ 单源处理圆满完成 ──> 发现新特征节点: {stats['new']} 个，历史重复已过滤: {stats['duplicate']} 个")
        
        self.dup_manager.save_processed_data()
        logger.info(f"🏁 自动化流水线作业圆满收官! 全局结算摘要:")
        logger.info(f"  成功收录订阅源: {overall_stats['processed_urls']}/{overall_stats['total_urls']} | 阻断不可用源: {overall_stats['failed_urls']}")
        logger.info(f"  全局累计产出新格式节点: {overall_stats['new_proxies']} 个 | 深度清洗过滤重复节点: {overall_stats['duplicate_proxies']} 个")

def main():
    INPUT_FILE = "urls.txt"
    OUTPUT_CSV = "all_proxies.csv"
    OUTPUT_JSON = "all_proxies.json"
    OUTPUT_LINKS = "all_links.txt"
    FAILED_LOG = "failed_urls.txt"
    
    processor = YAMLConfigProcessor(
        timeout=20,
        retry_count=2,
        verify_ssl=False,        
        follow_redirects=True,    
        skip_processed_urls=True  
    )
    
    processor.process_urls(
        input_file=INPUT_FILE,
        output_csv=OUTPUT_CSV,
        output_json=OUTPUT_JSON,
        output_links=OUTPUT_LINKS,
        failed_log=FAILED_LOG
    )

if __name__ == "__main__":
    if not os.path.exists("urls.txt"):
        with open("urls.txt", "w", encoding="utf-8") as f:
            f.write("# 在此填入订阅源链接，每行一个\n")
        print("首次初始化完成！已在当前目录下创建 urls.txt。")
    else:
        main()

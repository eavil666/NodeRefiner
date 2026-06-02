import subprocess
import time
import json
import os
import requests
import socket
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

OUTPUT_DIR = 'output'
LOG_DIR = 'logs'
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ⚙️ Linux 运行环境配置
MIHOMO_PATH = "./mihomo"
CONTROLLER_PORT = 9090
API_URL = f"http://127.0.0.1:{CONTROLLER_PORT}"

# ⚡ 并发性能配置
MAX_WORKERS = 60       # 同时下发测速的线程数（Actions 环境下建议 50-80）
TIMEOUT_MS = 2500      # 节点内核测速超时时间（2.5秒）
HTTP_TIMEOUT = 4       # Python 接口请求硬超时时间（略大于内核超时即可）

def is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    """用原生 Socket 检查指定端口是否已经开放监听"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((host, port))
        s.close()
        return True
    except:
        return False

def generate_temp_config(config_path: str = os.path.join(OUTPUT_DIR, "temp_mihomo_config.yaml")) -> bool:
    """读取 all_proxies.json 并生成用于测速的临时 YAML 配置文件"""
    input_json = os.path.join(OUTPUT_DIR, "all_proxies.json")
    if not os.path.exists(input_json):
        print("❌ 错误: 找不到全局纯净去重库 all_proxies.json，请确保前置抓取步骤已成功。")
        return False

    with open(input_json, "r", encoding="utf-8") as jf:
        try:
            json_proxies = json.load(jf)
        except Exception as e:
            print(f"❌ 错误: 解析 all_proxies.json 失败: {e}")
            return False
        
    proxies_to_load = []
    seen_names = {} 
    
    SUPPORTED_TYPES = {
        'ss', 'shadowsocks', 'snell', 'vmess', 'vless', 
        'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic', 
        'wireguard', 'wg', 'ssr', 'shadowsocksr', 'socks5', 'http'
    }
    VALID_SSR_OBFS = {'plain', 'http_simple', 'http_post', 'random_head', 'tls1.2_ticket_auth', 'tls1.2_ticket_fastauth'}

    for idx, p in enumerate(json_proxies):
        if not isinstance(p, dict):
            continue
            
        raw_name = str(p.get('name', '')).strip()
        ptype_lower = str(p.get('type', '')).strip().lower()
        
        if not raw_name or raw_name == "None" or raw_name == "":
            continue
            
        if ptype_lower not in SUPPORTED_TYPES:
            continue

        clean_proxy = {
            k: v for k, v in p.items() 
            if k not in ['fingerprint', 'timestamp', 'share_link', 'xray_config', 'source_urls', 'source_url']
        }
        
        clean_proxy['type'] = ptype_lower
        if ptype_lower == 'wg': clean_proxy['type'] = 'wireguard'
        if ptype_lower == 'hy2': clean_proxy['type'] = 'hysteria2'
        if ptype_lower == 'shadowsocks': clean_proxy['type'] = 'ss'
        if ptype_lower == 'shadowsocksr': clean_proxy['type'] = 'ssr'

        if raw_name not in seen_names:
            seen_names[raw_name] = 1
            clean_proxy['name'] = raw_name
        else:
            count = seen_names[raw_name]
            final_name = f"{raw_name}_dup{count}"
            seen_names[raw_name] += 1
            clean_proxy['name'] = final_name

        if 'skip_cert_verify' in clean_proxy:
            clean_proxy['skip-cert-verify'] = clean_proxy.pop('skip_cert_verify')
        if 'private_key' in clean_proxy:
            clean_proxy['private-key'] = clean_proxy.pop('private_key')
        if 'public_key' in clean_proxy:
            clean_proxy['public-key'] = clean_proxy.pop('public_key')
        if 'preshared_key' in clean_proxy:
            clean_proxy['preshared-key'] = clean_proxy.pop('preshared_key')
        if 'obfs_password' in clean_proxy:
            clean_proxy['obfs-password'] = clean_proxy.pop('obfs_password')

        is_corrupted = False
        
        if clean_proxy['type'] == 'ssr':
            ssr_obfs = str(clean_proxy.get('obfs', '')).strip().lower()
            if not ssr_obfs or ssr_obfs == 'none' or ssr_obfs not in VALID_SSR_OBFS:
                is_corrupted = True
            else:
                clean_proxy['obfs'] = ssr_obfs
            if not str(clean_proxy.get('protocol', '')).strip():
                clean_proxy['protocol'] = 'origin'

        elif clean_proxy['type'] == 'tuic':
            uuid_val = str(clean_proxy.get('uuid', clean_proxy.get('password', clean_proxy.get('token', '')))).strip()
            if not uuid_val or uuid_val == "None":
                is_corrupted = True
            else:
                clean_proxy['uuid'] = uuid_val
                if 'port' not in clean_proxy: clean_proxy['port'] = 443
            clean_proxy.pop('transport', None)
            clean_proxy.pop('username', None)

        elif clean_proxy['type'] in ['hysteria', 'hysteria2']:
            if not str(clean_proxy.get('password', '')).strip() or clean_proxy.get('password') == "None":
                is_corrupted = True

        elif clean_proxy['type'] in ['vmess', 'vless']:
            if not str(clean_proxy.get('uuid', '')).strip() or clean_proxy.get('uuid') == "None":
                is_corrupted = True

        elif clean_proxy['type'] == 'wireguard':
            if 'ip' not in clean_proxy or not str(clean_proxy['ip']).strip() or clean_proxy['ip'] == "None":
                if 'host' in clean_proxy and str(clean_proxy['host']).strip() and clean_proxy['host'] != "None":
                    clean_proxy['ip'] = clean_proxy['host']
                else:
                    clean_proxy['ip'] = "10.0.0.2"
            clean_proxy.pop('host', None)
            if not str(clean_proxy.get('private-key', '')).strip():
                is_corrupted = True

        if is_corrupted:
            continue

        if 'obfs' in clean_proxy and clean_proxy['type'] != 'ssr':
            obfs_type = str(clean_proxy['obfs']).strip().lower()
            if obfs_type and obfs_type != 'none':
                has_password = False
                if 'obfs-password' in clean_proxy and str(clean_proxy['obfs-password']).strip():
                    has_password = True
                elif isinstance(clean_proxy.get('plugin-opts'), dict) and str(clean_proxy['plugin-opts'].get('password', '')).strip():
                    has_password = True
                if not has_password:
                    clean_proxy.pop('obfs', None)
                    clean_proxy.pop('obfs-password', None)

        if 'alpn' in clean_proxy and clean_proxy['alpn']:
            raw_alpn = clean_proxy['alpn']
            final_alpn = []
            if isinstance(raw_alpn, list):
                final_alpn = [str(x).strip() for x in raw_alpn if x]
            elif isinstance(raw_alpn, str):
                if ',' in raw_alpn:
                    final_alpn = [x.strip() for x in raw_alpn.split(',') if x.strip()]
                else:
                    final_alpn = [raw_alpn.strip()]
            if final_alpn:
                clean_proxy['alpn'] = final_alpn
            else:
                clean_proxy.pop('alpn', None)
        else:
            clean_proxy.pop('alpn', None)

        proxies_to_load.append(clean_proxy)

    if not proxies_to_load:
        print("⚠️ 警告: 过滤后无任何有效代理节点，跳过本次测速。")
        return False

    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": f"127.0.0.1:{CONTROLLER_PORT}",
        "secret": "",        
        "proxies": proxies_to_load,
        "proxy-groups": [
            {
                "name": "测速分组", 
                "type": "select", 
                "proxies": [p["name"] for p in proxies_to_load]
            }
        ]
    }

    import yaml
    with open(config_path, "w", encoding="utf-8") as wf:
        yaml.dump(config, wf, allow_unicode=True, sort_keys=False)
    
    print(f"📊 测速配置文件组装完毕，共成功重命名冲突并载入 {len(proxies_to_load)} 个合规节点。")
    return True

def test_single_proxy(name, test_url):
    """【并发工作子单元】请求单节点测速 API 接口并返回延迟结果"""
    encoded_name = quote(name)
    test_api = f"{API_URL}/proxies/{encoded_name}/delay?url={quote(test_url)}&timeout={TIMEOUT_MS}"
    try:
        res = requests.get(test_api, timeout=HTTP_TIMEOUT)
        if res.status_code == 200:
            delay = res.json().get("delay", -1)
            if delay > 0:
                return name, delay
    except:
        pass
    return name, -1

def run_speedtest():
    config_file = os.path.join(OUTPUT_DIR, "temp_mihomo_config.yaml")
    if not generate_temp_config(config_file):
        return

    os.makedirs("clash_dummy", exist_ok=True)
    with open("clash_dummy/Country.mmdb", "w") as f:
        f.write("") 

    print("🚀 正在拉起后台 Mihomo 内核进程...")
    process = None
    kernel_log = os.path.join(LOG_DIR, "mihomo_kernel.log")
    try:
        log_file = open(kernel_log, "w")
        process = subprocess.Popen(
            [MIHOMO_PATH, "-f", config_file, "-d", "./clash_dummy"],
            stdout=log_file,
            stderr=log_file
        )

        print("⏳ 正在等待 Mihomo 外部控制器 (API) 端口开放...")
        api_ready = False
        for i in range(15):
            if is_port_open(CONTROLLER_PORT):
                print(f"✅ Mihomo API 外部控制接口已在第 {i+1} 秒成功激活！")
                api_ready = True
                break
            time.sleep(1)
            
        if not api_ready:
            print("❌ 严重错误: Mihomo 内核在 15 秒内未能成功监听 9090 端口！")
            if os.path.exists(kernel_log):
                print("\n📋 ─── 以下为 Mihomo 内核崩溃追踪日志 ───")
                with open(kernel_log, "r") as lf:
                    print(lf.read())
            return
        
        print("⚡ 正在获取全量测速节点清单...")
        try:
            proxies_res = requests.get(f"{API_URL}/proxies", timeout=5).json()
        except Exception as e:
            print(f"❌ 通信异常，无法连接到本地内核 API: {e}")
            return
        
        proxies_dict = proxies_res.get("proxies", {})
        test_url = "http://www.gstatic.com/generate_204"
        
        # 筛选出需要进行网络测试的有效代理节点
        node_names = [
            name for name, info in proxies_dict.items()
            if info.get("type") not in ["Selector", "URLTest", "Fallback", "LoadBalance", "Direct", "Reject"]
        ]
        
        total_nodes = len(node_names)
        print(f"⚡ 开始多线程并发测速，并发规模: {MAX_WORKERS}，节点总数: {total_nodes} ...")
        
        valid_delays = {}
        start_time = time.time()
        
        # ✨【高能优化核心】：启用线程池进行高并发请求下发
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # 建立未来任务映射
            future_to_node = {executor.submit(test_single_proxy, name, test_url): name for name in node_names}
            
            completed_count = 0
            for future in as_completed(future_to_node):
                name, delay = future.result()
                completed_count += 1
                
                if delay > 0:
                    valid_delays[name] = delay
                    print(f"  [{completed_count}/{total_nodes}] ✅ [可用] {name} ── {delay}ms")
                else:
                    # 减少标准 Actions 打印日志噪音，死节点仅计数，不轰炸控制台
                    if completed_count % 50 == 0 or completed_count == total_nodes:
                        print(f"  进度通知: 已完成 {completed_count}/{total_nodes} 个节点的连通性初筛...")

        elapsed_time = time.time() - start_time
        print(f"⏱️ 并发测速洗白完成！耗时: {elapsed_time:.2f} 秒。成功命中可用节点: {len(valid_delays)} 个")

        # 映射链接回填
        valid_nodes = []
        link_mapping = {}
        input_json = os.path.join(OUTPUT_DIR, "all_proxies.json")
        if os.path.exists(input_json):
            with open(input_json, "r", encoding="utf-8") as jf:
                for item in json.load(jf):
                    if isinstance(item, dict) and 'name' in item:
                        link_mapping[item['name']] = item.get('share_link', '')

        for name in valid_delays.keys():
            lookup_name = name.split('_dup')[0]
            share_link = link_mapping.get(lookup_name, link_mapping.get(name, ''))
            if share_link:
                valid_nodes.append(share_link)
        
        output_file = os.path.join(OUTPUT_DIR, "valid_links.txt")
        with open(output_file, "w", encoding="utf-8") as wf:
            wf.write("# 🌐 通过 GitHub Actions 自动化初筛的高可用代理列表\n")
            wf.write(f"# 🕒 更新时间: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")
            for link in valid_nodes:
                wf.write(f"{link}\n")
                
        print(f"\n🎉 筛选完成！已将 {len(valid_nodes)} 个高响应节点写入 {output_file}")
            
    except Exception as e:
        print(f"💥 运行期间发生未预期的脚本错误: {e}")
    finally:
        if process:
            print("🧹 正在清理，主动终结后台内核进程...")
            process.terminate()
            process.wait()
        if os.path.exists(config_file):
            os.remove(config_file)
        if os.path.exists(kernel_log):
            try: log_file.close()
            except: pass
            os.remove(kernel_log)

if __name__ == "__main__":
    run_speedtest()

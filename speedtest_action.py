import subprocess
import time
import json
import os
import requests
import socket
from urllib.parse import quote

# ⚙️ Linux 运行环境配置
MIHOMO_PATH = "./mihomo"
CONTROLLER_PORT = 9090
API_URL = f"http://127.0.0.1:{CONTROLLER_PORT}"

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

def generate_temp_config(config_path: str = "temp_mihomo_config.yaml") -> bool:
    """读取 all_proxies.json 并生成用于测速的临时 YAML 配置文件"""
    if not os.path.exists("all_proxies.json"):
        print("❌ 错误: 找不到全局纯净去重库 all_proxies.json，请确保前置抓取步骤已成功。")
        return False

    with open("all_proxies.json", "r", encoding="utf-8") as jf:
        try:
            json_proxies = json.load(jf)
        except Exception as e:
            print(f"❌ 错误: 解析 all_proxies.json 失败: {e}")
            return False
        
    proxies_to_load = []
    
    # 支持的标准内核协议白名单
    SUPPORTED_TYPES = {
        'ss', 'shadowsocks', 'snell', 'vmess', 'vless', 
        'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic', 
        'wireguard', 'wg', 'ssr', 'shadowsocksr', 'socks5', 'http'
    }

    for idx, p in enumerate(json_proxies):
        if not isinstance(p, dict):
            continue
            
        # 0. 严格阻断无名或残缺幽灵节点
        node_name = str(p.get('name', '')).strip()
        ptype_lower = str(p.get('type', '')).strip().lower()
        
        if not node_name or node_name == "None" or node_name == "":
            continue
            
        # ✨【核心防御 1】：非白名单标准协议，直接拦截，防止不认识的空协议让内核崩溃
        if ptype_lower not in SUPPORTED_TYPES:
            continue

        # 提取纯净的核心代理属性
        clean_proxy = {
            k: v for k, v in p.items() 
            if k not in ['fingerprint', 'timestamp', 'share_link', 'xray_config', 'source_urls', 'source_url']
        }
        
        # 修复规范化协议名称
        clean_proxy['type'] = ptype_lower
        if ptype_lower == 'wg': clean_proxy['type'] = 'wireguard'
        if ptype_lower == 'hy2': clean_proxy['type'] = 'hysteria2'
        if ptype_lower == 'shadowsocks': clean_proxy['type'] = 'ss'

        # 1. 字段名称平滑映射 (下划线转中划线)
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

        # 2. ✨【核心防御 2】：针对各协议鉴权和传输残缺字段进行毁灭性熔断检查
        is_corrupted = False
        
        # 针对 TUIC 协议的防闪退彻底净化
        if clean_proxy['type'] == 'tuic':
            # 获取凭证，tuic 核心必须要有 token/password/uuid 之一
            uuid_val = str(clean_proxy.get('uuid', clean_proxy.get('password', clean_proxy.get('token', '')))).strip()
            if not uuid_val or uuid_val == "None":
                is_corrupted = True # 缺凭证，标记损坏
            else:
                clean_proxy['uuid'] = uuid_val
                # 显式补全 TUIC 所需的核心空缺默认字段，防止报 unset fields
                if 'port' not in clean_proxy: clean_proxy['port'] = 443
                
            # 彻底拔除干扰内核自动推导 transport 的多余残缺字段
            clean_proxy.pop('transport', None)
            clean_proxy.pop('username', None)

        # 针对 Hysteria / Hysteria2 协议的防闪退净化
        elif clean_proxy['type'] in ['hysteria', 'hysteria2']:
            if not str(clean_proxy.get('password', '')).strip() or clean_proxy.get('password') == "None":
                is_corrupted = True

        # 针对 Vmess / Vless 协议的防闪退净化
        elif clean_proxy['type'] in ['vmess', 'vless']:
            if not str(clean_proxy.get('uuid', '')).strip() or clean_proxy.get('uuid') == "None":
                is_corrupted = True

        # 针对 WireGuard 补全本地地址
        elif clean_proxy['type'] == 'wireguard':
            if 'ip' not in clean_proxy or not str(clean_proxy['ip']).strip() or clean_proxy['ip'] == "None":
                if 'host' in clean_proxy and str(clean_proxy['host']).strip() and clean_proxy['host'] != "None":
                    clean_proxy['ip'] = clean_proxy['host']
                else:
                    clean_proxy['ip'] = "10.0.0.2"
            clean_proxy.pop('host', None)
            if not str(clean_proxy.get('private-key', '')).strip():
                is_corrupted = True

        # 如果节点在上面被检测出关键认证字段不齐，直接丢弃，不载入测速
        if is_corrupted:
            continue

        # 3. 混淆(obfs)字段净化
        if 'obfs' in clean_proxy:
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

        # 4. 彻底驯服 alpn 属性
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
        print("⚠️ 警告: 经过协议指纹过滤后无任何有效代理节点，跳过本次测速。")
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
    
    print(f"📊 测速配置文件组装完毕，共过滤并成功载入 {len(proxies_to_load)} 个绝对合规的代理节点。")
    return True

def run_speedtest():
    config_file = "temp_mihomo_config.yaml"
    if not generate_temp_config(config_file):
        return

    os.makedirs("clash_dummy", exist_ok=True)
    with open("clash_dummy/Country.mmdb", "w") as f:
        f.write("") 

    print("🚀 正在拉起后台 Mihomo 内核进程...")
    process = None
    try:
        log_file = open("mihomo_kernel.log", "w")
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
            if os.path.exists("mihomo_kernel.log"):
                print("\n📋 ─── 以下为 Mihomo 内核崩溃追踪日志 ───")
                with open("mihomo_kernel.log", "r") as lf:
                    print(lf.read())
            return
        
        print("⚡ 正在下发并行测速指令...")
        try:
            proxies_res = requests.get(f"{API_URL}/proxies", timeout=5).json()
        except Exception as e:
            print(f"❌ 通信异常，无法连接到本地内核 API: {e}")
            return
        
        proxies_dict = proxies_res.get("proxies", {})
        test_url = "http://www.gstatic.com/generate_204"
        timeout_ms = 3000
        
        valid_nodes = []
        link_mapping = {}
        if os.path.exists("all_proxies.json"):
            with open("all_proxies.json", "r", encoding="utf-8") as jf:
                for item in json.load(jf):
                    if isinstance(item, dict) and 'name' in item:
                        link_mapping[item['name']] = item.get('share_link', '')

        for name, info in proxies_dict.items():
            if info.get("type") in ["Selector", "URLTest", "Fallback", "LoadBalance", "Direct", "Reject"]:
                continue
                
            encoded_name = quote(name)
            test_api = f"{API_URL}/proxies/{encoded_name}/delay?url={quote(test_url)}&timeout={timeout_ms}"
            
            try:
                res = requests.get(test_api, timeout=4)
                if res.status_code == 200:
                    delay = res.json().get("delay", -1)
                    if delay > 0:
                        print(f"  ✅ [可用] {name} ── {delay}ms")
                        share_link = link_mapping.get(name)
                        if share_link:
                            valid_nodes.append(share_link)
                else:
                    print(f"  ❌ [不可用/超时] {name}")
            except:
                print(f"  ❌ [物理连接异常] {name}")
        
        output_file = "valid_links.txt"
        with open(output_file, "w", encoding="utf-8") as wf:
            wf.write("# 🌐 通过 GitHub Actions 自动化初筛的高可用代理列表\n")
            wf.write(f"# 🕒 更新时间: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")
            for link in valid_nodes:
                wf.write(f"{link}\n")
                
        print(f"\n🎉 筛选完成！总计有效节点: {len(valid_nodes)} 个，已写入 {output_file}")
            
    except Exception as e:
        print(f"💥 运行期间发生未预期的脚本错误: {e}")
    finally:
        if process:
            print("🧹 正在清理，主动终结后台内核进程...")
            process.terminate()
            process.wait()
        if os.path.exists(config_file):
            os.remove(config_file)
        if os.path.exists("mihomo_kernel.log"):
            try: log_file.close() 
            except: pass
            os.remove("mihomo_kernel.log")

if __name__ == "__main__":
    run_speedtest()

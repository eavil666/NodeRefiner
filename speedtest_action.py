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
    for idx, p in enumerate(json_proxies):
        if not isinstance(p, dict):
            continue
            
        # 0. 严格阻断无名或残缺幽灵节点
        node_name = str(p.get('name', '')).strip()
        if not node_name or node_name == "None":
            continue

        # 提取纯净的核心代理属性
        clean_proxy = {
            k: v for k, v in p.items() 
            if k not in ['fingerprint', 'timestamp', 'share_link', 'xray_config', 'source_urls', 'source_url']
        }
        
        # 1. 字段名称平滑映射 (下划线转中划线)
        if 'skip_cert_verify' in clean_proxy:
            clean_proxy['skip-cert-verify'] = clean_proxy.pop('skip_cert_verify')
        if 'private_key' in clean_proxy:
            clean_proxy['private-key'] = clean_proxy.pop('private_key')
        if 'public_key' in clean_proxy:
            clean_proxy['public-key'] = clean_proxy.pop('public_key')
        if 'preshared_key' in clean_proxy:
            clean_proxy['preshared-key'] = clean_proxy.pop('preshared_key')

        # 2. 协议特异性强补全与逻辑防御
        ptype_lower = str(clean_proxy.get('type', '')).lower()
        
        # 针对 WireGuard 补全本地地址 (ip 字段)
        if ptype_lower in ['wireguard', 'wg']:
            if 'ip' not in clean_proxy or not str(clean_proxy['ip']).strip() or clean_proxy['ip'] == "None":
                if 'host' in clean_proxy and str(clean_proxy['host']).strip() and clean_proxy['host'] != "None":
                    clean_proxy['ip'] = clean_proxy['host']
                else:
                    clean_proxy['ip'] = "10.0.0.2"
            clean_proxy.pop('host', None)

        # ✨【针对本次报错的防御】：补全 TUIC 协议可能触发的凭证或传输层解析缺陷
        elif ptype_lower == 'tuic':
            # Mihomo 的 tuic 核心字段包含：uuid/password (二选一)
            if 'uuid' not in clean_proxy and 'password' in clean_proxy:
                clean_proxy['uuid'] = clean_proxy['password'] # 相互对齐做兼容
            # 如果配置里带有一些多余的不规范字段干扰了内核对 transport 的自动推导，给予移除
            clean_proxy.pop('transport', None)

        # 3. 彻底驯服 alpn 属性
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
        print("⚠️ 警告: 过滤后无有效代理节点，跳过本次测速。")
        return False

    # 组装完整的 Clash/Mihomo 基础配置字典
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
    
    print(f"📊 测速配置文件组装完毕，共载入 {len(proxies_to_load)} 个绝对合规的代理节点。")
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
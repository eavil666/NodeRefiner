import subprocess
import time
import json
import os
import requests
import socket
from urllib.parse import quote

# ⚙️ Linux 环境配置
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

def generate_temp_config(config_path: str = "temp_mihomo_config.yaml"):
    """读取 processor1.py 生成的 all_proxies.json，构建临时 Clash 配置文件"""
    if not os.path.exists("all_proxies.json"):
        print("❌ 错误: 找不到 all_proxies.json，请检查前置采集步骤是否成功。")
        return False

    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": f"127.0.0.1:{CONTROLLER_PORT}",
        "secret": "",        
        "proxies": []
    }

    with open("all_proxies.json", "r", encoding="utf-8") as jf:
        json_proxies = json.load(jf)
        for idx, p in enumerate(json_proxies):
            # 1. ✨【核心修复】严格校验代理端口合法性，防止 invalid port 导致内核闪退
            try:
                port_val = int(p.get('port', 0))
                if port_val <= 0 or port_val > 65535:
                    print(f"⚠️ 熔断过滤: 节点 [{idx}] '{p.get('name', 'Unknown')}' 端口为非法值 ({port_val})，已自动剔除。")
                    continue
            except (ValueError, TypeError):
                print(f"⚠️ 熔断过滤: 节点 [{idx}] '{p.get('name', 'Unknown')}' 端口类型异常，已自动剔除。")
                continue

            # 过滤掉非内核的原生辅助字段
            clean_proxy = {k: v for k, v in p.items() if k not in ['fingerprint', 'timestamp', 'share_link', 'xray_config', 'source_urls']}
            
            # 2. 将 alpn 从字符串平滑转换为 Mihomo 要求的 Slice (列表) 格式
            if 'alpn' in clean_proxy and clean_proxy['alpn']:
                alpn_val = clean_proxy['alpn']
                if isinstance(alpn_val, str):
                    if ',' in alpn_val:
                        clean_proxy['alpn'] = [item.strip() for item in alpn_val.split(',') if item.strip()]
                    else:
                        clean_proxy['alpn'] = [alpn_val.strip()]
                elif isinstance(alpn_val, list):
                    pass
                else:
                    del clean_proxy['alpn']
            
            # 3. 兼容性清洗：如果含有空字符串的 alpn、sni 等，直接移除该键，走内核默认缺省值
            for optional_key in ['alpn', 'sni', 'host', 'path']:
                if optional_key in clean_proxy and (clean_proxy[optional_key] == "" or clean_proxy[optional_key] is None):
                    del clean_proxy[optional_key]

            config["proxies"].append(clean_proxy)

    # 兜底防御：防止 proxies 数组为空导致内核启动失败
    if not config["proxies"]:
        print("⚠️ 警告: 过滤后有效 proxies 数组为空，跳过本次测速流程。")
        return False

    config["proxy-groups"] = [
        {"name": "测速分组", "type": "select", "proxies": [p["name"] for p in config["proxies"]]}
    ]

    import yaml
    with open(config_path, "w", encoding="utf-8") as wf:
        yaml.dump(config, wf, allow_unicode=True, sort_keys=False)
    
    print(f"📊 临时配置文件构建成功，共载入 {len(config['proxies'])} 个规范化节点进行筛选。")
    return True

def run_speedtest():
    config_file = "temp_mihomo_config.yaml"
    if not generate_temp_config(config_file):
        return

    # 创建虚拟工作目录绕过 GeoIP 强校验
    os.makedirs("clash_dummy", exist_ok=True)
    with open("clash_dummy/Country.mmdb", "w") as f:
        f.write("") 

    print("🚀 正在启动后台 Mihomo 内核进程...")
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
                print(f"✅ Mihomo API 端口已成功在第 {i+1} 秒激活！")
                api_ready = True
                break
            time.sleep(1)
            
        if not api_ready:
            print("❌ 严重错误: Mihomo 内核在 15 秒内未能成功监听 9090 端口！")
            if os.path.exists("mihomo_kernel.log"):
                print("\n📋 ─── 以下为 Mihomo 内核崩溃日志 ───")
                with open("mihomo_kernel.log", "r") as lf:
                    print(lf.read())
            return
        
        print("⚡ 开始发送高并发延迟测试指令...")
        try:
            proxies_res = requests.get(f"{API_URL}/proxies", timeout=5).json()
        except Exception as e:
            print(f"❌ 连接到 API 失败: {e}")
            return
        
        proxies_dict = proxies_res.get("proxies", {})
        test_url = "http://www.gstatic.com/generate_204"
        timeout_ms = 3000
        
        valid_nodes = []
        link_mapping = {}
        if os.path.exists("all_proxies.json"):
            with open("all_proxies.json", "r", encoding="utf-8") as jf:
                for item in json.load(jf):
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
                print(f"  ❌ [连接异常] {name}")
        
        output_file = "valid_links.txt"
        with open(output_file, "w", encoding="utf-8") as wf:
            wf.write("# 🌐 通过 GitHub Actions 自动化初筛的高可用代理列表\n")
            wf.write(f"# 🕒 更新时间: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")
            for link in valid_nodes:
                wf.write(f"{link}\n")
                
        print(f"\n🎉 筛选完成！总计有效节点: {len(valid_nodes)} 个，已写入 {output_file}")
            
    except Exception as e:
        print(f"💥 运行期间发生严重错误: {e}")
    finally:
        if process:
            print("🧹 正在清理，关闭后台进程...")
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

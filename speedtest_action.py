import subprocess
import time
import json
import os
import requests
from urllib.parse import quote

# ⚙️ Linux 环境配置
MIHOMO_PATH = "./mihomo"  # 👈 Actions 中解压后的 Linux 执行文件名
CONTROLLER_PORT = 9090
API_URL = f"http://127.0.0.1:{CONTROLLER_PORT}"

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
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{CONTROLLER_PORT}",
        "proxies": []
    }

    with open("all_proxies.json", "r", encoding="utf-8") as jf:
        json_proxies = json.load(jf)
        for p in json_proxies:
            # 清洗字典，只保留 mihomo 原生支持的字段
            clean_proxy = {k: v for k, v in p.items() if k not in ['fingerprint', 'timestamp', 'share_link', 'xray_config', 'source_urls']}
            config["proxies"].append(clean_proxy)

    config["proxy-groups"] = [
        {"name": "测速分组", "type": "select", "proxies": [p["name"] for p in config["proxies"]]}
    ]

    import yaml
    with open(config_path, "w", encoding="utf-8") as wf:
        yaml.dump(config, wf, allow_unicode=True, sort_keys=False)
    
    print(f"📊 临时配置文件构建成功，共载入 {len(config['proxies'])} 个节点进行筛选。")
    return True

def run_speedtest():
    config_file = "temp_mihomo_config.yaml"
    if not generate_temp_config(config_file):
        return

    print("🚀 正在启动后台 Mihomo 内核进程...")
    process = None
    try:
        # 在 Linux 平台下安全启动进程
        process = subprocess.Popen(
            [MIHOMO_PATH, "-f", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(3)  # 给内核留足启动时间
        
        print("⚡ 开始发送高并发延迟测试指令...")
        try:
            proxies_res = requests.get(f"{API_URL}/proxies", timeout=5).json()
        except Exception as e:
            print(f"❌ 无法连接到 Mihomo API: {e}")
            return
        
        proxies_dict = proxies_res.get("proxies", {})
        test_url = "http://www.gstatic.com/generate_204"
        timeout_ms = 3000  # 超过 3 秒视为死节点
        
        valid_nodes = []
        
        # 建立一个快速查找原始分享链接的映射表
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
        
        # 💾 将真正有效的、测试通畅的节点写入单独的文件
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

if __name__ == "__main__":
    run_speedtest()
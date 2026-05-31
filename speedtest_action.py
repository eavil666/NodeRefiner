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
    """用原生 Socket 检查指定端口是否已经开放监听，不依赖第三方库"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((host, port))
        s.close()
        return True
    except:
        return False

def generate_temp_config(config_path: str = "temp_mihomo_config.yaml") -> bool:
    """直接读取纯净的 all_proxies.json，组装成临时 Mihomo 配置文件"""
    if not os.path.exists("all_proxies.json"):
        print("❌ 错误: 找不到全局纯净去重库 all_proxies.json，请确保前置抓取步骤已成功。")
        return False

    with open("all_proxies.json", "r", encoding="utf-8") as jf:
        json_proxies = json.load(jf)
        
    proxies_to_load = []
    for p in json_proxies:
        # 移除仅用于前置流程或通知的辅助字段，避免干扰 Mihomo 静态解析
        clean_proxy = {
            k: v for k, v in p.items() 
            if k not in ['fingerprint', 'timestamp', 'share_link', 'xray_config', 'source_urls', 'source_url']
        }
        
        # 针对 Clash/Mihomo 的特殊通用布尔或中划线字段做一层键名平滑映射
        if 'skip_cert_verify' in clean_proxy:
            clean_proxy['skip-cert-verify'] = clean_proxy.pop('skip_cert_verify')
        if 'private_key' in clean_proxy:
            clean_proxy['private-key'] = clean_proxy.pop('private_key')
        if 'public_key' in clean_proxy:
            clean_proxy['public-key'] = clean_proxy.pop('public_key')
        if 'preshared_key' in clean_proxy:
            clean_proxy['preshared-key'] = clean_proxy.pop('preshared_key')

        proxies_to_load.append(clean_proxy)

    if not proxies_to_load:
        print("⚠️ 警告: all_proxies.json 中没有任何可用代理项，跳过本次测速。")
        return False

    # 组装纯净核心配置外壳
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
    
    print(f"📊 测速配置文件构建成功，共无损载入 {len(proxies_to_load)} 个经前置清洗的高规节点。")
    return True

def run_speedtest():
    config_file = "temp_mihomo_config.yaml"
    if not generate_temp_config(config_file):
        return

    # 1. 自动生成虚拟工作目录与占位符文件，完美绕过内核强校验
    os.makedirs("clash_dummy", exist_ok=True)
    with open("clash_dummy/Country.mmdb", "w") as f:
        f.write("") 

    print("🚀 正在异步拉起后台 Mihomo 内核进程...")
    process = None
    try:
        log_file = open("mihomo_kernel.log", "w")
        process = subprocess.Popen(
            [MIHOMO_PATH, "-f", config_file, "-d", "./clash_dummy"],
            stdout=log_file,
            stderr=log_file
        )
        
        # 2. 控制器监听状态弹性探测
        print("⏳ 正在等待 Mihomo 外部控制器 (API) 端口开放...")
        api_ready = False
        for i in range(15):
            if is_port_open(CONTROLLER_PORT):
                print(f"✅ Mihomo API 外部控制接口已在第 {i+1} 秒成功激活！")
                api_ready = True
                break
            time.sleep(1)
            
        if not api_ready:
            print("❌ 严重错误: Mihomo 内核在 15 秒内启动异常，未成功监听 9090 端口！")
            if os.path.exists("mihomo_kernel.log"):
                print("\n📋 ─── 以下为 Mihomo 内核崩溃追踪日志 ───")
                with open("mihomo_kernel.log", "r") as lf:
                    print(lf.read())
            return
        
        # 3. 通过内置外部控制 API 发起并行延迟测速
        print("⚡ 正在向内核下发批量并发测试指令 (并发模型由 Go 内核底层驱动)...")
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
                    link_mapping[item['name']] = item.get('share_link', '')

        # 遍历测速
        for name, info in proxies_dict.items():
            # 过滤策略组以及内置无意义节点
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
        
        # 4. 将筛选结果生成高价值产物并持久化
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
        # 5. 优雅回收资源，确保不留下孤儿后台进程
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

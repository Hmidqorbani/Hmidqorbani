import base64
import json
import re
from urllib.parse import urlparse

import requests


# ----- توابع کمکی برای اعتبارسنجی (از کد خودت) -----
def is_valid_ipv4(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        if not (0 <= int(p) <= 255):
            return False
    return True


def is_valid_ipv6(ip):
    ip = ip.strip("[]")
    try:
        import ipaddress

        ipaddress.IPv6Address(ip)
        return True
    except:
        return False


def is_valid_domain(host):
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    return re.match(pattern, host) is not None and "." in host


# ----- تابع استخراج (host, port) از هر خط (همون کد خودت) -----
def extract_host_port(line):
    line = line.strip()
    if not line:
        return None

    host = None
    port = None

    # 1. vmess://
    if line.startswith("vmess://"):
        try:
            b64 = line[8:]
            b64 += "=" * (4 - len(b64) % 4) if len(b64) % 4 else ""
            decoded = base64.b64decode(b64).decode("utf-8")
            data = json.loads(decoded)
            host = data.get("add") or data.get("host")
            port = data.get("port")
            if host and port:
                port = int(port)
                return (host, port)
        except:
            pass

    # 2. ssr://
    if line.startswith("ssr://"):
        try:
            b64 = line[6:]
            b64 += "=" * (4 - len(b64) % 4) if len(b64) % 4 else ""
            decoded = base64.b64decode(b64).decode("utf-8")
            parts = decoded.split(":")
            if len(parts) >= 2:
                host = parts[0]
                port = int(parts[1])
                return (host, port)
        except:
            pass

    # 3. URIهای استاندارد (vless, trojan, http, socks, ...)
    if "://" in line:
        try:
            parsed = urlparse(line)
            host = parsed.hostname
            port = parsed.port
            if host:
                return (host, port)
        except:
            pass

    # 4. حالت ساده مثل "1.2.3.4:8080" یا "example.com:443"
    match = re.search(r"([a-zA-Z0-9\.\-:]+)(?::(\d+))?", line)
    if match:
        potential_host = match.group(1)
        potential_port = match.group(2)
        if (
            is_valid_ipv4(potential_host)
            or is_valid_ipv6(potential_host)
            or is_valid_domain(potential_host)
        ):
            host = potential_host
            port = int(potential_port) if potential_port else None
            return (host, port)

    return None


# ----- دریافت از مخزن‌ها و استخراج کانفیگ‌ها -----
def fetch_configs(urls):
    all_lines = []
    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            content = response.text

            # تشخیص Base64
            if re.match(r"^[A-Za-z0-9+/=]+$", content.strip()):
                try:
                    decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
                    content = decoded
                except:
                    pass

            # ذخیره تمام خطوط غیرخالی
            for line in content.splitlines():
                line = line.strip()
                if line:
                    all_lines.append(line)
            print(f"✅ دریافت {len(content.splitlines())} خط از {url}")
        except Exception as e:
            print(f"❌ خطا در دریافت {url}: {e}")
    return all_lines


# ----- حذف تکراری‌ها بر اساس host:port (با استفاده از extract_host_port) -----
def remove_duplicates(lines):
    seen = set()
    result = []
    removed = 0
    no_key = 0

    for line in lines:
        extracted = extract_host_port(line)
        if extracted is None:
            # خطی که قابل تشخیص نیست رو نگه می‌داریم (مثل کامنت)
            result.append(line)
            no_key += 1
            continue

        host, port = extracted
        key = (host, port) if port is not None else (host, None)

        if key in seen:
            removed += 1
            print(f"🗑️ حذف تکراری: {host}:{port if port else 'نامشخص'}")
        else:
            seen.add(key)
            result.append(line)

    return result, removed, no_key


# ----- تابع اصلی -----
def main():
    # لیست مخزن‌ها
    urls = [
        "https://shadowmere.xyz/api/b64sub/",
        "https://github.com/iampedii/whitedns-sub/raw/refs/heads/main/base64.txt",
        "https://raw.githubusercontent.com/luxxuria/harvester/main/speed_tested.txt",
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
        "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs_tested.txt",
        "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
        "https://raw.githubusercontent.com/paranoideveloper/CoreForge-Sub/main/subscription_base64.txt",
        "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/sub.txt",
        "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    ]

    print("🔄 در حال دریافت کانفیگ‌ها از مخزن‌ها...")
    raw_lines = fetch_configs(urls)
    print(f"\n📥 تعداد کل خطوط دریافت‌شده: {len(raw_lines)}")

    print("\n🔄 در حال حذف کانفیگ‌های تکراری...")
    unique_lines, removed_count, no_key_count = remove_duplicates(raw_lines)

    # ذخیره در فایل خروجی
    output_file = "cln.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(unique_lines))

    print("\n" + "=" * 40)
    print("✅ عملیات با موفقیت انجام شد!")
    print(f"📄 تعداد کل خطوط اولیه: {len(raw_lines)}")
    print(f"🗑️ تعداد حذف‌شده (تکراری): {removed_count}")
    print(f"🔀 تعداد خطوط بدون host/port (نگهداری شدند): {no_key_count}")
    print(f"📁 تعداد کانفیگ‌های نهایی: {len(unique_lines)}")
    print(f"📂 خروجی در فایل: {output_file}")


if __name__ == "__main__":
    main()

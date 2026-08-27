import re
import base64
import json
from urllib.parse import urlparse

# ----- توابع کمکی برای اعتبارسنجی -----
def is_valid_ipv4(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        if not (0 <= int(p) <= 255):
            return False
    return True

def is_valid_ipv6(ip):
    # حذف براکت‌های احتمالی
    ip = ip.strip('[]')
    try:
        # استفاده از ماژول ipaddress برای اعتبارسنجی
        import ipaddress
        ipaddress.IPv6Address(ip)
        return True
    except:
        return False

def is_valid_domain(host):
    # الگوی ساده برای دامنه (حداقل یک نقطه و حروف معتبر)
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return re.match(pattern, host) is not None and '.' in host

# ----- تابع اصلی استخراج (host, port) از هر خط -----
def extract_host_port(line):
    line = line.strip()
    if not line:
        return None

    host = None
    port = None

    # 1. پردازش vmess://
    if line.startswith('vmess://'):
        try:
            b64 = line[8:]
            b64 += '=' * (4 - len(b64) % 4) if len(b64) % 4 else ''
            decoded = base64.b64decode(b64).decode('utf-8')
            data = json.loads(decoded)
            # فیلدهای معمول: add یا host
            host = data.get('add') or data.get('host')
            port = data.get('port')
            if host and port:
                port = int(port)
                return (host, port)
        except:
            pass

    # 2. پردازش ssr://
    if line.startswith('ssr://'):
        try:
            b64 = line[6:]
            b64 += '=' * (4 - len(b64) % 4) if len(b64) % 4 else ''
            decoded = base64.b64decode(b64).decode('utf-8')
            # ساختار: host:port:protocol:method:obfs:params
            parts = decoded.split(':')
            if len(parts) >= 2:
                host = parts[0]
                port = int(parts[1])
                return (host, port)
        except:
            pass

    # 3. سایر URIهای استاندارد (vless, trojan, http, socks, ...)
    if '://' in line:
        try:
            parsed = urlparse(line)
            host = parsed.hostname
            if parsed.port:
                port = parsed.port
            else:
                # اگر پورت مشخص نشده، سعی می‌کنیم از پروتکل حدس بزنیم (اختیاری)
                # ولی برای احتیاط port رو None می‌ذاریم تا فقط host بررسی بشه
                port = None
            if host:
                return (host, port)
        except:
            pass

    # 4. در نهایت، اگر هیچکدام از فرمت‌های بالا موفق نشد،
    #    به دنبال یک IP یا دامنه در خط می‌گردیم و سعی می‌کنیم پورت را هم پیدا کنیم.
    #    این حالت برای لینک‌های ساده مثل "1.2.3.4:8080" یا "example.com:443" کاربرد دارد.
    match = re.search(r'([a-zA-Z0-9\.\-:]+)(?::(\d+))?', line)
    if match:
        potential_host = match.group(1)
        potential_port = match.group(2)
        # بررسی اینکه host معتبر باشد (IPv4, IPv6 یا دامنه)
        if is_valid_ipv4(potential_host) or is_valid_ipv6(potential_host) or is_valid_domain(potential_host):
            host = potential_host
            port = int(potential_port) if potential_port else None
            return (host, port)

    # اگر هیچ چیزی پیدا نشد، None برگردان
    return None

# ----- تابع اصلی -----
def main():
    input_file = 'configs.txt'
    output_file = 'cleaned_configs.txt'

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"❌ فایل '{input_file}' پیدا نشد!")
        return

    seen_keys = set()   # مجموعه کلیدهای (host, port) یکتا
    result = []
    removed_count = 0
    no_key_count = 0

    for raw_line in lines:
        line = raw_line.rstrip('\n\r')
        if not line:   # خط خالی
            result.append('')
            continue

        extracted = extract_host_port(line)

        if extracted is None:
            # خطی که نتوانستیم host/port از آن استخراج کنیم، نگهش می‌داریم
            result.append(line)
            no_key_count += 1
            continue

        host, port = extracted
        # کلید یکتا: اگر پورت None بود، فقط host را به عنوان کلید در نظر می‌گیریم
        if port is None:
            key = (host, None)
        else:
            key = (host, port)

        if key in seen_keys:
            removed_count += 1
            print(f"🗑️ حذف شد (تکراری): {host}:{port if port else 'نامشخص'}")
        else:
            seen_keys.add(key)
            result.append(line)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(result))

    print("\n" + "="*30)
    print("✅ عملیات با موفقیت انجام شد!")
    print(f"📄 تعداد کل خطوط: {len(lines)}")
    print(f"🗑️ تعداد حذف‌شده (تکراری): {removed_count}")
    print(f"🔀 تعداد خطوط بدون host/port (نگهداری شدند): {no_key_count}")
    print(f"📁 تعداد کانفیگ‌های نهایی: {len(result)}")
    print(f"📂 خروجی: {output_file}")

if __name__ == "__main__":
    main()

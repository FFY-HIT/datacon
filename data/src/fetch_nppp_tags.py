"""Fetch NPPP plugin tags list + fixed version zip for CVE-2025-6213 knowledge."""
import re
import sys
import requests

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"}
BASE = "https://plugins.svn.wordpress.org/fastcgi-cache-purge-and-preload-nginx"

r = requests.get(BASE + "/tags/", headers=H, timeout=30)
r.raise_for_status()
tags = re.findall(r'href="([0-9][0-9.]*)/"', r.text)
print("TAGS:", tags)

# readme.txt of trunk shows stable tag
rt = requests.get(BASE + "/trunk/readme.txt", headers=H, timeout=30)
m = re.search(r"Stable tag:\s*([0-9.]+)", rt.text)
print("STABLE:", m.group(1) if m else "?")

ver = sys.argv[1] if len(sys.argv) > 1 else (m.group(1) if m else "")
if ver:
    z = requests.get(
        f"https://downloads.wordpress.org/plugin/fastcgi-cache-purge-and-preload-nginx.{ver}.zip",
        headers=H, timeout=120)
    print("ZIP", ver, z.status_code, len(z.content))
    if z.status_code == 200:
        with open(f"data/src/nppp-{ver}.zip", "wb") as f:
            f.write(z.content)

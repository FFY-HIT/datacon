"""Resumable download of WordPress core tarball for CVE-2025-6213 lab."""
import os
import sys
import time
import requests

URLS = [
    "https://cn.wordpress.org/wordpress-6.7.2-zh_CN.tar.gz",
]
DEST = "tasks/CVE-2025-6213/assets/wordpress-6.7.2.tar.gz"
H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

# start fresh (previous partial file was zh_CN from a different URL)
if os.path.exists(DEST):
    os.remove(DEST)

for url in URLS:
    for attempt in range(40):
        have = os.path.getsize(DEST) if os.path.exists(DEST) else 0
        headers = dict(H)
        if have:
            headers["Range"] = f"bytes={have}-"
        try:
            r = requests.get(url, headers=headers, timeout=(15, 60), stream=True)
            if r.status_code == 416:  # already complete
                print("DONE(range416)", url, have, flush=True)
                sys.exit(0)
            if have and r.status_code == 200:
                # server ignored Range; restart
                have = 0
            if r.status_code not in (200, 206):
                print("HTTP", r.status_code, url, flush=True)
                break
            total = r.headers.get("Content-Range") or r.headers.get("Content-Length")
            mode = "ab" if have and r.status_code == 206 else "wb"
            with open(DEST, mode) as f:
                for chunk in r.iter_content(1 << 18):
                    f.write(chunk)
            size = os.path.getsize(DEST)
            print("COMPLETE", url, size, flush=True)
            # sanity: gzip magic + tar end via tarfile
            import tarfile
            with tarfile.open(DEST, "r:gz") as tf:
                names = tf.getnames()
            assert any(n.endswith("wp-settings.php") for n in names), "not a WP tarball"
            print("VERIFIED tar entries:", len(names), flush=True)
            sys.exit(0)
        except Exception as e:  # noqa: BLE001
            print(f"RETRY {url} attempt={attempt} have={os.path.getsize(DEST) if os.path.exists(DEST) else 0} err={type(e).__name__}: {e}", flush=True)
            time.sleep(3)
print("ALL_SOURCES_FAILED", flush=True)
sys.exit(1)

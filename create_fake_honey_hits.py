#!/usr/bin/env python3
"""
create_fake_honey_hits.py

Simple script to insert fake honey_hits (and optional blocklist entries)
into listings.db for testing the Admin Alerts dashboard.

Usage:
    python create_fake_honey_hits.py
"""
import sqlite3
import random
from datetime import datetime, timedelta

DB = "listings.db"

# -------- CONFIGURE HERE ----------
NUM_HITS = 8                   # total fake hits to insert
LISTING_IDS = [1, 2, 3]        # listing IDs to choose from (ensure these exist in your DB)
MAKE_BLOCKLIST = True          # whether to also add the IPs to blocklist (to test unblock UI)
# ----------------------------------

SAMPLE_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/117.0.0.0",
    "curl/7.64.1",
    "python-requests/2.31.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/116.0.0.0"
]
SAMPLE_REFERERS = [
    "http://example.com",
    "https://scanner.local",
    "http://bot.example.net/search",
    "https://google.com",
    "-"
]

def random_ip():
    if random.random() < 0.6:
        a = random.choice([ "192.168", "10.0", "172.16" ])
        return f"{a}.{random.randint(1,254)}.{random.randint(1,254)}"
    else:
        return f"{random.randint(11,195)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

def insert_fake_hits(num_hits=NUM_HITS, listing_ids=LISTING_IDS, make_blocklist=MAKE_BLOCKLIST):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    inserted = 0
    blocked = set()

    for i in range(num_hits):
        lid = random.choice(listing_ids)
        ip = random_ip()
        ua = random.choice(SAMPLE_UAS)
        ref = random.choice(SAMPLE_REFERERS)
        ts = (datetime.utcnow() - timedelta(minutes=random.randint(0, 120))).isoformat()

        try:
            c.execute(
                "INSERT INTO honey_hits (listing_id, ip, ua, referer, ts) VALUES (?, ?, ?, ?, ?)",
                (lid, ip, ua, ref, ts)
            )
            inserted += 1
        except Exception as e:
            print("Error inserting honey_hit:", e)

        if make_blocklist:
            try:
                c.execute(
                    "INSERT OR REPLACE INTO blocklist (ip, blocked_at) VALUES (?, ?)",
                    (ip, datetime.utcnow().isoformat())
                )
                blocked.add(ip)
            except Exception as e:
                print("Error inserting blocklist:", e)

    conn.commit()
    conn.close()
    print(f" Inserted {inserted} fake honey_hits into {DB}")
    if make_blocklist:
        print(f" Also added {len(blocked)} IP(s) to blocklist (sample: {list(blocked)[:3]})")
    print("Now open http://127.0.0.1:5050/admin/alerts to view them.")

if __name__ == "__main__":
    print("Running fake honey hit generator...")
    insert_fake_hits()

import os
import sqlite3
from PIL import Image
import imagehash


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "listings.db")

PHASH_DUP_THRESHOLD = 10  

def compute_phash(image_path):
    try:
        img = Image.open(image_path)
        return str(imagehash.phash(img, hash_size=8))
    except Exception as e:
        print(f"pHash error for {image_path}: {e}")
        return None

def main():
    if not os.path.exists(DB_PATH):
        print(" Database not found at:", DB_PATH)
        return

    print(" Using DB:", DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    rows = cur.execute("SELECT id, image, image_gallery FROM listings").fetchall()
    print(f"Found {len(rows)} listings")

    updated = 0

    for row in rows:
        listing_id = row["id"]


        img_path = None
        gallery = row["image_gallery"] or ""
        if gallery:
            first = gallery.split(",")[0]
            img_path = first.lstrip("/")
        else:
            img_path = (row["image"] or "").lstrip("/")

        if not img_path:
            print(f"[{listing_id}] No image path, skipping")
            continue

        abs_img_path = os.path.join(BASE_DIR, img_path)

        if not os.path.exists(abs_img_path):
            print(f"[{listing_id}] Image file not found: {abs_img_path}")
            continue

        phash = compute_phash(abs_img_path)
        if not phash:
            print(f"[{listing_id}] Could not compute phash")
            continue

        cur.execute(
            "UPDATE listings SET primary_image_hash = ? WHERE id = ?",
            (phash, listing_id),
        )
        updated += 1
        print(f"[{listing_id}] pHash updated -> {phash}")

    conn.commit()
    conn.close()
    print(f"\n Done. Updated {updated} listings with pHash.")

if __name__ == "__main__":
    main()

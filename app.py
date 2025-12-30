from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import json
from PIL import Image
import imagehash
import random  
import smtplib
from email.message import EmailMessage


UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
DB_PATH = 'listings.db'
HONEY_LOGFILE = 'logs/honey_hits.log'
ADMIN_NOTIF_LOGFILE = 'logs/admin_notifications.log'


app.secret_key = "change-this-secret-key"

# Simple admin credentials 
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# Blocking behaviour
BLOCK_DURATION_HOURS = 24       # IP kitne time tak blocked rahe
BLOCK_THRESHOLD = 2             # 2 hits ke baad block
WINDOW_MINUTES = 2              # 2 minute ke andar 2 hits

# pHash duplicate sensitivity (cropped / similar images ke liye)
PHASH_DUP_THRESHOLD = 10       

# REAL EMAIL NOTIFICATION CONFIG 
EMAIL_ENABLED = True

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "unmakedengineer@gmail.com"

SMTP_PASSWORD = "nncbdhrdzuctriig"
ADMIN_EMAIL_ADDRESS = "unmakedengineer@gmail.com"


# DATABASE 
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_all_listings():
    conn = get_db_connection()
    rows = conn.execute('SELECT * FROM listings').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def fetch_listing_by_id(listing_id):
    conn = get_db_connection()
    row = conn.execute('SELECT * FROM listings WHERE id = ?', (listing_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


#  ADMIN NOTIFICATION 
def send_admin_alert(event_type: str, message: str, extra: dict | None = None):
    """
    'Real-time/email style' notification abstraction.
    - logs/admin_notifications.log me JSON append
    - terminal me print
    - GMAIL SMTP se real email send (agar EMAIL_ENABLED = True)
    """
    # Time in HH.MM format 
    now = datetime.utcnow()
    ts = now.strftime("%H.%M")

    safe_extra = {}
    if extra:
        for k, v in extra.items():
            if isinstance(v, (int, float, str, bool)) or v is None:
                safe_extra[k] = v
            else:
                try:
                    safe_extra[k] = int(v)
                except Exception:
                    safe_extra[k] = str(v)

    payload = {
        "ts": ts,
        "type": event_type,
        "message": message,
        "extra": safe_extra
    }


    os.makedirs(os.path.dirname(ADMIN_NOTIF_LOGFILE), exist_ok=True)
    with open(ADMIN_NOTIF_LOGFILE, "a") as f:
        f.write(json.dumps(payload, default=str) + "\n")

    # Console visibility
    print(f"[ADMIN-ALERT] {ts} | {event_type} | {message}")

    #  REAL EMAIL VIA GMAIL SMTP 
    if EMAIL_ENABLED:
        try:
            # Sirf "reason" yaha map kara
            reason_map = {
                "honey_hit": "Honeytoken Triggered",
                "ip_blocked": "IP Auto-Blocked",
                "duplicate_listing": "Duplicate Listing Detected",
                "duplicate_listing_edit": "Listing Edit Now Duplicate",
            }
            reason = reason_map.get(event_type, event_type.replace("_", " ").title())
            subject = f"Alert : {reason}"

            body_lines = [
                f"Time (UTC): {ts}",
                f"Event Type: {reason}",
                "",
                "Message:",
                message,
                "",
            ]

            if safe_extra:
                body_lines.append("Extra details:")
                for k, v in safe_extra.items():
                    label = k.replace("_", " ").title()
                    body_lines.append(f"- {label}: {v}")
            else:
                body_lines.append("Extra details: None")

            body = "\n".join(body_lines)

            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = SMTP_USER
            msg["To"] = ADMIN_EMAIL_ADDRESS
            msg.set_content(body)

            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)

            print(f"[EMAIL SENT] {event_type} -> {ADMIN_EMAIL_ADDRESS}")

        except Exception as e:
            # Email failure se app crash nahi hona chahiye
            print("[EMAIL ERROR]", e)


#  IMAGE PHASH HELPER 
def compute_phash(image_path):
    """
    Image ko perceptual hash (pHash) me convert karta hai.
    Resize / compress hone par bhi similar images ka hash kareeb aata hai.
    """
    try:
        img = Image.open(image_path)
        return str(imagehash.phash(img))
    except Exception as e:
        print("pHash error:", e)
        return None


#  HONEYTOKEN & BLOCKING 
def record_honey_hit(listing_id, ip, ua, referer):
    ts = datetime.utcnow().isoformat()
    conn = get_db_connection()

    try:
        # hit log karo
        conn.execute(
            'INSERT INTO honey_hits (listing_id, ip, ua, referer, ts) VALUES (?, ?, ?, ?, ?)',
            (listing_id, ip, ua, referer, ts)
        )
        conn.commit()

        # recent hits count (WINDOW_MINUTES ke andar)
        window_start = (datetime.utcnow() - timedelta(minutes=WINDOW_MINUTES)).isoformat()
        cur = conn.execute(
            'SELECT COUNT(*) as cnt FROM honey_hits WHERE ip = ? AND ts >= ?',
            (ip, window_start)
        ).fetchone()
        cnt = cur['cnt'] if cur else 0

        # logfile me bhi likhha h yaha
        os.makedirs(os.path.dirname(HONEY_LOGFILE), exist_ok=True)
        with open(HONEY_LOGFILE, "a") as f:
            f.write(json.dumps({
                "ts": ts,
                "listing_id": listing_id,
                "ip": ip,
                "ua": ua,
                "referer": referer,
                "recent_count": cnt
            }) + "\n")


        send_admin_alert(
            "honey_hit",
            f"Honeytoken triggered for listing {listing_id} from IP {ip}",
            {"listing_id": listing_id, "ip": ip, "recent_count": cnt}
        )

        # threshold cross hua to block
        if cnt >= BLOCK_THRESHOLD:
            add_ip_to_blocklist(ip)
            print(f"🚫 BLOCKED IP: {ip} (hits={cnt})")

            # High severity notification
            send_admin_alert(
                "ip_blocked",
                f"IP {ip} automatically blocked after {cnt} honey hits.",
                {"ip": ip, "hits_window": cnt, "window_minutes": WINDOW_MINUTES}
            )
        else:
            print(f"Honey hit: {ip} (hits={cnt})")

    finally:
        conn.close()


def add_ip_to_blocklist(ip):
    now = datetime.utcnow().isoformat()
    conn = get_db_connection()
    conn.execute(
        'INSERT OR REPLACE INTO blocklist (ip, blocked_at) VALUES (?, ?)',
        (ip, now)
    )
    conn.commit()
    conn.close()


def is_ip_blocked(ip):
    conn = get_db_connection()
    row = conn.execute(
        'SELECT blocked_at FROM blocklist WHERE ip = ?',
        (ip,)
    ).fetchone()
    conn.close()

    if not row:
        return False

    blocked_at = datetime.fromisoformat(row['blocked_at'])
    # agar block duration cross ho gaya to auto-unblock
    if datetime.utcnow() - blocked_at > timedelta(hours=BLOCK_DURATION_HOURS):
        conn = get_db_connection()
        conn.execute('DELETE FROM blocklist WHERE ip = ?', (ip,))
        conn.commit()
        conn.close()
        return False

    return True


def get_recent_honey_hits(limit=200):
    conn = get_db_connection()
    rows = conn.execute(
        'SELECT * FROM honey_hits ORDER BY ts DESC LIMIT ?',
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_blocked_ips():
    conn = get_db_connection()
    rows = conn.execute(
        'SELECT * FROM blocklist ORDER BY blocked_at DESC'
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_duplicate_listings():
    """sirf woh listings jaha is_duplicate = 1 hai"""
    conn = get_db_connection()
    rows = conn.execute(
        'SELECT * FROM listings WHERE is_duplicate = 1 ORDER BY id DESC'
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# RISK SCORING HELPERS 
def get_honey_hit_count_for_listing(listing_id: int) -> int:
    conn = get_db_connection()
    row = conn.execute(
        'SELECT COUNT(*) as cnt FROM honey_hits WHERE listing_id = ?',
        (listing_id,)
    ).fetchone()
    conn.close()
    if not row:
        return 0
    try:
        return row['cnt']
    except Exception:
        return row[0]


def compute_risk(listing: dict) -> dict:
    """
    Simple risk scoring:
    - duplicate image -> +40
    - low price (< 800) -> +30
    - honey hits for this listing -> +40
    """
    score = 0
    reasons = []

    # 1) duplicate image flag
    if listing.get('is_duplicate'):
        score += 40
        reasons.append("Image matches another existing listing")

    # 2) suspiciously low price
    price_val = 0.0
    raw_price = listing.get('price', '')
    try:
        price_val = float(raw_price)
    except Exception:
        digits = ''.join(ch for ch in str(raw_price) if ch.isdigit() or ch == '.')
        try:
            price_val = float(digits) if digits else 0.0
        except Exception:
            price_val = 0.0

    if price_val and price_val < 800:
        score += 30
        reasons.append(f"Price seems unusually low (€{price_val})")

    # 3) honey hits for this listing
    listing_id = listing.get('id')
    hits = 0
    if listing_id is not None:
        hits = get_honey_hit_count_for_listing(listing_id)
        if hits >= 1:
            score += 40
            reasons.append(f"Honeytoken triggered {hits} time(s) for this listing")

    # risk level
    if score >= 70:
        level = "High"
    elif score >= 40:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "Low"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "honey_hits": hits,
    }


#  ADMIN HELPER 
def is_admin():
    return session.get("is_admin", False)


def require_admin():
    if not is_admin():
        next_url = request.path
        return redirect(url_for("login", next=next_url))


# is_admin ko sab templates me global bana diya
@app.context_processor
def inject_is_admin():
    return {"is_admin": is_admin()}


#  BLOCK MIDDLEWARE 
@app.before_request
def block_bad_ips():
    ip = request.remote_addr

    # localhost ko allow (development ke liye)
    if ip in ('127.0.0.1', '::1'):
        return

    if is_ip_blocked(ip):
        return "🚫 Access denied — your IP is blocked.", 403


# AUTH ROUTES 
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        next_url = request.form.get("next") or url_for("index")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["is_admin"] = True
            print("Admin logged in")
            return redirect(next_url)
        else:
            error = "Invalid credentials"
            return render_template("login.html", error=error, next=next_url)

    # GET request
    next_url = request.args.get("next", url_for("index"))
    return render_template("login.html", next=next_url)


# `/admin/login` ko bhi support karo 
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    return login()


@app.route("/logout")
@app.route("/admin/logout")
def logout():
    session.pop("is_admin", None)
    return redirect(url_for("index"))


#  ROUTES 
@app.route('/')
def index():
    listings = fetch_all_listings()
    admin_mode = is_admin()

    if admin_mode:
        # admin ke liye har listing ka risk pre-compute
        for l in listings:
            l['risk'] = compute_risk(l)

    return render_template(
        'index.html',
        listings=listings,
    )


@app.route('/listing/<int:listing_id>')
def listing_detail(listing_id):
    listing = fetch_listing_by_id(listing_id)
    if not listing:
        return "Listing not found", 404

    admin_mode = is_admin()
    risk = compute_risk(listing) if admin_mode else None

    # SIMPLE MATH CAPTCHA 
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    session[f"captcha_{listing_id}"] = a + b

    return render_template(
        'listing.html',
        listing=listing,
        risk=risk,
        captcha_a=a,
        captcha_b=b,
        captcha_error=None,
    )


# ADD NEW LISTING 
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # only admin allowed
    if not is_admin():
        return require_admin()

    if request.method == 'POST':
        title = request.form.get('title')
        price = request.form.get('price')
        beds = request.form.get('beds')
        baths = request.form.get('baths')
        desc = request.form.get('description', '')
        address = request.form.get('address', '')
        real_contact = request.form.get('real_contact', '')
        real_phone = request.form.get('real_phone', '')

        # honeytoken email (trap)
        honey_email = f"honey-{title.lower().replace(' ', '')}@fake.ie"

        # images + perceptual hash
        image_files = request.files.getlist('images')
        saved_paths = []
        primary_phash = None

        for img in image_files:
            if img and img.filename:
                filename = secure_filename(img.filename)
                save_path = os.path.join(UPLOAD_FOLDER, filename)
                img.save(save_path)
                saved_paths.append('/' + save_path.replace("\\", "/"))

                if primary_phash is None:
                    primary_phash = compute_phash(save_path)

        image_gallery = ",".join(saved_paths)

        conn = get_db_connection()
        is_duplicate = 0

        # PERCEPTUAL DUPLICATE CHECK (primary_image_hash column me pHash store hoga)
        if primary_phash:
            rows = conn.execute(
                "SELECT id, title, primary_image_hash FROM listings WHERE primary_image_hash IS NOT NULL"
            ).fetchall()
            for r in rows:
                old_hash = r["primary_image_hash"]
                if old_hash:
                    try:
                        diff = imagehash.hex_to_hash(primary_phash) - imagehash.hex_to_hash(old_hash)
                        if diff <= PHASH_DUP_THRESHOLD:  # threshold yaha use ho raha
                            is_duplicate = 1
                            print(
                                f"⚠️ PERCEPTUAL DUPLICATE DETECTED! Similar to listing ID {r['id']} ({r['title']}) | diff={diff}"
                            )
                            # Notification for duplicate image listing
                            send_admin_alert(
                                "duplicate_listing",
                                f"New listing '{title}' appears similar to existing listing {r['id']} ({r['title']}).",
                                {"new_title": title, "existing_id": r["id"], "diff": diff}
                            )
                            break
                    except Exception as e:
                        print("hash compare error:", e)

        print(f"[ADMIN] New listing: {title} | duplicate={is_duplicate}")

        conn.execute('''
            INSERT INTO listings
            (title, price, beds, baths, description,
             address, real_contact, real_phone,
             image, contact_email, image_gallery,
             primary_image_hash, is_duplicate)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            title,
            price,
            beds,
            baths,
            desc,
            address,
            real_contact,
            real_phone,
            saved_paths[0] if saved_paths else "/static/images/default.jpg",
            honey_email,
            image_gallery,
            primary_phash,
            is_duplicate
        ))
        conn.commit()
        conn.close()

        return redirect(url_for('index'))

    return render_template('admin.html')


# EDIT LISTING 
@app.route('/edit/<int:listing_id>', methods=['GET', 'POST'])
def edit_listing(listing_id):
    # only admin
    if not is_admin():
        return require_admin()

    listing = fetch_listing_by_id(listing_id)
    if not listing:
        return "Listing not found", 404

    if request.method == 'POST':
        title = request.form.get('title')
        price = request.form.get('price')
        beds = request.form.get('beds')
        baths = request.form.get('baths')
        desc = request.form.get('description', '')
        address = request.form.get('address', '')
        real_contact = request.form.get('real_contact', '')
        real_phone = request.form.get('real_phone', '')

        image_files = request.files.getlist('images')
        saved_paths = []
        primary_phash = listing.get('primary_image_hash')  # default purana hash
        is_duplicate = listing.get('is_duplicate', 0)

        if any(img.filename for img in image_files):
            # nayi images aayi -> gallery + pHash + duplicate recheck
            primary_phash = None
            for img in image_files:
                if img and img.filename:
                    filename = secure_filename(img.filename)
                    save_path = os.path.join(UPLOAD_FOLDER, filename)
                    img.save(save_path)
                    saved_paths.append('/' + save_path.replace("\\", "/"))
                    if primary_phash is None:
                        primary_phash = compute_phash(save_path)

            image_gallery = ",".join(saved_paths)

            conn = get_db_connection()
            is_duplicate = 0

            if primary_phash:
                rows = conn.execute(
                    "SELECT id, title, primary_image_hash FROM listings WHERE primary_image_hash IS NOT NULL AND id != ?",
                    (listing_id,)
                ).fetchall()
                for r in rows:
                    old_hash = r["primary_image_hash"]
                    if old_hash:
                        try:
                            diff = imagehash.hex_to_hash(primary_phash) - imagehash.hex_to_hash(old_hash)
                            if diff <= PHASH_DUP_THRESHOLD:
                                is_duplicate = 1
                                print(
                                    f"⚠️ PERCEPTUAL DUPLICATE ON EDIT! Similar to ID {r['id']} ({r['title']}) | diff={diff}"
                                )
                                send_admin_alert(
                                    "duplicate_listing_edit",
                                    f"Edited listing {listing_id} now similar to listing {r['id']} ({r['title']}).",
                                    {"edited_id": listing_id, "existing_id": r["id"], "diff": diff}
                                )
                                break
                        except Exception as e:
                            print("hash compare error:", e)
            conn.close()
        else:
            # koi nayi image nahi -> purana gallery + hash use karo
            image_gallery = listing.get('image_gallery', '')

        conn = get_db_connection()
        conn.execute('''
            UPDATE listings SET
            title=?, price=?, beds=?, baths=?, description=?,
            address=?, real_contact=?, real_phone=?,
            image_gallery=?, primary_image_hash=?, is_duplicate=?
            WHERE id=?
        ''', (
            title, price, beds, baths, desc,
            address, real_contact, real_phone,
            image_gallery, primary_phash, is_duplicate,
            listing_id
        ))
        conn.commit()
        conn.close()

        print(f"[EDIT] Listing {listing_id} updated | duplicate={is_duplicate}")
        return redirect(url_for('index'))

    return render_template('edit.html', listing=listing)


# DELETE 
@app.route('/delete/<int:listing_id>', methods=['POST'])
def delete_listing(listing_id):
    # only admin
    if not is_admin():
        return require_admin()

    conn = get_db_connection()
    conn.execute('DELETE FROM listings WHERE id=?', (listing_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))


#  HONEYTOKEN TRIGGER 
@app.route('/honey/<int:listing_id>')
def honey_trigger(listing_id):
    ip = request.remote_addr
    ua = request.headers.get("User-Agent")
    referer = request.headers.get("Referer")
    record_honey_hit(listing_id, ip, ua, referer)
    return render_template("honey_thanks.html")


#  CONTACT FORM 
@app.route('/contact/<int:listing_id>', methods=['POST'])
def contact_owner(listing_id):
    name = request.form.get('name')
    email = request.form.get('email')
    message = request.form.get('message')
    user_answer = request.form.get('captcha_answer', '').strip()

    expected = session.get(f"captcha_{listing_id}")

    # CAPTCHA VALIDATION
    try:
        user_answer_int = int(user_answer)
    except Exception:
        user_answer_int = None

    if expected is None or user_answer_int != expected:

        listing = fetch_listing_by_id(listing_id)
        if not listing:
            return "Listing not found", 404

        admin_mode = is_admin()
        risk = compute_risk(listing) if admin_mode else None


        a = random.randint(1, 9)
        b = random.randint(1, 9)
        session[f"captcha_{listing_id}"] = a + b

        error_msg = "CAPTCHA incorrect. Please try again."

        return render_template(
            'listing.html',
            listing=listing,
            risk=risk,
            captcha_a=a,
            captcha_b=b,
            captcha_error=error_msg,
        )


    print("\n📩 CONTACT FORM SUBMISSION")
    print("Listing:", listing_id)
    print("Name:", name)
    print("Email:", email)
    print("Message:", message)


    session.pop(f"captcha_{listing_id}", None)

    return render_template('contact_success.html', name=name)


#  ADMIN ALERTS 
@app.route('/admin/alerts')
def admin_alerts():
    # only admin
    if not is_admin():
        return require_admin()

    view = request.args.get('view', 'all')

    hits = get_recent_honey_hits() if view in ('all', 'hits') else []
    blocked = get_blocked_ips() if view in ('all', 'blocked') else []

    total_hits = len(get_recent_honey_hits())
    total_blocked = len(get_blocked_ips())
    duplicates = get_duplicate_listings()
    total_duplicates = len(duplicates)

    return render_template(
        'admin_alerts.html',
        hits=hits,
        blocked=blocked,
        duplicates=duplicates,
        active_view=view,
        total_hits=total_hits,
        total_blocked=total_blocked,
        total_duplicates=total_duplicates
    )


#  STATS (CHARTS) 
@app.route('/admin/stats')
def admin_stats():
    if not is_admin():
        return require_admin()

    conn = get_db_connection()
    hit_rows = conn.execute(
        "SELECT substr(ts,1,10) as day, COUNT(*) as cnt FROM honey_hits GROUP BY day ORDER BY day"
    ).fetchall()
    block_rows = conn.execute(
        "SELECT substr(blocked_at,1,10) as day, COUNT(*) as cnt FROM blocklist GROUP BY day ORDER BY day"
    ).fetchall()
    conn.close()

    hits_labels = [r['day'] for r in hit_rows]
    hits_counts = [r['cnt'] for r in hit_rows]
    block_labels = [r['day'] for r in block_rows]
    block_counts = [r['cnt'] for r in block_rows]

    return render_template(
        "admin_stats.html",
        hits_labels=hits_labels,
        hits_counts=hits_counts,
        block_labels=block_labels,
        block_counts=block_counts,
    )


# UNBLOCK 
@app.route('/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    # only admin
    if not is_admin():
        return require_admin()

    conn = get_db_connection()
    conn.execute('DELETE FROM blocklist WHERE ip=?', (ip,))
    conn.commit()
    conn.close()
    print("Unblocked:", ip)
    return redirect(url_for('admin_alerts'))


#  MAIN 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)

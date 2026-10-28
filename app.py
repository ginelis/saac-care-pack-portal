import streamlit as st
import streamlit.components.v1 as components
import sqlite3, hashlib, secrets, re, time, hmac
import pandas as pd
from cryptography.fernet import Fernet

st.set_page_config(page_title="Volunteer Delivery Portal", page_icon="📦", layout="centered")

DB = "portal.db"
SESSION_HOURS = 4
MAX_ATTEMPTS = 5
fernet = Fernet(st.secrets["FERNET_KEY"].encode())


# ---------- Database ----------
def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS volunteers(
            vid TEXT PRIMARY KEY, pin_hash TEXT, salt TEXT,
            expires_at REAL DEFAULT 0, active INTEGER DEFAULT 0, attempts INTEGER DEFAULT 0)""")
        c.execute("""CREATE TABLE IF NOT EXISTS deliveries(
            id INTEGER PRIMARY KEY AUTOINCREMENT, vid TEXT, name TEXT,
            address_enc BLOB, pack TEXT, status TEXT DEFAULT 'pending', delivered_at REAL)""")

init_db()

def hash_pin(pin, salt):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 100_000).hex()

def mask_address(addr):
    m = re.search(r"\b(\d{6})\b", addr)
    if m:
        return f"Singapore {m.group(1)[:2]}****"
    return "Address hidden until you start this delivery"


# ---------- Anti-copy / anti-print protections ----------
def inject_protection():
    st.markdown("""
    <style>
      * { -webkit-user-select: none; user-select: none; -webkit-touch-callout: none; }
      @media print { html, body, .stApp { display: none !important; } }
      #MainMenu, footer, header [data-testid="stToolbar"] { visibility: hidden; }
      .block-container { padding-top: 1.5rem; max-width: 600px; }
      .addr { font-size: 1.15rem; padding: .8rem; background: #fff3cd; border-radius: 8px; }
      .card { padding: .6rem 0; }
    </style>""", unsafe_allow_html=True)
    components.html("""
    <script>
    const d = window.parent.document, w = window.parent;
    const block = e => { e.preventDefault(); e.stopPropagation(); return false; };
    ['contextmenu','copy','cut','dragstart','selectstart'].forEach(ev => d.addEventListener(ev, block, true));
    d.addEventListener('keydown', e => {
      const k = e.key.toLowerCase();
      if ((e.ctrlKey || e.metaKey) && ['p','s','c','u','a'].includes(k)) block(e);
      if (e.key === 'PrintScreen') { navigator.clipboard && navigator.clipboard.writeText(''); block(e); }
      if (e.key === 'F12') block(e);
    }, true);
    w.addEventListener('beforeprint', () => { d.body.style.display = 'none'; });
    w.addEventListener('afterprint', () => { d.body.style.display = ''; });
    // Blur content when app is in background / app-switcher
    d.addEventListener('visibilitychange', () => {
      d.body.style.filter = d.hidden ? 'blur(20px)' : '';
    });
    w.addEventListener('blur', () => { d.body.style.filter = 'blur(20px)'; });
    w.addEventListener('focus', () => { d.body.style.filter = ''; });
    </script>""", height=0)

def privacy_footer():
    st.divider()
    st.caption(
        "🔒 **Privacy Notice (PDPA):** The information shown is confidential and provided solely "
        "for delivering care packs. Do not screenshot, photograph, copy, write down, or share any "
        "beneficiary's details. Do not retain any personal data after delivery. Misuse of personal "
        "data may breach the Personal Data Protection Act. Report any loss or leak to the organiser immediately."
    )


# ---------- Volunteer logic ----------
def volunteer_logout():
    for k in ("vid", "revealed"):
        st.session_state.pop(k, None)

def volunteer_login_page():
    st.title("📦 Volunteer Delivery Portal")
    st.write("Enter your Volunteer ID and the PIN given by the organiser.")
    with st.form("login"):
        vid = st.text_input("Volunteer ID").strip().upper()
        pin = st.text_input("PIN", type="password")
        ok = st.form_submit_button("Log in", use_container_width=True)
    if not ok:
        return
    with conn() as c:
        v = c.execute("SELECT * FROM volunteers WHERE vid=?", (vid,)).fetchone()
        if not v or not v["pin_hash"]:
            st.error("Invalid ID or PIN.")
            return
        if v["attempts"] >= MAX_ATTEMPTS:
            st.error("Account locked. Please contact the organiser.")
            return
        good = hmac.compare_digest(hash_pin(pin, v["salt"]), v["pin_hash"])
        if not good:
            c.execute("UPDATE volunteers SET attempts=attempts+1 WHERE vid=?", (vid,))
            st.error("Invalid ID or PIN.")
            return
        if not v["active"] or v["expires_at"] < time.time():
            st.error("Your access has expired. Please contact the organiser.")
            return
        c.execute("UPDATE volunteers SET attempts=0 WHERE vid=?", (vid,))
    st.session_state.vid = vid
    st.rerun()

def volunteer_page():
    vid = st.session_state.vid
    with conn() as c:
        v = c.execute("SELECT * FROM volunteers WHERE vid=?", (vid,)).fetchone()
    if not v or not v["active"] or v["expires_at"] < time.time():
        volunteer_logout()
        st.warning("Your session has expired. Access has been closed.")
        st.stop()

    remaining = int((v["expires_at"] - time.time()) / 60)
    top = st.columns([3, 1])
    top[0].subheader(f"Hello, {vid}")
    if top[1].button("Log out"):
        volunteer_logout()
        st.rerun()
    st.caption(f"Access expires in about {remaining} min")

    with conn() as c:
        rows = c.execute(
            "SELECT * FROM deliveries WHERE vid=? AND status='pending' ORDER BY id", (vid,)).fetchall()

    if not rows:
        with conn() as c:
            c.execute("UPDATE volunteers SET active=0 WHERE vid=?", (vid,))
        volunteer_logout()
        st.success("🎉 All deliveries completed. Thank you! Your access has been closed.")
        st.stop()

    st.write(f"**{len(rows)} deliveries remaining**")
    revealed = st.session_state.get("revealed")

    for i, r in enumerate(rows, 1):
        with st.container(border=True):
            st.markdown(f"**Stop {i}: {r['name']}**  \nPack: {r['pack']}")
            if revealed == r["id"]:
                full = fernet.decrypt(r["address_enc"]).decode()
                st.markdown(f"<div class='addr'>📍 {full}</div>", unsafe_allow_html=True)
                c1, c2 = st.columns(2)
                if c1.button("Hide address", key=f"hide{r['id']}", use_container_width=True):
                    st.session_state.revealed = None
                    st.rerun()
                if c2.button("✅ Mark as Delivered", key=f"done{r['id']}", type="primary",
                             use_container_width=True):
                    with conn() as c:
                        c.execute("""UPDATE deliveries SET status='delivered', address_enc=NULL,
                                     delivered_at=? WHERE id=?""", (time.time(), r["id"]))
                    st.session_state.revealed = None
                    st.rerun()
            else:
                try:
                    area = mask_address(fernet.decrypt(r["address_enc"]).decode())
                except Exception:
                    area = "Address hidden"
                st.write(f"📍 {area}")
                if st.button("Start this delivery / Show address", key=f"show{r['id']}",
                             use_container_width=True):
                    st.session_state.revealed = r["id"]
                    st.rerun()


# ---------- Admin ----------
def admin_page():
    st.title("🛠️ Admin Dashboard")
    if not st.session_state.get("admin"):
        pw = st.text_input("Admin password", type="password")
        if st.button("Log in"):
            if hmac.compare_digest(pw, st.secrets["ADMIN_PASSWORD"]):
                st.session_state.admin = True
                st.rerun()
            else:
                st.error("Wrong password.")
        return

    t1, t2, t3, t4 = st.tabs(["Upload list", "Volunteers & PINs", "Status", "Purge data"])

    with t1:
        st.write("Upload a CSV/Excel with columns: **Name, Address, Care Pack Type, Volunteer ID**")
        f = st.file_uploader("File", type=["csv", "xlsx"])
        if f:
            df = pd.read_csv(f) if f.name.endswith(".csv") else pd.read_excel(f)
            df.columns = [c.strip() for c in df.columns]
            need = ["Name", "Address", "Care Pack Type", "Volunteer ID"]
            if not all(n in df.columns for n in need):
                st.error(f"Missing columns. Required: {need}")
            else:
                st.write(f"{len(df)} rows found (addresses hidden in preview).")
                st.dataframe(df[["Name", "Care Pack Type", "Volunteer ID"]])
                if st.button("Import", type="primary"):
                    with conn() as c:
                        for _, r in df.iterrows():
                            vid = str(r["Volunteer ID"]).strip().upper()
                            c.execute("INSERT OR IGNORE INTO volunteers(vid) VALUES(?)", (vid,))
                            c.execute("INSERT INTO deliveries(vid,name,address_enc,pack) VALUES(?,?,?,?)",
                                      (vid, str(r["Name"]),
                                       fernet.encrypt(str(r["Address"]).encode()),
                                       str(r["Care Pack Type"])))
                    st.success("Imported. Now generate PINs in the next tab.")

    with t2:
        with conn() as c:
            vols = c.execute("""SELECT v.vid, v.active, v.expires_at, v.attempts,
                (SELECT COUNT(*) FROM deliveries d WHERE d.vid=v.vid AND d.status='pending') AS pending
                FROM volunteers v ORDER BY v.vid""").fetchall()
        new = st.text_input("Add a Volunteer ID manually (optional)").strip().upper()
        if st.button("Add") and new:
            with conn() as c:
                c.execute("INSERT OR IGNORE INTO volunteers(vid) VALUES(?)", (new,))
            st.rerun()
        for v in vols:
            live = v["active"] and v["expires_at"] > time.time()
            with st.container(border=True):
                st.write(f"**{v['vid']}** | pending: {v['pending']} | "
                         f"{'🟢 active' if live else '⚪ inactive'}"
                         f"{' | 🔒 locked' if v['attempts'] >= MAX_ATTEMPTS else ''}")
                c1, c2 = st.columns(2)
                if c1.button(f"Generate {SESSION_HOURS}h PIN", key=f"pin{v['vid']}"):
                    pin = f"{secrets.randbelow(900000) + 100000}"
                    salt = secrets.token_hex(8)
                    with conn() as c:
                        c.execute("""UPDATE volunteers SET pin_hash=?, salt=?, expires_at=?,
                                     active=1, attempts=0 WHERE vid=?""",
                                  (hash_pin(pin, salt), salt, time.time() + SESSION_HOURS * 3600, v["vid"]))
                    st.success(f"PIN for {v['vid']}: **{pin}** (shown once; valid {SESSION_HOURS} hours)")
                if c2.button("Revoke access", key=f"rev{v['vid']}"):
                    with conn() as c:
                        c.execute("UPDATE volunteers SET active=0 WHERE vid=?", (v["vid"],))
                    st.rerun()

    with t3:
        with conn() as c:
            data = c.execute("""SELECT id, vid AS volunteer, name, pack, status,
                datetime(delivered_at,'unixepoch','localtime') AS delivered_at
                FROM deliveries ORDER BY id""").fetchall()
        st.dataframe(pd.DataFrame([dict(r) for r in data]), use_container_width=True)

    with t4:
        st.warning("Erases all stored addresses and revokes all volunteer access.")
        if st.checkbox("I understand") and st.button("Purge all addresses now", type="primary"):
            with conn() as c:
                c.execute("UPDATE deliveries SET address_enc=NULL")
                c.execute("UPDATE volunteers SET active=0, pin_hash=NULL")
            st.success("All addresses erased and access revoked.")
        if st.checkbox("Also delete all delivery records") and st.button("Delete records"):
            with conn() as c:
                c.execute("DELETE FROM deliveries")
            st.success("Deleted.")

    if st.button("Admin log out"):
        st.session_state.admin = False
        st.rerun()


# ---------- Router ----------
inject_protection()
if st.query_params.get("admin") == "1":
    admin_page()
elif "vid" in st.session_state:
    volunteer_page()
else:
    volunteer_login_page()
privacy_footer()

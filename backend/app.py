# backend/app.py
import os
import json
import time
import threading
import uuid
import binascii
from datetime import datetime
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
import gspread
from google.oauth2.service_account import Credentials
import requests
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from passlib.hash import pbkdf2_sha256

# ---------------- Flask app & CORS ----------------
app = Flask(__name__, static_folder='.')
CORS(app)  # allow GitHub Pages frontend to call this API

# ---------------- CONFIG (Set these on Render env) ----------------
SHEET_ID = os.environ.get('GOOGLE_SHEET_ID')           # Google Sheet ID
TELNYX_API_KEY = os.environ.get('TELNYX_API_KEY')     # Telnyx API key (secret)
TELNYX_PUBLIC_KEY = os.environ.get('TELNYX_PUBLIC_KEY')  # Telnyx webhook pubkey (hex/base64)
TELNYX_FROM_NUMBER = os.environ.get('TELNYX_FROM_NUMBER', '')  # optional default sender number
COST_PER_SMS_CENTS = int(os.environ.get('COST_PER_SMS_CENTS', '8'))  # default cost per SMS (cents)
# -----------------------------------------------------------------

# single-instance global lock to serialize wallet changes (required while using Google Sheets)
lock = threading.Lock()

# ---------------- Google Sheets client ----------------
def gs_client():
    scopes = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
    sa_json = os.environ.get('GOOGLE_SA_JSON')
    sa_path = os.environ.get('GOOGLE_SA_JSON_PATH')
    if sa_json:
        creds = Credentials.from_service_account_info(json.loads(sa_json), scopes=scopes)
    elif sa_path:
        creds = Credentials.from_service_account_file(sa_path, scopes=scopes)
    else:
        raise RuntimeError("Provide GOOGLE_SA_JSON or GOOGLE_SA_JSON_PATH env var")
    return gspread.authorize(creds)

gc = gs_client()
sheet = gc.open_by_key(SHEET_ID)

def get_ws(name):
    return sheet.worksheet(name)

def now_ts():
    return datetime.utcnow().isoformat() + "Z"

def find_row(ws, col_name, value):
    """
    Find a row by header column name and value. Returns (row_index, row_values_list) or (None, None).
    """
    headers = ws.row_values(1)
    if col_name not in headers:
        return None, None
    col_idx = headers.index(col_name) + 1
    try:
        cell = ws.find(value, in_column=col_idx)
        return cell.row, ws.row_values(cell.row)
    except Exception:
        return None, None

# ---------------- Password helpers (passlib) ----------------
def hash_password(plain):
    return pbkdf2_sha256.hash(plain)

def verify_password(plain, hashed):
    try:
        return pbkdf2_sha256.verify(plain, hashed)
    except Exception:
        return False

# ---------------- Auth endpoints (signup/login) ----------------
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()
    name = (data.get('display_name') or '').strip()
    password = data.get('password')

    if not email or not password:
        return jsonify({'error':'email and password required'}), 400

    ws = get_ws('profiles')
    row, _ = find_row(ws, 'email', email)
    if row:
        return jsonify({'error':'user_exists'}), 400

    pwd_hash = hash_password(password)
    new_id = str(uuid.uuid4())

    # profiles header must be:
    # id,email,display_name,password_hash,assigned_numbers,is_admin,created_at
    ws.append_row([new_id, email, name, pwd_hash, '', 'FALSE', now_ts()])

    # create wallet row
    wallets = get_ws('wallets')
    wallets.append_row([email, '0', now_ts()])

    return jsonify({'ok': True, 'id': new_id})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password')

    if not email or not password:
        return jsonify({'error':'email_and_password_required'}), 400

    ws = get_ws('profiles')
    row, vals = find_row(ws, 'email', email)
    if not row:
        return jsonify({'error':'not_found'}), 404

    # vals layout: [id, email, display_name, password_hash, assigned_numbers, is_admin, created_at]
    stored_hash = None
    if len(vals) >= 4:
        stored_hash = vals[3]

    if not stored_hash:
        return jsonify({'error':'no_password_set'}), 403

    if not verify_password(password, stored_hash):
        return jsonify({'error':'invalid_credentials'}), 401

    return jsonify({'ok': True, 'profile': {'id': vals[0], 'email': vals[1], 'display_name': vals[2]}})

# ---------------- Admin detection helper ----------------
def require_admin(req):
    """
    Validates that the calling user (X-Admin-Email header) exists and has is_admin truthy.
    Accepts boolean True, numeric 1, or text 'TRUE' (case-insensitive).
    """
    admin_email = req.headers.get('X-Admin-Email')
    if not admin_email:
        abort(401)
    pws = get_ws('profiles')
    row, vals = find_row(pws, 'email', admin_email)
    if not row:
        abort(403)

    # Find is_admin using header lookup if possible
    headers = pws.row_values(1)
    is_admin_val = None
    if 'is_admin' in headers:
        col_idx = headers.index('is_admin') + 1
        try:
            is_admin_val = pws.cell(row, col_idx).value
        except Exception:
            # fallback to vals array
            try:
                is_admin_val = vals[5] if len(vals) > 5 else None
            except Exception:
                is_admin_val = None
    else:
        is_admin_val = vals[5] if len(vals) > 5 else None

    is_admin = False
    if isinstance(is_admin_val, bool):
        is_admin = bool(is_admin_val)
    elif isinstance(is_admin_val, (int, float)):
        is_admin = bool(is_admin_val)
    elif is_admin_val is not None:
        try:
            is_admin = str(is_admin_val).strip().upper() == 'TRUE'
        except Exception:
            is_admin = False

    if not is_admin:
        abort(403)
    return admin_email

# ---------------- Admin endpoints ----------------
@app.route('/admin/assign-number', methods=['POST'])
def admin_assign_number():
    admin_email = require_admin(request)
    data = request.json or {}
    target_email = data.get('email')
    number = data.get('number')
    telnyx_id = data.get('telnyx_number_id', '')
    if not target_email or not number:
        return jsonify({'error':'email and number required'}), 400

    ws = get_ws('numbers')
    row, vals = find_row(ws, 'number', number)
    if row:
        ws.update_cell(row, 2, target_email)
        ws.update_cell(row, 3, telnyx_id)
    else:
        ws.append_row([number, target_email, telnyx_id, now_ts()])

    # update profiles.assigned_numbers (assigned_numbers is column 5)
    pws = get_ws('profiles')
    prow, pvals = find_row(pws, 'email', target_email)
    if prow:
        assigned = ''
        if len(pvals) >= 5:
            assigned = pvals[4] or ''
        if number not in assigned:
            new_assigned = (assigned + ',' + number).lstrip(',')
            pws.update_cell(prow, 5, new_assigned)

    aws = get_ws('admin_actions')
    aws.append_row([str(uuid.uuid4()), admin_email, target_email, 'assign_number', json.dumps({'number':number,'telnyx_id':telnyx_id}), now_ts()])
    return jsonify({'ok': True})

@app.route('/admin/topup', methods=['POST'])
def admin_topup():
    admin_email = require_admin(request)
    data = request.json or {}
    target_email = data.get('email')
    try:
        amount_cents = int(data.get('amount_cents'))
    except Exception:
        return jsonify({'error':'invalid_amount'}), 400
    note = data.get('note','manual topup')

    with lock:
        wws = get_ws('wallets')
        wrow, wvals = find_row(wws, 'email', target_email)
        if not wrow:
            wws.append_row([target_email, str(amount_cents), now_ts()])
        else:
            cur = int(wvals[1] or 0)
            new = cur + amount_cents
            wws.update_cell(wrow, 2, str(new))
            wws.update_cell(wrow, 3, now_ts())
    tws = get_ws('transactions')
    tws.append_row([str(uuid.uuid4()), target_email, 'topup', amount_cents, note, '', now_ts()])
    aws = get_ws('admin_actions')
    aws.append_row([str(uuid.uuid4()), admin_email, target_email, 'topup', json.dumps({'amount_cents':amount_cents, 'note':note}), now_ts()])
    return jsonify({'ok': True})

# ---------------- Profile endpoint ----------------
@app.route('/api/profile/<email>', methods=['GET'])
def get_profile(email):
    pws = get_ws('profiles')
    prow, pvals = find_row(pws, 'email', email)
    if not prow:
        return jsonify({'error':'not found'}), 404

    # assigned_numbers is column 5 (index 4)
    assigned_raw = ''
    if len(pvals) >= 5:
        assigned_raw = pvals[4] or ''
    assigned_list = [x for x in assigned_raw.split(',') if x]

    wws = get_ws('wallets')
    wrow, wvals = find_row(wws, 'email', email)
    balance = int(wvals[1] or 0) if wvals else 0

    return jsonify({'profile': {'email': pvals[1], 'display_name': pvals[2], 'assigned_numbers': assigned_list}, 'wallet_cents': balance})

# ---------------- Conversations & messages read endpoints ----------------
@app.route('/api/conversations', methods=['GET'])
def api_conversations():
    """
    GET /api/conversations?email=owner@example.com
    Returns list of conversations where owner_email matches.
    """
    owner = request.args.get('email')
    cws = get_ws('conversations')
    rows = cws.get_all_records()
    if owner:
        rows = [r for r in rows if str(r.get('owner_email') or '').lower() == owner.lower()]
    # normalize: ensure id, contact_number, last_message_at keys
    convs = []
    for r in rows:
        convs.append({
            'id': str(r.get('id') or ''),
            'contact_number': r.get('contact_number') or r.get('contact') or '',
            'last_message_at': r.get('last_message_at') or ''
        })
    return jsonify({'conversations': convs})

@app.route('/api/conversations/<conv_id>/messages', methods=['GET'])
def api_conversation_messages(conv_id):
    """
    GET /api/conversations/<conv_id>/messages
    Returns messages belonging to a conversation id.
    """
    mws = get_ws('messages')
    rows = mws.get_all_records()
    msgs = []
    for r in rows:
        if str(r.get('conversation_id') or '') == conv_id:
            msgs.append({
                'id': r.get('id'),
                'conversation_id': r.get('conversation_id'),
                'from_number': r.get('from_number'),
                'to_number': r.get('to_number'),
                'direction': r.get('direction'),
                'body': r.get('body'),
                'status': r.get('status'),
                'telnyx_message_id': r.get('telnyx_message_id'),
                'cost_cents': int(r.get('cost_cents') or 0),
                'created_at': r.get('created_at')
            })
    # sort by created_at (ISO timestamps) if present
    try:
        msgs.sort(key=lambda x: x.get('created_at') or '')
    except Exception:
        pass
    return jsonify({'messages': msgs})

# ---------------- Telnyx helpers ----------------
def telnyx_send(from_num, to_num, text):
    if not TELNYX_API_KEY:
        raise RuntimeError("TELNYX_API_KEY not configured")
    url = "https://api.telnyx.com/v2/messages"
    headers = {"Authorization": f"Bearer {TELNYX_API_KEY}", "Content-Type": "application/json"}
    payload = {"from": from_num, "to": [to_num], "text": text}
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    r.raise_for_status()
    return r.json()

def verify_telnyx_signature(req):
    """
    Verifies Telnyx webhook signature using ED25519.
    Requires TELNYX_PUBLIC_KEY env var (hex or base64).
    """
    if not TELNYX_PUBLIC_KEY:
        return False, "No TELNYX_PUBLIC_KEY configured"
    sig_header = req.headers.get('Telnyx-Signature-Ed25519') or req.headers.get('telnyx-signature-ed25519')
    ts_header = req.headers.get('Telnyx-Signature-Timestamp') or req.headers.get('telnyx-signature-timestamp')
    if not sig_header or not ts_header:
        return False, "Missing signature headers"
    # decode signature
    try:
        signature = binascii.unhexlify(sig_header)
    except Exception:
        try:
            signature = binascii.a2b_base64(sig_header)
        except Exception:
            return False, "Cannot decode signature"
    message = (ts_header + req.get_data(as_text=True)).encode('utf-8')
    try:
        try:
            pub = binascii.unhexlify(TELNYX_PUBLIC_KEY)
        except Exception:
            pub = binascii.a2b_base64(TELNYX_PUBLIC_KEY)
        verify_key = VerifyKey(pub)
        verify_key.verify(message, signature)
        return True, ""
    except BadSignatureError:
        return False, "Bad signature"
    except Exception as e:
        return False, str(e)

# ---------------- Sending SMS (wallet deduction + Telnyx call) ----------------
@app.route('/api/send', methods=['POST'])
def send_sms():
    data = request.json or {}
    email = data.get('email')
    from_num = data.get('from')
    to_num = data.get('to')
    text = data.get('text','')
    if not all([email, from_num, to_num, text]):
        return jsonify({'error':'missing fields'}), 400

    # check wallet and deduct atomically
    with lock:
        wws = get_ws('wallets')
        wrow, wvals = find_row(wws, 'email', email)
        if not wrow:
            return jsonify({'error':'no wallet'}), 400
        balance = int(wvals[1] or 0)
        if balance < COST_PER_SMS_CENTS:
            return jsonify({'error':'insufficient_funds'}), 402
        newbal = balance - COST_PER_SMS_CENTS
        wws.update_cell(wrow, 2, str(newbal))
        wws.update_cell(wrow, 3, now_ts())
        tws = get_ws('transactions')
        txid = str(uuid.uuid4())
        tws.append_row([txid, email, 'charge', -COST_PER_SMS_CENTS, f'SMS to {to_num}', '', now_ts()])

    # log outbound message in messages sheet (queued)
    mws = get_ws('messages')
    msgid = str(uuid.uuid4())
    # messages header: id,conversation_id,from_number,to_number,direction,body,status,telnyx_message_id,cost_cents,created_at
    mws.append_row([msgid, '', from_num, to_num, 'outbound', text, 'queued', '', COST_PER_SMS_CENTS, now_ts()])

    try:
        res = telnyx_send(from_num, to_num, text)
        # Telnyx returns an object; try to extract id
        telnyx_id = None
        try:
            telnyx_id = res.get('data', {}).get('id') or res.get('data', [{}])[0].get('id')
        except Exception:
            telnyx_id = None
        # update message row: status and telnyx id
        row, vals = find_row(mws, 'id', msgid)
        if row:
            # status column is index 7 (1-based), telnyx_message_id is index 8
            mws.update_cell(row, 7, 'sent')
            mws.update_cell(row, 8, telnyx_id or '')
        return jsonify({'ok': True, 'msgid': msgid, 'telnyx_id': telnyx_id})
    except Exception as e:
        # on failure, refund the wallet
        with lock:
            try:
                wws = get_ws('wallets')
                wrow, wvals = find_row(wws, 'email', email)
                if wrow:
                    cur = int(wvals[1] or 0)
                    wws.update_cell(wrow, 2, str(cur + COST_PER_SMS_CENTS))
                    wws.update_cell(wrow, 3, now_ts())
                    tws = get_ws('transactions')
                    tws.append_row([str(uuid.uuid4()), email, 'refund', COST_PER_SMS_CENTS, f'refund failed send to {to_num}', msgid, now_ts()])
            except Exception:
                pass
        return jsonify({'error':'telnyx_send_failed', 'detail': str(e)}), 500

# ---------------- Telnyx webhook receiver ----------------
@app.route('/webhooks/telnyx', methods=['POST'])
def telnyx_webhook():
    ok, msg = verify_telnyx_signature(request)
    if not ok:
        return jsonify({'error':'invalid_signature', 'detail': msg}), 400
    payload = request.json or {}
    event_type = payload.get('event_type','')
    data = payload.get('data', {})
    p = data.get('payload', data)  # Telnyx nests payload sometimes
    # handle inbound messages
    if 'inbound' in event_type or 'message' in event_type:
        from_num = p.get('from')
        to_num = p.get('to')
        text = p.get('text','')
        nws = get_ws('numbers')
        nrow, nvals = find_row(nws, 'number', to_num)
        owner_email = None
        if nrow and nvals and len(nvals) >= 2:
            owner_email = nvals[1]
        cws = get_ws('conversations')
        # create conversation and message rows
        conv_id = str(uuid.uuid4())
        cws.append_row([conv_id, owner_email or '', from_num, now_ts()])
        mws = get_ws('messages')
        mws.append_row([str(uuid.uuid4()), conv_id, from_num, to_num, 'inbound', text, 'received', '', 0, now_ts()])
    return jsonify({'ok': True})

# ---------------- Run ----------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

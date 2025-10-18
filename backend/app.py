# app.py
import os, json, time, threading, uuid, binascii
from datetime import datetime
from flask import Flask, request, jsonify, abort
import gspread
from google.oauth2.service_account import Credentials
import requests
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

app = Flask(__name__)
app.static_folder = '.'

# ---------------- CONFIG (Set these on Render env)
SHEET_ID = os.environ.get('GOOGLE_SHEET_ID')           # Google Sheet ID
TELNYX_API_KEY = os.environ.get('TELNYX_API_KEY')     # Telnyx API key
TELNYX_PUBLIC_KEY = os.environ.get('TELNYX_PUBLIC_KEY')  # Telnyx public key (hex/base64 as provided)
TELNYX_FROM_NUMBER = os.environ.get('TELNYX_FROM_NUMBER', '')  # default sender
COST_PER_SMS_CENTS = int(os.environ.get('COST_PER_SMS_CENTS', '8'))  # default cost
# ---------------- END CONFIG

lock = threading.Lock()

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
    headers = ws.row_values(1)
    if col_name not in headers:
        return None, None
    col_idx = headers.index(col_name) + 1
    try:
        cell = ws.find(value, in_column=col_idx)
        return cell.row, ws.row_values(cell.row)
    except Exception:
        return None, None

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    name = data.get('display_name', '')
    if not email:
        return jsonify({'error':'email required'}), 400
    ws = get_ws('profiles')
    row, _ = find_row(ws, 'email', email)
    if row:
        return jsonify({'ok': True, 'message':'already exists'})
    new_id = str(uuid.uuid4())
    ws.append_row([new_id, email, name, '', 'FALSE', now_ts()])
    wallets = get_ws('wallets')
    wallets.append_row([email, '0', now_ts()])
    return jsonify({'ok': True, 'id': new_id})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    if not email:
        return jsonify({'error':'email required'}), 400
    ws = get_ws('profiles')
    row, rowvals = find_row(ws, 'email', email)
    if not row:
        return jsonify({'error':'not found'}), 404
    return jsonify({'ok': True, 'profile': {'id': rowvals[0], 'email': rowvals[1], 'display_name': rowvals[2]}})

def require_admin(req):
    admin_email = req.headers.get('X-Admin-Email')
    if not admin_email:
        abort(401)
    ws = get_ws('profiles')
    row, vals = find_row(ws, 'email', admin_email)
    if not row:
        abort(403)
    if len(vals) < 5 or vals[4].upper() != 'TRUE':
        abort(403)
    return admin_email

@app.route('/admin/assign-number', methods=['POST'])
def admin_assign_number():
    admin_email = require_admin(request)
    data = request.json
    target_email = data['email']
    number = data['number']
    telnyx_id = data.get('telnyx_number_id', '')
    ws = get_ws('numbers')
    row, vals = find_row(ws, 'number', number)
    if row:
        ws.update_cell(row, 2, target_email)
        ws.update_cell(row, 3, telnyx_id)
    else:
        ws.append_row([number, target_email, telnyx_id, now_ts()])
    pws = get_ws('profiles')
    prow, pvals = find_row(pws, 'email', target_email)
    if prow:
        assigned = pvals[3] or ''
        if number not in assigned:
            new_assigned = (assigned + ',' + number).lstrip(',')
            pws.update_cell(prow, 4, new_assigned)
    aws = get_ws('admin_actions')
    aws.append_row([str(uuid.uuid4()), admin_email, target_email, 'assign_number', json.dumps({'number':number,'telnyx_id':telnyx_id}), now_ts()])
    return jsonify({'ok': True})

@app.route('/admin/topup', methods=['POST'])
def admin_topup():
    admin_email = require_admin(request)
    data = request.json
    target_email = data['email']
    amount_cents = int(data['amount_cents'])
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

@app.route('/api/profile/<email>', methods=['GET'])
def get_profile(email):
    pws = get_ws('profiles')
    prow, pvals = find_row(pws, 'email', email)
    if not prow:
        return jsonify({'error':'not found'}), 404
    wws = get_ws('wallets')
    wrow, wvals = find_row(wws, 'email', email)
    balance = int(wvals[1] or 0) if wvals else 0
    return jsonify({'profile': {'email':pvals[1], 'display_name': pvals[2], 'assigned_numbers': pvals[3].split(',') if pvals[3] else []}, 'wallet_cents': balance})

def telnyx_send(from_num, to_num, text):
    url = "https://api.telnyx.com/v2/messages"
    headers = {"Authorization": f"Bearer {TELNYX_API_KEY}", "Content-Type": "application/json"}
    payload = {"from": from_num, "to": [to_num], "text": text}
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    r.raise_for_status()
    return r.json()

def verify_telnyx_signature(req):
    if not TELNYX_PUBLIC_KEY:
        return False, "No TELNYX_PUBLIC_KEY configured"
    sig_header = req.headers.get('Telnyx-Signature-Ed25519') or req.headers.get('telnyx-signature-ed25519')
    ts_header = req.headers.get('Telnyx-Signature-Timestamp') or req.headers.get('telnyx-signature-timestamp')
    if not sig_header or not ts_header:
        return False, "Missing signature headers"
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

@app.route('/api/send', methods=['POST'])
def send_sms():
    data = request.json
    email = data.get('email')
    from_num = data.get('from')
    to_num = data.get('to')
    text = data.get('text','')
    if not all([email, from_num, to_num, text]):
        return jsonify({'error':'missing fields'}), 400

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

    mws = get_ws('messages')
    msgid = str(uuid.uuid4())
    mws.append_row([msgid, '', from_num, to_num, 'outbound', text, 'queued', '', COST_PER_SMS_CENTS, now_ts()])

    try:
        res = telnyx_send(from_num, to_num, text)
        telnyx_id = res.get('data', {}).get('id')
        row, vals = find_row(mws, 'id', msgid)
        if row:
            mws.update_cell(row, 7, 'sent')
            mws.update_cell(row, 8, telnyx_id)
        return jsonify({'ok': True, 'msgid': msgid, 'telnyx_id': telnyx_id})
    except Exception as e:
        with lock:
            wws = get_ws('wallets')
            wrow, wvals = find_row(wws, 'email', email)
            if wrow:
                cur = int(wvals[1] or 0)
                wws.update_cell(wrow, 2, str(cur + COST_PER_SMS_CENTS))
                wws.update_cell(wrow, 3, now_ts())
                tws.append_row([str(uuid.uuid4()), email, 'refund', COST_PER_SMS_CENTS, f'refund failed send to {to_num}', msgid, now_ts()])
        return jsonify({'error':'telnyx_send_failed', 'detail': str(e)}), 500

@app.route('/webhooks/telnyx', methods=['POST'])
def telnyx_webhook():
    ok, msg = verify_telnyx_signature(request)
    if not ok:
        return jsonify({'error':'invalid_signature', 'detail': msg}), 400
    payload = request.json or {}
    event_type = payload.get('event_type','')
    data = payload.get('data', {})
    p = data.get('payload', data)
    if 'inbound' in event_type or 'message' in event_type:
        from_num = p.get('from')
        to_num = p.get('to')
        text = p.get('text','')
        nws = get_ws('numbers')
        nrow, nvals = find_row(nws, 'number', to_num)
        owner_email = nvals[1] if nvals else None
        cws = get_ws('conversations')
        conv_id = str(uuid.uuid4())
        cws.append_row([conv_id, owner_email or '', from_num, now_ts()])
        mws = get_ws('messages')
        mws.append_row([str(uuid.uuid4()), conv_id, from_num, to_num, 'inbound', text, 'received', '', 0, now_ts()])
    return jsonify({'ok': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))


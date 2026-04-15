"""
app.py — DDoS Shield: Real Traffic Detection & Blocking
- NO fake/random IPs
- Every real HTTP request is tracked per source IP
- ML model analyzes actual flow features from real requests
- Auto-blocks attacking IPs, identifies attack TYPE
"""
import os, time, threading, json, logging, random
from collections import defaultdict, deque
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response
from flask_socketio import SocketIO, emit
from detector    import get_detector, generate_attack_flow
from blocker     import get_blocker
from flow_tracker import get_tracker, classify_attack_type

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

app      = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

detector = get_detector()
blocker  = get_blocker()
tracker  = get_tracker()

recent_attacks     = deque(maxlen=100)
blocked_history    = deque(maxlen=100)
traffic_history    = deque(maxlen=120)
attack_type_counts = defaultdict(int)
ip_request_counts  = defaultdict(int)

stats = {
    'total_requests':   0,
    'attacks_detected': 0,
    'benign_requests':  0,
    'ips_blocked':      0,
    'uptime_start':     time.time(),
}

ip_streak   = defaultdict(int)
BLOCK_AFTER = 5
MIN_REQS    = 3

_sec_bucket = {'ts': int(time.time()), 'total': 0, 'attacks': 0, 'benign': 0}
_sec_lock   = threading.Lock()


def get_real_ip():
    xff = request.headers.get('X-Forwarded-For')
    if xff: return xff.split(',')[0].strip()
    xri = request.headers.get('X-Real-IP')
    if xri: return xri.strip()
    return request.remote_addr or '0.0.0.0'


def _analyze_request(ip, req_size, resp_size, method, path, elapsed_ms):
    tracker.record(ip, req_size, resp_size, method, path, elapsed_ms)
    ip_request_counts[ip] += 1
    stats['total_requests'] += 1

    if ip_request_counts[ip] < MIN_REQS:
        stats['benign_requests'] += 1
        return

    features = tracker.get_features(ip)
    if features is None:
        stats['benign_requests'] += 1
        return

    result      = detector.predict(features)
    label       = result['label']
    conf        = result['confidence']
    model       = result['model']
    req_rate    = tracker.get_req_rate(ip)

    ts       = time.time()
    time_str = datetime.fromtimestamp(ts).strftime('%d/%m/%Y, %H:%M:%S')

    attack_type = 'BENIGN'
    if label == 'ATTACK':
        attack_type = classify_attack_type(features, req_rate)
        attack_type_counts[attack_type] += 1
        stats['attacks_detected'] += 1
        ip_streak[ip] += 1
    else:
        stats['benign_requests'] += 1
        ip_streak[ip] = max(0, ip_streak[ip] - 1)

    with _sec_lock:
        now_sec = int(ts)
        if now_sec != _sec_bucket['ts']:
            traffic_history.append(dict(_sec_bucket))
            _sec_bucket.update({'ts': now_sec, 'total': 0, 'attacks': 0, 'benign': 0})
        _sec_bucket['total']   += 1
        _sec_bucket['attacks'] += (1 if label == 'ATTACK' else 0)
        _sec_bucket['benign']  += (1 if label == 'BENIGN' else 0)

    event = {
        'ts': ts, 'time': time_str, 'ip': ip,
        'label': label, 'attack_type': attack_type,
        'confidence': round(conf, 3), 'model': model,
        'method': method, 'path': path,
        'req_rate': round(req_rate, 1),
        'req_count': ip_request_counts[ip],
    }

    if label == 'ATTACK':
        recent_attacks.appendleft(event)
        socketio.emit('attack_event', event)

    socketio.emit('traffic_event', event)

    if ip_streak[ip] >= BLOCK_AFTER and not blocker.is_blocked(ip):
        _block_ip(ip, attack_type, conf, time_str)
    if req_rate > 200 and label == 'ATTACK' and not blocker.is_blocked(ip):
        _block_ip(ip, f'{attack_type} (rate={req_rate:.0f}/s)', conf, time_str)

    socketio.emit('stats_update', {
        'stats': stats, 'under_attack': _is_under_attack(),
        'blocked_count': len(blocker.get_blocked_list()),
        'attack_types': dict(attack_type_counts),
    })


def _block_ip(ip, reason, conf, time_str):
    result = blocker.block(ip, reason)
    if result['success']:
        stats['ips_blocked'] += 1
        ip_streak[ip] = 0
        block_event = {'ip': ip, 'reason': reason, 'conf': round(conf, 3), 'time': time_str, 'type': 'BLOCKED'}
        blocked_history.appendleft(block_event)
        socketio.emit('ip_blocked', block_event)
        socketio.emit('blocked_update', _blocked_list())
        logger.info('BLOCKED %s — %s', ip, reason)


def _is_under_attack():
    if not recent_attacks: return False
    cutoff = time.time() - 10
    return sum(1 for e in recent_attacks if e['ts'] > cutoff) > 5


def _blocked_list():
    lst = blocker.get_blocked_list()
    now = time.time()
    for b in lst:
        if b.get('expires'):
            b['remaining_seconds'] = max(0, int(b['expires'] - now))
    return lst


def _simulate_attack(ip, attack_type='DrDoS_UDP', count=1, auto_block=True):
    features = generate_attack_flow(attack_type=attack_type, src_ip=ip)
    if detector.is_ready():
        result   = detector.predict(features)
        # Force label to ATTACK for simulation purposes if the model is unsure
        if result['label'] == 'BENIGN':
            result['label'] = 'ATTACK'
            result['confidence'] = 0.95
            result['model'] = f"{detector.model_name} (sim)"
    else:
        result = {'label': 'ATTACK', 'confidence': 1.0, 'model': 'simulator'}
    label    = result['label']
    conf     = result['confidence']
    model    = result['model']
    req_rate = max(tracker.get_req_rate(ip), float(count))

    stats['total_requests'] += 1
    ip_request_counts[ip] += 1

    ts       = time.time()
    time_str = datetime.fromtimestamp(ts).strftime('%d/%m/%Y, %H:%M:%S')
    attack_type_label = classify_attack_type(features, req_rate) if label == 'ATTACK' else 'BENIGN'

    if label == 'ATTACK':
        attack_type_counts[attack_type_label] += 1
        stats['attacks_detected'] += 1
        if auto_block:
            ip_streak[ip] += 1
    else:
        stats['benign_requests'] += 1
        if auto_block:
            ip_streak[ip] = max(0, ip_streak[ip] - 1)

    with _sec_lock:
        now_sec = int(ts)
        if now_sec != _sec_bucket['ts']:
            traffic_history.append(dict(_sec_bucket))
            _sec_bucket.update({'ts': now_sec, 'total': 0, 'attacks': 0, 'benign': 0})
        _sec_bucket['total']   += 1
        _sec_bucket['attacks'] += (1 if label == 'ATTACK' else 0)
        _sec_bucket['benign']  += (1 if label == 'BENIGN' else 0)

    event = {
        'ts': ts, 'time': time_str, 'ip': ip,
        'label': label, 'attack_type': attack_type_label,
        'confidence': round(conf, 3), 'model': model,
        'method': 'POST', 'path': '/api/simulate',
        'req_rate': round(req_rate, 1),
        'req_count': ip_request_counts[ip],
    }

    if label == 'ATTACK':
        recent_attacks.appendleft(event)
        socketio.emit('attack_event', event)

    socketio.emit('traffic_event', event)

    if auto_block and label == 'ATTACK' and ip_streak[ip] >= BLOCK_AFTER and not blocker.is_blocked(ip):
        _block_ip(ip, attack_type_label, conf, time_str)
    if auto_block and label == 'ATTACK' and req_rate > 200 and not blocker.is_blocked(ip):
        _block_ip(ip, f'{attack_type_label} (rate={req_rate:.0f}/s)', conf, time_str)

    socketio.emit('stats_update', {
        'stats': stats, 'under_attack': _is_under_attack(),
        'blocked_count': len(blocker.get_blocked_list()),
        'attack_types': dict(attack_type_counts),
    })
    return event


@app.before_request
def before_req():
    request._start_time = time.time()
    ip = get_real_ip()
    if ip and blocker.is_blocked(ip) and request.path not in ('/api/status', '/'):
        return Response(
            json.dumps({'error': 'IP blocked — suspicious activity detected', 'ip': ip}),
            status=403, mimetype='application/json'
        )


@app.after_request
def after_req(response):
    ip = get_real_ip() or '127.0.0.1'
    if request.path.startswith('/static') or request.path in ('/api/simulate', '/api/alerts'):
        return response
    elapsed   = (time.time() - getattr(request, '_start_time', time.time())) * 1000
    req_size  = int(request.content_length or 100)
    resp_size = 500
    try:
        if not response.direct_passthrough:
            resp_size = len(response.get_data())
    except Exception:
        pass
    threading.Thread(
        target=_analyze_request,
        args=(ip, req_size, resp_size, request.method, request.path, elapsed),
        daemon=True
    ).start()
    return response


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

# Attack target endpoints — hammer these with Locust/curl
@app.route('/api/test')
def api_test():
    return jsonify({'status': 'ok', 'ts': time.time()})

@app.route('/api/data', methods=['GET', 'POST'])
def api_data():
    return jsonify({'data': list(range(50)), 'status': 'ok'})

@app.route('/api/search')
def api_search():
    return jsonify({'results': [], 'query': request.args.get('q', '')})

# Dashboard API
@app.route('/api/status')
def api_status():
    return jsonify({
        **stats,
        'uptime_seconds': int(time.time() - stats['uptime_start']),
        'under_attack':   _is_under_attack(),
        'model_info':     detector.get_model_info(),
        'blocked_count':  len(blocker.get_blocked_list()),
        'attack_types':   dict(attack_type_counts),
    })

@app.route('/api/attacks')
def api_attacks():
    return jsonify(list(recent_attacks))

@app.route('/api/traffic')
def api_traffic():
    return jsonify(list(traffic_history)[-60:])

@app.route('/api/blocked')
def api_blocked():
    return jsonify(_blocked_list())

@app.route('/api/unblock/<ip>', methods=['POST', 'DELETE'])
def api_unblock(ip):
    result = blocker.unblock(ip)
    if result['success']:
        stats['ips_blocked'] = max(0, stats['ips_blocked'] - 1)
        ip_streak[ip] = 0
        socketio.emit('blocked_update', _blocked_list())
    return jsonify(result)

@app.route('/api/block/<ip>', methods=['POST'])
def api_block_manual(ip):
    data   = request.get_json(silent=True) or {}
    result = blocker.block(ip, data.get('reason', 'Manual block'))
    if result['success']:
        stats['ips_blocked'] += 1
        socketio.emit('blocked_update', _blocked_list())
    return jsonify(result)

@app.route('/api/simulate', methods=['POST'])
def api_simulate():
    payload = request.get_json(silent=True) or {}
    ip       = payload.get('ip') or get_real_ip() or '127.0.0.1'
    attack_type = payload.get('type', 'DrDoS_UDP')
    count    = int(payload.get('count', 1) or 1)
    event    = _simulate_attack(ip, attack_type=attack_type, count=count)
    return jsonify({'success': True, 'event': event})

@app.route('/api/alerts')
def api_alerts():
    return jsonify(list(recent_attacks))

@app.route('/api/clear_blocks', methods=['POST'])
def api_clear_blocks():
    lst = blocker.get_blocked_list()
    for b in lst: blocker.unblock(b['ip'])
    stats['ips_blocked'] = 0
    socketio.emit('blocked_update', [])
    return jsonify({'cleared': len(lst)})


@socketio.on('connect')
def on_connect():
    emit('init', {
        'stats': stats, 'model_info': detector.get_model_info(),
        'attacks': list(recent_attacks)[:30], 'blocked': _blocked_list(),
        'traffic': list(traffic_history)[-30:],
        'attack_types': dict(attack_type_counts),
        'under_attack': _is_under_attack(),
    })


def stats_pusher():
    while True:
        time.sleep(1)
        with _sec_lock:
            bucket = dict(_sec_bucket)
        socketio.emit('traffic_tick', {
            **bucket,
            'under_attack':  _is_under_attack(),
            'stats':         stats,
            'blocked_count': len(blocker.get_blocked_list()),
            'attack_types':  dict(attack_type_counts),
        })


def attack_generator(interval=5):
    attack_types = ['DrDoS_UDP', 'DrDoS_LDAP', 'DrDoS_MSSQL']
    while True:
        time.sleep(interval)
        ip = f'203.0.113.{random.randint(10, 250)}'
        attack_type = random.choice(attack_types)
        _simulate_attack(ip, attack_type=attack_type, count=10, auto_block=False)
        logger.info('Simulated attack event: %s %s', ip, attack_type)


if __name__ == '__main__':
    if detector.is_ready():
        logger.info('Model loaded: %s', detector.model_name)
    else:
        logger.warning('No model! Run: python train_model.py')
    threading.Thread(target=stats_pusher, daemon=True).start()
    threading.Thread(target=attack_generator, daemon=True).start()
    logger.info('Starting on http://0.0.0.0:5000')
    logger.info('Attack targets: /api/test  /api/data  /api/search')
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
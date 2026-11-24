"""Single-project OpenAI-compatible relay. No request or provider bodies in SQLite.

LTZY_UPSTREAMS is an ordered JSON array of HTTPS lane definitions (see README).
With no configuration only the explicitly named local/echo test model exists.
"""
import hashlib
import http.client
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from urllib.parse import urlsplit

MILLION = 1_000_000
MAX_BODY = 1024 * 1024
LANES = ()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def encode(obj):
    return json.dumps(obj, separators=(",", ":"), allow_nan=False).encode()


def valid_id(value):
    return isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}", value)


def configuration():
    raw = os.environ.get("LTZY_UPSTREAMS")
    if raw is None:
        return (dict(id="local-test", model="local/echo", kind="local-test", context=8192,
                     input_price="0.5", output_price="1.5", price_version="test-v1"),)
    try:
        lanes = json.loads(raw)
        if not isinstance(lanes, list) or len(lanes) > 128:
            raise ValueError
        ids = set()
        for lane in lanes:
            for field in ("id", "model", "upstream_model", "price_version"):
                if not valid_id(lane[field]):
                    raise ValueError
            if lane['id'] in ids or lane['model'] == 'local/echo':
                raise ValueError
            ids.add(lane['id'])
            url = urlsplit(lane['base_url'])
            if (url.scheme != 'https' or not url.hostname or url.username is not None or
                    url.password is not None or url.query or url.fragment or url.port == 0):
                raise ValueError
            if not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', lane['api_key_env']):
                raise ValueError
            if not os.environ.get(lane['api_key_env']):
                raise ValueError
            if type(lane['context']) is not int or not 1 <= lane['context'] <= 10_000_000:
                raise ValueError
            for field in ('input_price', 'output_price'):
                price = Decimal(str(lane[field]))
                if not price.is_finite() or not 0 <= price <= MILLION or price.as_tuple().exponent < -6:
                    raise ValueError
                lane[field] = str(price)
            lane['kind'] = 'https'
    except (ValueError, KeyError, TypeError, InvalidOperation):
        raise ValueError('Invalid LTZY_UPSTREAMS configuration or missing upstream credential') from None
    return tuple(lanes)


def init(db):
    global LANES
    LANES = configuration()
    db.execute('''CREATE TABLE IF NOT EXISTS receipts(
        id TEXT PRIMARY KEY, createdAt TEXT NOT NULL, model TEXT NOT NULL, lane TEXT,
        keyId TEXT NOT NULL, status TEXT NOT NULL, settlement TEXT NOT NULL,
        inputTokens INTEGER, outputTokens INTEGER, cost INTEGER, reserved INTEGER NOT NULL,
        latencyMs INTEGER, trace TEXT NOT NULL, price TEXT NOT NULL)''')
    # Startup recovery for a single server process: never release uncertain spend silently.
    db.execute("UPDATE receipts SET status='interrupted',settlement='pending' WHERE status='running'")
    db.commit()


def enabled_lanes(db):
    settings = dict(db.execute('SELECT id,enabled FROM lane_settings'))
    return [(lane, bool(settings.get(lane['id'], 1))) for lane in LANES]


def price_of(lane):
    return dict(input=lane['input_price'], output=lane['output_price'],
                currency='USD', version=lane['price_version'])


def micros(price, inp, out):
    # USD per million tokens numerically equals micro-USD per token. Round once.
    return int((Decimal(price['input']) * inp + Decimal(price['output']) * out).to_integral_value(rounding=ROUND_CEILING))


def funds(db, user_id=None):
    """Per-user balance in production; the historic global budget as the None fallback."""
    if user_id is None:
        limit, = db.execute('SELECT budget_micros FROM settings WHERE id=1').fetchone()
        spent, held = db.execute('SELECT coalesce(sum(cost),0),coalesce(sum(reserved),0) FROM receipts').fetchone()
        return limit, spent, held
    balance, = db.execute('SELECT balance_micros FROM users WHERE id=?', (user_id,)).fetchone()
    spent, held = db.execute('SELECT coalesce(sum(cost),0),coalesce(sum(reserved),0) FROM receipts WHERE user_id=?',
                             (user_id,)).fetchone()
    return balance, spent, held


def receipt(row):
    r = dict(row)
    r['trace'] = json.loads(r['trace'])
    r['price'] = json.loads(r['price'])
    for k in ('input', 'output'):
        r['price'][k] = float(r['price'][k])
    if r['cost'] is not None:
        r['cost'] /= MILLION
    r['reserved'] /= MILLION
    return r


def csv_rows(db, user_id=None):
    sql = 'SELECT * FROM receipts ORDER BY rowid DESC' if not user_id else \
        'SELECT * FROM receipts WHERE user_id=? ORDER BY rowid DESC'
    for row in db.execute(sql, (user_id,) if user_id else ()):
        r = receipt(row)
        del r['trace']
        r.update({'price_' + k: v for k, v in r.pop('price').items()})
        yield r


def snapshot(db, public=False, user_id=None):
    models, lanes = {}, []
    for idx, (lane, enabled) in enumerate(enabled_lanes(db), 1):
        mid = lane['model']
        lanes.append(dict(id=lane['id'], model=mid, enabled=enabled, priority=idx, kind=lane['kind']))
        if mid not in models or not models[mid]['enabled'] and enabled:
            models[mid] = dict(id=mid, provider=lane['id'], kind=lane['kind'], enabled=enabled,
                               inputPrice=float(lane['input_price']), outputPrice=float(lane['output_price']),
                               context=lane['context'], capabilities=['chat', 'stream'])
    scope, args = ('WHERE user_id=?', (user_id,)) if user_id else ('', ())
    total, ok, failed = db.execute(f"SELECT count(*),count(CASE WHEN status='success' THEN 1 END),count(CASE WHEN status IN ('failed','interrupted') THEN 1 END) FROM receipts {scope}", args).fetchone()
    result = dict(models=list(models.values()), status=dict(updatedAt=now(), requests=total, successful=ok,
                  failed=failed, enabledLanes=sum(x['enabled'] for x in lanes), totalLanes=len(lanes)))
    if not public:
        limit, spent, held = funds(db, user_id)
        usage = [dict(model=m, requests=n, inputTokens=i, outputTokens=o, cost=c/MILLION) for m,n,i,o,c in
                 db.execute(f'SELECT model,count(*),sum(inputTokens),sum(outputTokens),coalesce(sum(cost),0) FROM receipts {scope} GROUP BY model ORDER BY model', args)]
        pending_sql = "SELECT * FROM receipts WHERE settlement='pending' ORDER BY rowid" if not user_id else \
            "SELECT * FROM receipts WHERE user_id=? AND settlement='pending' ORDER BY rowid"
        result['pending'] = [receipt(r) for r in db.execute(pending_sql, args)]
        result.update(lanes=lanes, usage=usage,
                      requests=[receipt(r) for r in db.execute(f'SELECT * FROM receipts {scope} ORDER BY rowid DESC LIMIT 200', args)],
                      budget=dict(limit=limit/MILLION, spent=spent/MILLION, reserved=held/MILLION, remaining=(limit-spent-held)/MILLION))
    return result


def reconcile(db, rid, inp, out):
    row = db.execute("SELECT * FROM receipts WHERE id=? AND settlement='pending'", (rid,)).fetchone()
    if not row or not all(type(t) is int and 0 <= t <= 10_000_000 for t in (inp,out)):
        raise ValueError('Invalid receipt or usage')
    cost = micros(json.loads(row['price']), inp, out)
    limit, spent, held = funds(db, row['user_id'])
    if cost > limit - spent - held + row['reserved']:
        raise ValueError('Top up the account balance before settlement')
    trace = json.loads(row['trace']) + [dict(event='reconciled', lane=row['lane'], ms=row['latencyMs'])]
    db.execute("UPDATE receipts SET settlement='settled',inputTokens=?,outputTokens=?,cost=?,reserved=0,trace=? WHERE id=?", (inp,out,cost,json.dumps(trace),rid))


class Problem(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


class Rejected(Exception):
    """Provider explicitly rejected the request, before any downstream headers."""
    def __init__(self, status):
        self.status = status


def authenticate(h, db):
    header = h.headers.get('Authorization', '').split()
    if len(header) == 2 and header[0].lower() == 'bearer':
        row = db.execute('''SELECT k.id,k.scope,u.id AS uid,u.status
                            FROM api_keys k JOIN users u ON u.id=k.user_id
                            WHERE k.digest=? AND k.revoked=0''',
                         (hashlib.sha256(header[1].encode()).hexdigest(),)).fetchone()
        if row:
            if row['status'] != 'active':
                raise Problem(403, 'account_disabled')
            if h.command != 'GET' and row['scope'] != 'chat':
                raise Problem(403, 'insufficient_scope')
            return row['id'], row['uid']
    raise Problem(401, 'invalid_api_key')


# Fields the relay bills and routes on. Everything else in the OpenAI request
# shape is forwarded to the upstream unchanged instead of being rejected.
CONTROL_FIELDS = frozenset({'messages','model','max_tokens','temperature','stream','stream_options'})
PASSTHROUGH_FIELDS = frozenset({
    'top_p','frequency_penalty','presence_penalty','seed','user','n','stop',
    'logprobs','top_logprobs','logit_bias','response_format','tools',
    'tool_choice','parallel_tool_calls','reasoning_effort','metadata','store',
})
MESSAGE_ROLES = frozenset({'system','developer','user','assistant','tool'})
MESSAGE_FIELDS = frozenset({'role','content','name','tool_calls','tool_call_id'})
MAX_CONTENT_PARTS = 512
MAX_TOOLS = 64


def _number(value, lo, hi):
    return type(value) in (int, float) and lo <= value <= hi


def _valid_tools(value):
    if not isinstance(value, list) or len(value) > MAX_TOOLS:
        return False
    for tool in value:
        fn = tool.get('function') if isinstance(tool, dict) and tool.get('type') == 'function' else None
        if not isinstance(fn, dict):
            return False
        if not isinstance(fn.get('name'), str) or not valid_id(fn['name']):
            return False
        if 'description' in fn and not isinstance(fn['description'], str):
            return False
        if 'parameters' in fn and not isinstance(fn['parameters'], dict):
            return False
        if 'strict' in fn and type(fn['strict']) is not bool:
            return False
    return True


def _valid_tool_choice(value):
    if value in ('none', 'auto', 'required'):
        return True
    if isinstance(value, dict) and value.get('type') == 'function':
        fn = value.get('function')
        return isinstance(fn, dict) and isinstance(fn.get('name'), str) and valid_id(fn['name'])
    return False


def _valid_response_format(value):
    if not isinstance(value, dict) or set(value) - {'type', 'json_schema'}:
        return False
    if value.get('type') == 'text':
        return True
    if value.get('type') == 'json_object':
        return 'json_schema' not in value or isinstance(value['json_schema'], dict)
    return False


def check_message(m):
    """Validate one chat message, accepting the OpenAI shapes the relay forwards."""
    if not isinstance(m, dict) or set(m) - MESSAGE_FIELDS:
        raise ValueError
    if 'role' not in m or 'content' not in m or m['role'] not in MESSAGE_ROLES:
        raise ValueError
    if m['role'] == 'tool' and (not isinstance(m.get('tool_call_id'), str) or not m.get('tool_call_id')):
        raise ValueError
    if m['role'] == 'assistant' and 'tool_calls' in m and not isinstance(m['tool_calls'], list):
        raise ValueError
    if 'name' in m and not isinstance(m['name'], str):
        raise ValueError
    content = m['content']
    if isinstance(content, str):
        content.encode('utf-8')
        return
    if not isinstance(content, list) or len(content) > MAX_CONTENT_PARTS:
        raise ValueError
    for part in content:
        if not isinstance(part, dict) or part.get('type') not in ('text', 'image_url'):
            raise ValueError
        if part['type'] == 'text':
            if not isinstance(part.get('text'), str):
                raise ValueError
            part['text'].encode('utf-8')
        elif not isinstance(part.get('image_url'), dict):
            raise ValueError


def message_text(m):
    """Text projection of a message: what a single-project relay bills and echoes."""
    content = m['content']
    if isinstance(content, str):
        return content
    return ''.join(part['text'] for part in content
                   if isinstance(part, dict) and part.get('type') == 'text'
                   and isinstance(part.get('text'), str))

def payload(h):
    try:
        lengths = h.headers.get_all('Content-Length', [])
        if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                or len(lengths[0]) > 8 or h.headers.get('Transfer-Encoding')):
            raise ValueError
        size = int(lengths[0])
        if size > MAX_BODY:
            raise Problem(413, 'request_too_large')
        if size <= 0 or h.headers.get('Transfer-Encoding'):
            raise ValueError
        p = json.loads(h.rfile.read(size).decode('utf-8'))
        if not isinstance(p, dict) or set(p) - CONTROL_FIELDS - PASSTHROUGH_FIELDS:
            raise ValueError
        if not valid_id(p['model']) or not isinstance(p['messages'], list) or not 1 <= len(p['messages']) <= 256:
            raise ValueError
        for m in p['messages']:
            check_message(m)
        if 'top_p' in p and not _number(p['top_p'], 0, 1):
            raise ValueError
        for field in ('frequency_penalty', 'presence_penalty'):
            if field in p and not _number(p[field], -2, 2):
                raise ValueError
        if 'seed' in p and (type(p['seed']) is not int or not 0 <= p['seed'] <= 2147483647):
            raise ValueError
        if 'user' in p and (not isinstance(p['user'], str) or not 1 <= len(p['user']) <= 256):
            raise ValueError
        if 'n' in p and (type(p['n']) is not int or not 1 <= p['n'] <= 8):
            raise ValueError
        if 'stop' in p and not (p['stop'] is None or isinstance(p['stop'], str)
                               or (isinstance(p['stop'], list) and len(p['stop']) <= 4
                                   and all(isinstance(x, str) for x in p['stop']))):
            raise ValueError
        if 'logprobs' in p and type(p['logprobs']) is not bool:
            raise ValueError
        if 'top_logprobs' in p and (type(p['top_logprobs']) is not int or not 0 <= p['top_logprobs'] <= 20):
            raise ValueError
        if 'parallel_tool_calls' in p and type(p['parallel_tool_calls']) is not bool:
            raise ValueError
        if 'store' in p and type(p['store']) is not bool:
            raise ValueError
        if 'tools' in p and not _valid_tools(p['tools']):
            raise ValueError
        if 'tool_choice' in p and not _valid_tool_choice(p['tool_choice']):
            raise ValueError
        if 'reasoning_effort' in p and p['reasoning_effort'] not in ('low', 'medium', 'high'):
            raise ValueError
        if 'response_format' in p and not _valid_response_format(p['response_format']):
            raise ValueError
        if 'logit_bias' in p and not (isinstance(p['logit_bias'], dict)
                and all(re.fullmatch(r'-?[0-9]+', k) and type(v) is int and -100 <= v <= 100
                        for k, v in p['logit_bias'].items())):
            raise ValueError
        if 'metadata' in p and not (isinstance(p['metadata'], dict)
                and all(isinstance(k, str) and isinstance(v, str) for k, v in p['metadata'].items())):
            raise ValueError
        if type(p.setdefault('max_tokens',256)) is not int or not 1 <= p['max_tokens'] <= 65536:
            raise ValueError
        if type(p.setdefault('stream',False)) is not bool:
            raise ValueError
        t = p.get('temperature',1)
        if type(t) not in (int,float) or not 0 <= t <= 2:
            raise ValueError
        if 'stream_options' in p and (not p['stream'] or p['stream_options'] not in ({'include_usage':True},{'include_usage':False})):
            raise ValueError
        return p
    except (TypeError,ValueError,KeyError,RecursionError):
        raise Problem(400,'invalid_chat_request') from None


def headers(h,status,kind,rid,length=None):
    h.send_response(status)
    h.send_header('Content-Type',kind)
    h.send_header('Cache-Control','no-store')
    h.send_header('X-Request-Id',rid)
    if length is not None:
        h.send_header('Content-Length',str(length))
    h.send_header('Connection','close')
    h.close_connection = True
    h.end_headers()


def send_json(h,status,obj,rid):
    data = encode(obj)
    headers(h,status,'application/json; charset=utf-8',rid,len(data))
    h.wfile.write(data)


def local(lane,p,rid):
    # This adapter's documented token unit is one Unicode character, not a vendor tokenizer.
    prompt = sum(len(message_text(m))+1 for m in p['messages'])
    text = ('Local test: '+message_text(p['messages'][-1]))[:p['max_tokens']]
    use = dict(prompt_tokens=prompt, completion_tokens=len(text), total_tokens=prompt+len(text))
    base = dict(id=rid,created=int(time.time()),model=p['model'])
    if p['stream']:
        base['object']='chat.completion.chunk'
        for i in range(0,len(text),12):
            yield dict(base,choices=[dict(index=0,delta={'content':text[i:i+12]},finish_reason=None)])
        yield dict(base,choices=[dict(index=0,delta={},finish_reason='stop')])
        yield dict(base,choices=[],usage=use)
    else:
        yield dict(base,object='chat.completion',usage=use,choices=[dict(index=0,message=dict(role='assistant',content=text),finish_reason='stop')])


def sse_events(response):
    fields, size, total = [], 0, 0
    while True:
        line = response.readline(MAX_BODY+1)
        total += len(line)
        size += len(line)
        if not line or size > MAX_BODY or total > 32*MAX_BODY:
            raise ValueError('incomplete or oversized stream')
        line = line.rstrip(b'\r\n')
        if not line:
            if fields:
                data = b'\n'.join(fields)
                if data == b'[DONE]':
                    return
                yield json.loads(data)
            fields, size = [], 0
        elif line.startswith(b'data:'):
            fields.append(line[5:].lstrip(b' '))


def upstream(lane,p,rid):
    if lane['kind']=='local-test':
        yield from local(lane,p,rid)
        return
    url = urlsplit(lane['base_url'])
    body = dict(p,model=lane['upstream_model'])
    if p['stream']:
        body['stream_options']={'include_usage':True}
    # HTTPSConnection verifies certificates and never follows redirects with credentials.
    with closing(http.client.HTTPSConnection(url.hostname,url.port,timeout=30)) as conn:
        conn.request('POST',url.path.rstrip('/')+'/chat/completions',encode(body),
                     {'Content-Type':'application/json','Authorization':'Bearer '+os.environ[lane['api_key_env']]})
        with conn.getresponse() as res:
            if res.status != 200:
                raise Rejected(res.status)
            if p['stream']:
                if res.getheader('Content-Type','').split(';')[0].strip().lower() != 'text/event-stream':
                    raise ValueError('not a stream')
                yield from sse_events(res)
            else:
                data = res.read(8*MAX_BODY+1)
                if len(data)>8*MAX_BODY:
                    raise ValueError('oversized response')
                yield json.loads(data)


def reserve(db,h,p,rid):
    db.execute('BEGIN IMMEDIATE')
    with db:
        key,uid = authenticate(h,db)  # Linearize revocation and balance admission together.
        matches = [(l,on) for l,on in enabled_lanes(db) if l['model']==p['model']]
        if not matches:
            raise Problem(404,'model_not_found')
        candidates = [l for l,on in matches if on][:2]
        if not candidates:
            raise Problem(503,'no_enabled_lane')
        candidates = [l for l in candidates if p['max_tokens'] <= l['context'] and
                      (l['kind']!='local-test' or sum(len(message_text(m))+1 for m in p['messages'])+p['max_tokens']<=l['context'])]
        if not candidates:
            raise Problem(400,'context_limit')
        # No tokenizer guessing for HTTPS lanes: hold full configured input context plus output cap.
        local_input=sum(len(message_text(m))+1 for m in p['messages'])
        amount=max(micros(price_of(l), local_input if l['kind']=='local-test' else l['context'],p['max_tokens']) for l in candidates)
        limit,spent,held=funds(db,uid)
        if amount > limit-spent-held:
            raise Problem(402,'insufficient_balance')
        first=candidates[0]
        db.execute('''INSERT INTO receipts(id,createdAt,model,lane,keyId,status,settlement,reserved,trace,price,user_id)
                      VALUES(?,?,?,?,?,'running','reserved',?,'[]',?,?)''',
                   (rid,now(),p['model'],first['id'],key,amount,json.dumps(price_of(first)),uid))
    return candidates,amount


def chat(h,db,rid,p):
    lanes,held=reserve(db,h,p,rid)
    start=time.monotonic()
    trace=[]
    started=False
    usage=None
    status,settlement='failed','void'
    cost=None
    lane=lanes[0]

    def note(event):
        trace.append(dict(lane=lane['id'],event=event,ms=int((time.monotonic()-start)*1000)))

    note('reserved')
    try:
        for idx,lane in enumerate(lanes):
            note('attempt')
            price=price_of(lane)
            with db:
                db.execute('UPDATE receipts SET lane=?,trace=?,price=? WHERE id=?',
                           (lane['id'],json.dumps(trace),json.dumps(price),rid))
            try:
                with closing(upstream(lane,p,rid)) as events:
                    seen=False
                    for obj in events:
                        if not isinstance(obj,dict) or 'error' in obj or not isinstance(obj.get('choices'),list):
                            raise ValueError('invalid response')
                        obj['model']=p['model']
                        u=obj.get('usage')
                        if isinstance(u,dict):
                            pair=(u.get('prompt_tokens'),u.get('completion_tokens'))
                            if all(type(x) is int and 0<=x<=10_000_000 for x in pair):
                                usage=pair
                        if p['stream'] and not obj['choices'] and not p.get('stream_options',{}).get('include_usage'):
                            continue
                        data=encode(obj)
                        if not started:
                            started=True  # Includes headers and disconnects while writing them.
                            note('first_byte')
                            headers(h,200,'text/event-stream' if p['stream'] else 'application/json',rid,None if p['stream'] else len(data))
                        h.wfile.write(b'data: '+data+b'\n\n' if p['stream'] else data)
                        h.wfile.flush()
                        seen=True
                    if not seen:
                        raise ValueError('empty response')
                status='success'
                if usage and micros(price,*usage)<=held:
                    settlement='settled'
                    cost=micros(price,*usage)
                else:
                    settlement='pending'
                if p['stream']:
                    h.wfile.write(b'data: [DONE]\n\n')
                break
            except Rejected as exc:
                note('http_'+str(exc.status))
                if idx+1<len(lanes) and not started and exc.status in (429,502,503,504):
                    continue
                raise Problem(502,'upstream_rejected') from None
            except (ValueError,OSError,http.client.HTTPException,RecursionError,KeyError):
                note('incomplete_response')
                settlement='pending'  # Provider may have billed; keep reservation until reconciled.
                cost=None
                status='interrupted' if started else 'failed'
                if not started:
                    raise Problem(502,'upstream_unavailable') from None
                if p['stream']:
                    try:
                        h.wfile.write(b'data: {"error":{"code":"stream_interrupted"}}\n\n')
                    except OSError:
                        pass
                break
    finally:
        note(settlement)
        with db:
            db.execute('''UPDATE receipts SET status=?,settlement=?,inputTokens=?,outputTokens=?,cost=?,
                       reserved=?,latencyMs=?,trace=? WHERE id=? AND status='running' ''',
                       (status,settlement,*(usage or (None,None)),cost,held if settlement=='pending' else 0,
                        trace[-1]['ms'],json.dumps(trace),rid))


def dispatch(handler,db_path):
    rid='req_'+uuid.uuid4().hex
    with closing(sqlite3.connect(db_path,timeout=10)) as db:
        db.row_factory=sqlite3.Row
        try:
            authenticate(handler,db)
            path=handler.path.split('?')[0]
            if path=='/v1/models' and handler.command=='GET':
                items=[dict(id=m['id'],object='model',created=0,owned_by=m['provider'])
                       for m in snapshot(db,public=True)['models'] if m['enabled']]
                send_json(handler,200,dict(object='list',data=items),rid)
            elif path=='/v1/chat/completions' and handler.command=='POST':
                chat(handler,db,rid,payload(handler))
            else:
                raise Problem(404,'not_found')
        except Problem as exc:
            send_json(handler,exc.status,dict(error=dict(message=exc.code,code=exc.code,type='gateway_error')),rid)
    return True

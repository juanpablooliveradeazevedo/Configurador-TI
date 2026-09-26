"""Escaped, server-rendered forms; no JS dependency or database access."""
from html import escape
from .messages import msg
from fleet_protocol.contracts import AGENT_VERSION,CATALOG

def esc(v): return escape(str(v),quote=True)
def hidden(key,value): return f'<input type="hidden" name="{esc(key)}" value="{esc(value)}">'
def field(key,kind='text',value='',required=True):
    extra=' required' if required else ''
    return f'<label>{esc(msg(key))}<input type="{kind}" name="{esc(key)}" value="{esc(value)}" maxlength="256"{extra}></label>'
def select(key,rows,blank=False):
    out=f'<label>{esc(msg(key))}<select name="{esc(key)}">'
    if blank: out+='<option value="">—</option>'
    for value,title in rows: out+=f'<option value="{esc(value)}">{esc(title)}</option>'
    return out+'</select></label>'
def form(csrf,op,body,button='save'):
    return '<form method="post" action="/">'+hidden('csrf',csrf)+hidden('operation',op)+body+f'<button>{esc(msg(button))}</button></form>'
def value(v):
    if v is None: return '—'
    if isinstance(v,bool): return esc(msg('yes' if v else 'no'))
    if isinstance(v,dict): return '<dl>'+''.join(f'<dt>{esc(msg(k))}</dt><dd>{value(x)}</dd>' for k,x in v.items())+'</dl>'
    if isinstance(v,list): return ', '.join(value(x) for x in v) or '—'
    return esc(v)
def table(rows,columns):
    if not rows: return '<p class="muted">'+msg('empty')+'</p>'
    out='<div class="scroll"><table><thead><tr>'+''.join('<th>'+esc(msg(c))+'</th>' for c in columns)+'</tr></thead><tbody>'
    for row in rows:
        out+='<tr>'+''.join('<td>'+value(row.get(c))+'</td>' for c in columns)+'</tr>'
    return out+'</tbody></table></div>'
def options(rows): return [(r['id'],(r.get('display_name') or r.get('label') or r.get('login') or r.get('plan_id') or r['id'])+' · '+r['id'][:8]) for r in rows]
def page(csrf,snapshot=None,notice='',error='',preview=None,special=None,audit=None):
    body='<header><div><strong>'+msg('title')+'</strong><span>'+msg('subtitle')+'</span></div>'
    if snapshot: body+=form(csrf,'logout','', 'logout')
    body+='</header><main>'
    if notice: body+='<p role="status" class="notice">'+esc(notice)+'</p>'
    if error: body+='<p role="alert" class="error">'+esc(msg('error')+error)+'</p>'
    if not snapshot:
        body+='<section class="login"><h1>'+msg('login')+'</h1><p>'+msg('note')+'</p>'+form(csrf,'login',field('username')+field('password','password'),'login')+'</section>'
    else:
        s=snapshot;role=s['principal']['role'];admin=role in ('OWNER','TENANT_ADMIN');owner=role=='OWNER';mutable=role!='VIEWER'
        body+='<p class="muted">'+msg('note')+' • '+esc(role)+'</p><nav>'+''.join(f'<a href="#{k}">{msg(k)}</a>' for k in ('tenant','user','license','fleet_agent','fleet_command','session','audit'))+'<a href="/">'+msg('refresh')+'</a></nav>'
        body+='<div class="cards">'+''.join(f'<article><span>{msg(k)}</span><strong>{s["counts"][k]}</strong></article>' for k in ('tenant','user','license','seat','fleet_agent','fleet_command'))+'</div>'
        alerts=[{'label':r['label'],'status':r['status'],'summary':r['summary']} for r in s['fleet_agent'] if r['status']!='ONLINE' or (r['summary'] or {}).get('posture',{}).get('assessment')!='OK']
        body+='<section><h2>'+msg('alerts')+'</h2><p>'+msg('alert_note')+'</p>'+table(alerts,['label','status','summary'])+'</section>'
        if special:
            for k in ('enrollment_code','authorization_code'):
                if k in special: body+='<section class="notice"><h2>'+msg(k)+'</h2><code>'+esc(special[k])+'</code></section>'
        if preview:
            body+='<section class="notice"><h2>'+msg('prepare')+'</h2>'+value(preview)+'<p>'+msg('prepare_note')+'</p>'+form(csrf,'send','<label><input type="checkbox" name="confirmed" value="yes" required>'+msg('confirm')+'</label>','send')+'</section>'
        body+='<section id="tenant"><h2>'+msg('tenant')+'</h2>'+table(s['tenant'],['label','id','state'])
        if owner: body+=form(csrf,'create_tenant',field('label'),'create')+form(csrf,'suspend_tenant',select('id',options(s['tenant'])),'suspend')
        body+='</section><section id="user"><h2>'+msg('user')+'</h2>'+table(s['user'],['display_name','login','id','tenant_id','role','state'])
        if admin:
            roles=['TECHNICIAN','VIEWER']+(['TENANT_ADMIN'] if owner else [])
            body+=form(csrf,'create_user',select('tenant_id',options(s['tenant']))+field('display_name')+field('login')+field('password','password')+select('role',[(r,r) for r in roles]),'create')
            body+=form(csrf,'suspend_user',select('id',options(s['user'])),'suspend')+form(csrf,'force_logout',select('user_id',options(s['user'])),'force_logout')+form(csrf,'login_code',select('user_id',options(s['user'])),'qa_code')
            if owner: body+=form(csrf,'role',select('user_id',options(s['user']))+select('role',[(r,r) for r in roles]))
        body+='</section><section id="license"><h2>'+msg('license')+'</h2>'+table(s['license'],['id','tenant_id','plan_id','state','expires'])
        if owner:
            body+=form(csrf,'create_license',select('tenant_id',options(s['tenant']))+select('plan_id',options(s['plan'])),'create')
            body+=form(csrf,'suspend_license',select('id',options(s['license'])),'suspend')+form(csrf,'revoke_license',select('id',options(s['license'])),'revoke')
        body+='<h3>'+msg('seat')+'</h3>'+table(s['seat'],['id','user_id','license_id','state'])
        if admin: body+=form(csrf,'assign_seat',select('user_id',options(s['user']))+select('license_id',options(s['license'])),'assign')+form(csrf,'release_seat',select('id',options(s['seat'])),'release')
        if owner:
            body+='<details><summary>'+msg('plan')+'</summary>'+table(s['plan'],['id','seat_limit','device_limit','features','minimum_supported_version'])
            body+=form(csrf,'plan_policy',select('id',options(s['plan']))+field('seat_limit','number',10)+field('device_limit','number',2)+field('validity_seconds','number',2592000)+field('offline_seconds','number',86400)+field('minimum_supported_version','text','5.0')+'<label><input type="checkbox" name="fleet_enabled" value="yes">'+msg('fleet_enabled')+'</label>')+'</details>'
        body+='</section><section id="fleet_agent"><h2>'+msg('fleet_agent')+'</h2>'+table(s['fleet_agent'],['label','id','status','last_seen','agent_version','capabilities','enrollment','tags','assigned_technician','summary','policy_version','drift_state'])
        if admin:
            body+=form(csrf,'invite',select('user_id',options(s['user']))+field('label'),'invite')
            body+=form(csrf,'suspend_agent',select('id',options(s['fleet_agent'])),'suspend')+form(csrf,'revoke_device',select('id',options(s['device'])),'revoke')
            body+=form(csrf,'agent_tags',select('id',options(s['fleet_agent']))+field('tags',required=False)+select('assigned_technician',options([u for u in s['user'] if u['role'] in ('TECHNICIAN','TENANT_ADMIN')]),True))
        body+='<details><summary>'+msg('device')+'</summary>'+table(s['device'],['id','user_id','state','last_seen'])+'</details></section>'
        body+='<section id="fleet_command"><h2>'+msg('fleet_command')+'</h2>'
        if mutable:
            body+=form(csrf,'prepare',select('device_id',options(s['fleet_agent']))+select('action_id',[(k,k) for k in s['catalog']])+select('interval_seconds',[(str(n),str(n)) for n in (30,60,120,300)]),'prepare')
        body+=table(s['fleet_command'],['id','device_id','action_id','state','actor','issued_at'])
        for c in s['fleet_command']:
            body+='<details><summary>'+msg('proof')+' · '+esc(c['id'])+'</summary>'+value(c.get('proof'))
            if mutable and c['state'] not in ('SUCCEEDED','FAILED','CANCELLED','EXPIRED'): body+=form(csrf,'cancel',hidden('id',c['id']),'cancel')
            body+='</details>'
        body+='</section><section id="session"><h2>'+msg('session')+'</h2>'+table(s['session'],['id','user_id','device_id','state','expires'])+'<h3>'+msg('web_session')+'</h3>'+table(s['web_session'],['id','account_id','expires'])
        if admin: body+=form(csrf,'revoke_session',select('id',options(s['session']+s['web_session'])),'revoke')
        body+='</section><section id="audit"><h2>'+msg('audit')+'</h2>'+form(csrf,'audit',select('tenant',options(s['tenant']),True)+field('actor',required=False)+field('action',required=False)+field('result',required=False),'filter')+table(audit if audit is not None else s['audit'],['time','tenant_id','actor','action','target','result','correlation_id'])+'</section>'
        off=s['offset'];body+='<footer><p>'+msg('retention_note')+'</p>'
        if off: body+=form(csrf,'page',hidden('offset',max(0,off-20)),'previous')
        if any(count>off+20 for count in s['counts'].values()): body+=form(csrf,'page',hidden('offset',off+20),'next')
        body+='</footer>'
    return ('<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+msg('title')+'</title><link rel="stylesheet" href="/style.css"></head><body>'+body+'</main></body></html>').encode()

CSS=b'''*{box-sizing:border-box}body{margin:0;background:#f1f5f9;color:#152b40;font:15px system-ui,sans-serif}header{background:#102b44;color:white;padding:22px max(24px,4vw);display:flex;justify-content:space-between;align-items:center}header strong{font-size:26px}header span{display:block;color:#b5cbda;margin-top:6px}main{max-width:1480px;margin:auto;padding:24px}nav{display:flex;gap:18px;flex-wrap:wrap;padding:14px 0}a{color:#0e617d}section{background:white;border:1px solid #d5e0e9;border-radius:12px;padding:22px;margin:20px 0}h2{margin-top:0;font-size:21px}h3{font-size:17px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:20px 0}.cards article{background:white;border:1px solid #d5e0e9;padding:20px;border-radius:10px}.cards strong{display:block;font-size:30px;margin-top:6px}form{display:flex;align-items:end;gap:12px;flex-wrap:wrap;margin:16px 0}label{display:flex;flex-direction:column;gap:6px;font-size:13px}input,select{padding:9px;border:1px solid #a4b8c7;border-radius:5px;max-width:340px;background:white}input[type=checkbox]{align-self:start}button{background:#0c6576;color:white;border:0;padding:11px 16px;border-radius:5px;cursor:pointer}button:hover{background:#084955}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;color:#40576a;background:#eef4f7}th,td{padding:10px;border-bottom:1px solid #e3ebf0;vertical-align:top}td{max-width:330px;overflow-wrap:anywhere}dl{margin:0;min-width:160px}dt{font-weight:600}dd{margin:2px 0 10px}details{margin:14px 0;padding:12px;background:#f4f8fa;border-radius:6px}summary{cursor:pointer}.muted,footer{color:#526879}.notice{padding:16px;background:#e3f3eb;border:1px solid #8cbea3;border-radius:8px}.error{padding:16px;background:#ffe9e5;color:#8d2b1d;border-radius:8px}.login{max-width:520px;margin:50px auto}.login form{display:grid}.login input{max-width:none}code{font-size:16px;overflow-wrap:anywhere}footer form{display:inline-flex;margin-right:16px}header form{margin:0}@media(max-width:600px){main{padding:12px}section{padding:14px}header{padding:18px}input,select{max-width:280px}}'''

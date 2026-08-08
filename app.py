from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re
from collections import Counter
import math

app = Flask(__name__)

SUSPICIOUS_WORDS = {
    'login':1.0,'verify':1.2,'verification':1.2,'urgent':1.5,'account':.6,
    'password':1.3,'secure':.4,'update':.8,'confirm':.8,'bank':1.2,
    'wallet':1.2,'free':.8,'prize':1.0,'winner':1.0,'gift':.8,
    'suspended':1.4,'click':.8,'limited':.6,'offer':.5
}
SHORTENERS={'bit.ly','tinyurl.com','t.co','is.gd','cutt.ly','rb.gy','shorturl.at','ow.ly'}
TRUSTED={'google.com','github.com','microsoft.com','apple.com','amazon.com','linkedin.com','youtube.com'}

def entropy(text):
    if not text:return 0
    c=Counter(text); n=len(text)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def normalize(raw):
    raw=(raw or '').strip()
    if raw and not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://',raw): raw='http://'+raw
    return raw

def analyze_url(raw):
    url=normalize(raw)
    if not url:return {'score':0,'level':'Unknown','reasons':['No URL was provided.']}
    try:
        p=urlparse(url); host=(p.hostname or '').lower(); pq=(p.path+'?'+p.query).lower()
    except Exception:
        return {'score':100,'level':'High Risk','reasons':['The URL could not be parsed safely.']}
    score=0; reasons=[]
    if p.scheme!='https': score+=18; reasons.append('The link does not use HTTPS.')
    if '@' in p.netloc: score+=30; reasons.append("The URL contains '@', which can hide the real destination.")
    if host in SHORTENERS: score+=25; reasons.append('A URL-shortening service hides the final destination.')
    if len(url)>90: score+=10; reasons.append('The URL is unusually long.')
    if host and len(host.split('.'))>4: score+=12; reasons.append('The domain contains many subdomains.')
    if re.search(r'\d{4,}',host): score+=10; reasons.append('The domain contains a long numeric sequence.')
    if host.count('-')>=3: score+=10; reasons.append('The domain contains many hyphens.')
    if any(w in pq for w in ['login','verify','password','bank','wallet','confirm']):
        score+=15; reasons.append('The URL contains words commonly used in credential or payment scams.')
    if host in TRUSTED or any(host.endswith('.'+d) for d in TRUSTED):
        score=max(0,score-20); reasons.append('The domain matches a commonly trusted service.')
    score=min(100,max(0,score))
    level='High Risk' if score>=60 else ('Suspicious' if score>=30 else 'Low Risk')
    if not reasons: reasons.append('No major warning signs were detected by the prototype rules.')
    return {'score':score,'level':level,'reasons':reasons,'domain':host or 'Unknown','protocol':p.scheme.upper(),'length':len(url),'entropy':round(entropy(url),2)}

def analyze_text(text):
    text=(text or '').lower(); score=0; reasons=[]; hits=[]
    for word,weight in SUSPICIOUS_WORDS.items():
        if re.search(r'\b'+re.escape(word)+r'\b',text): score+=int(weight*7); hits.append(word)
    if 'http://' in text or 'https://' in text: score+=8; reasons.append('The message contains a web link.')
    if re.search(r'\b\d{10}\b',text): score+=6; reasons.append('The message contains a 10-digit number.')
    if 'otp' in text: score+=12; reasons.append('The message asks about an OTP or verification code.')
    if 'click now' in text or 'act now' in text: score+=12; reasons.append('The message uses urgent call-to-action language.')
    score=min(100,score)
    level='High Risk' if score>=60 else ('Suspicious' if score>=30 else 'Low Risk')
    if hits: reasons.append('Potentially risky keywords detected: '+', '.join(hits[:8])+'.')
    if not reasons: reasons.append('No major phishing indicators were detected by the prototype.')
    return {'score':score,'level':level,'reasons':reasons}

@app.route('/')
def index(): return render_template('index.html')
@app.route('/scan')
def scan(): return render_template('scan.html')
@app.route('/about')
def about(): return render_template('about.html')
@app.post('/api/scan-url')
def scan_url(): return jsonify(analyze_url((request.get_json(silent=True) or {}).get('url','')))
@app.post('/api/scan-text')
def scan_text(): return jsonify(analyze_text((request.get_json(silent=True) or {}).get('text','')))

if __name__=='__main__': app.run(debug=True)

import os, subprocess, hashlib, pickle, yaml, sqlite3

AWS_KEY = "AKIAABCDEFGHJKMNPQRS"   # hardcoded secret (fake)
API_KEY = "sk_live_FAKESECRETVALUE12345"

def get_user(conn, uid):
    # SQL injection via f-string
    conn.execute(f"SELECT * FROM users WHERE id = {uid}")

def run(cmd):
    subprocess.run(cmd, shell=True)   # command injection

def weak(data):
    return hashlib.md5(data).hexdigest()   # weak hash

def load(blob):
    return pickle.loads(blob)   # unsafe deser

def parse(y):
    return yaml.load(y)   # unsafe yaml

def insecure():
    import requests
    return requests.get("https://x.example", verify=False)   # TLS off

"""HTTP 测试客户端（标准库），支持自定义幂等键、并发调用、子进程重启服务。"""
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

PORT = int(os.environ.get("CONSENT_TEST_PORT", "8099"))
BASE = f"http://127.0.0.1:{PORT}"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_proc = None


def wait_port(up, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", PORT))
            if up:
                return True
        except OSError:
            if not up:
                return True
        finally:
            s.close()
        time.sleep(0.15)
    return not up


def start(server_db):
    global _proc
    if not wait_port(False, timeout=1):
        raise RuntimeError(f"port {PORT} already in use — 上一个测试服务器仍在运行")
    env = dict(os.environ, CONSENT_PORT=str(PORT), CONSENT_DB=server_db)
    _proc = subprocess.Popen(
        [sys.executable, "server.py"], cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    assert wait_port(True), "server did not come up"
    time.sleep(0.2)


def stop(hard=False):
    global _proc
    if not _proc:
        return
    if hard:
        os.killpg(_proc.pid, signal.SIGKILL)  # 模拟程序异常退出（无优雅清理）
    else:
        _proc.terminate()
    _proc.wait(timeout=10)
    _proc = None
    assert wait_port(False), "port still bound"


def restart(server_db, hard=True):
    stop(hard=hard)
    start(server_db)


def call(method, path, body=None, token=None, idem=None, raw=False):
    url = BASE + path
    data = None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        d = dict(body)
        if idem is not None:
            d["idempotency_key"] = idem
        data = json.dumps(d).encode()
    elif idem is not None:
        headers["Idempotency-Key"] = idem
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            payload = json.loads(r.read())
            return (r.status, payload) if not raw else payload
    except urllib.error.HTTPError as e:
        payload = json.loads(e.read())
        return (e.code, payload) if not raw else payload


class Client:
    def __init__(self, token=None):
        self.token = token

    def __call__(self, method, path, body=None, idem=None):
        return call(method, path, body, self.token, idem)


def login(login, pw):
    code, r = call("POST", "/api/auth/login", {"login": login, "password": pw})
    assert code == 200, r
    return Client(r["token"]), r["user"]


def parallel(*jobs, timeout=30):
    """jobs: 无参 callables。用屏障让它们尽量同时打入，制造竞态。"""
    results = [None] * len(jobs)
    barrier = threading.Barrier(len(jobs))

    def worker(i):
        barrier.wait(timeout=10)
        try:
            results[i] = jobs[i]()
        except Exception as e:  # noqa: BLE001
            results[i] = ("EXC", repr(e))

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(len(jobs))]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout)
    return results

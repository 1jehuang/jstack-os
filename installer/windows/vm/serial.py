#!/usr/bin/env python3
"""Log in on a VM serial getty (QEMU unix socket) and run commands.

  serial.py SOCK USER PASSWORD TIMEOUT CMD...

Prints each command's output. The last command may reboot the guest.
"""
import socket
import sys
import time

sock_path, user, password, timeout = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
cmds = sys.argv[5:]


def connect():
    end = time.time() + timeout
    while True:
        try:
            s = socket.socket(socket.AF_UNIX)
            s.connect(sock_path)
            s.settimeout(1)
            return s
        except OSError:
            if time.time() > end:
                raise SystemExit('serial socket never appeared')
            time.sleep(2)


s = connect()
buf = b''


def read_until(pats, t):
    global buf
    end = time.time() + t
    while time.time() < end:
        for p in pats:
            i = buf.find(p)
            if i >= 0:
                out, buf = buf[:i + len(p)], buf[i + len(p):]
                return p, out
        try:
            d = s.recv(65536)
            if not d:
                time.sleep(1)
            buf += d
        except socket.timeout:
            pass
    return None, buf


def send(line):
    s.sendall(line.encode() + b'\r')


# Wait for the login prompt (first boot can take a while), nudging with Enter.
end = time.time() + timeout
while time.time() < end:
    p, _ = read_until([b'login: '], 15)
    if p:
        break
    send('')
else:
    raise SystemExit('no login prompt on serial console')
send(user)
p, _ = read_until([b'assword: '], 30)
if not p:
    raise SystemExit('no password prompt')
send(password)
p, out = read_until([b'$ ', b'> ', b'Login incorrect'], 60)
if p in (None, b'Login incorrect'):
    raise SystemExit('login failed: ' + out.decode(errors='replace')[-300:])
# Plain, predictable shell (fish is the default login shell).
send("exec bash --norc --noprofile")
time.sleep(2)
# The marker is split in the command so its echo does not match the prompt itself.
send("PS1='__''P__ '; export TERM=dumb; bind 'set enable-bracketed-paste off' 2>/dev/null; stty -echo")
read_until([b'__P__ '], 20)
for i, c in enumerate(cmds):
    print(f'$ {c}', flush=True)
    send(c)
    if i == len(cmds) - 1:
        p, out = read_until([b'__P__ '], 20)
    else:
        p, out = read_until([b'__P__ '], 120)
    text = out.decode(errors='replace').replace('\r', '')
    text = text.replace('__P__ ', '').strip()
    print(text, flush=True)

#!/usr/bin/env python3
"""Static file server with HTTP Range support (like GitHub's CDN), for resume tests.

  rangehttp.py PORT DIR
"""
import http.server
import os
import re
import sys


class H(http.server.SimpleHTTPRequestHandler):
    def send_head(self):
        path = self.translate_path(self.path)
        m = re.fullmatch(r'bytes=(\d+)-', self.headers.get('Range', ''))
        if not m or not os.path.isfile(path):
            return super().send_head()
        size = os.path.getsize(path)
        start = int(m.group(1))
        if start >= size:
            self.send_response(416)
            self.send_header('Content-Range', f'bytes */{size}')
            self.end_headers()
            return None
        f = open(path, 'rb')
        f.seek(start)
        self.send_response(206)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Range', f'bytes {start}-{size - 1}/{size}')
        self.send_header('Content-Length', str(size - start))
        self.end_headers()
        return f


if __name__ == '__main__':
    os.chdir(sys.argv[2])
    http.server.ThreadingHTTPServer(('', int(sys.argv[1])), H).serve_forever()

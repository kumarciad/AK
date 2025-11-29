import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import hashlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
UN_FILE = os.path.join(BASE_DIR, "UN")
PWD_FILE = os.path.join(BASE_DIR, "pwd")


def ensure_storage_files():
    for path in (UN_FILE, PWD_FILE):
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write("")


def read_template(name: str) -> bytes:
    file_path = os.path.join(TEMPLATE_DIR, name)
    with open(file_path, "rb") as f:
        return f.read()


def load_users():
    ensure_storage_files()
    with open(UN_FILE, "r", encoding="utf-8") as f_un, open(PWD_FILE, "r", encoding="utf-8") as f_pwd:
        usernames = [line.strip() for line in f_un.readlines() if line.strip()]
        password_hashes = [line.strip() for line in f_pwd.readlines() if line.strip()]
    return usernames, password_hashes


def save_user(username: str, password_hash: str) -> None:
    ensure_storage_files()
    with open(UN_FILE, "a", encoding="utf-8") as f_un:
        f_un.write(username + "\n")
    with open(PWD_FILE, "a", encoding="utf-8") as f_pwd:
        f_pwd.write(password_hash + "\n")


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


class SimpleAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/login":
            self._serve_html("login.html")
        elif self.path == "/signup":
            self._serve_html("signup.html")
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        data = parse_qs(body)

        if self.path == "/login":
            username = (data.get("username") or [""])[0].strip()
            password = (data.get("password") or [""])[0]
            self._handle_login(username, password)
        elif self.path == "/create":
            username = (data.get("username") or [""])[0].strip()
            password = (data.get("password") or [""])[0]
            self._handle_create(username, password)
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def _serve_html(self, template_name: str):
        try:
            content = read_template(template_name)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_response(500)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Template not found")

    def _handle_login(self, username: str, password: str):
        usernames, password_hashes = load_users()
        if username in usernames:
            idx = usernames.index(username)
            expected_hash = password_hashes[idx] if idx < len(password_hashes) else None
            ok = expected_hash is not None and expected_hash == hash_password(password)
            if ok:
                self._render_message("Login successful", f"Welcome, {username}!")
            else:
                self._render_message("Login failed", "Invalid username/password combination.")
        else:
            self._render_message("Login failed", "User does not exist.")

    def _handle_create(self, username: str, password: str):
        if not username or not password:
            self._render_message("Sign Up failed", "Username and password are required.")
            return
        usernames, _ = load_users()
        if username in usernames:
            self._render_message("Sign Up failed", "Username already exists.")
            return
        save_user(username, hash_password(password))
        self._render_message("Account created", "You can now log in.")

    def _render_message(self, title: str, message: str):
        html = f"""
        <!doctype html>
        <html>
        <head>
            <meta charset='utf-8'>
            <title>{title}</title>
            <style>
                body {{ font-family: system-ui, Arial, sans-serif; padding: 2rem; }}
                .card {{ max-width: 420px; margin: 2rem auto; border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; }}
                .actions a {{ margin-right: 1rem; }}
            </style>
        </head>
        <body>
            <div class='card'>
                <h2>{title}</h2>
                <p>{message}</p>
                <div class='actions'>
                    <a href='/'>Back to Login</a>
                    <a href='/signup'>Create Account</a>
                </div>
            </div>
        </body>
        </html>
        """.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html)


def run(host: str = "127.0.0.1", port: int = 8000):
    ensure_storage_files()
    httpd = HTTPServer((host, port), SimpleAuthHandler)
    print(f"Server running at http://{host}:{port}/")
    httpd.serve_forever()


if __name__ == "__main__":
    run()


import os
from datetime import datetime, timedelta
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from telegram import Bot
from telegram.error import TelegramError
import databases
import asyncpg
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, select
from sqlalchemy.sql import text

# ===== CONFIGURATION from environment =====
BOT_TOKEN = os.environ.get("BOT_TOKEN")
GROUP_CHAT_ID = int(os.environ.get("GROUP_CHAT_ID"))
PASSWORD_HASH = os.environ.get("PASSWORD_HASH")
JWT_SECRET = os.environ.get("JWT_SECRET")
DATABASE_URL = os.environ.get("DATABASE_URL")

if not all([BOT_TOKEN, GROUP_CHAT_ID, PASSWORD_HASH, JWT_SECRET, DATABASE_URL]):
    raise ValueError("Missing required environment variables")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

# ===== DATABASE SETUP =====
database = databases.Database(DATABASE_URL)
metadata = MetaData()

files = Table(
    "files",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("filename", String),
    Column("file_size", Integer),
    Column("mime_type", String),
    Column("telegram_message_id", Integer),
    Column("telegram_file_id", String),
    Column("uploaded_at", String),
)

# ===== INIT =====
app = FastAPI()
bot = Bot(token=BOT_TOKEN)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# ===== DATABASE CONNECTION EVENTS =====
@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# ===== PASSWORD UTILITY =====
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# ===== JWT UTILITIES =====
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("sub") is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ===== HELPER =====
async def get_file_meta(file_id: int):
    query = files.select().where(files.c.id == file_id)
    row = await database.fetch_one(query)
    if not row:
        raise HTTPException(status_code=404, detail="File not found")
    return dict(row)

# ===== AUTH ENDPOINTS =====
@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    try:
        await get_current_user(request)
        return RedirectResponse(url="/dashboard")
    except:
        pass
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Login - Telegram Cloud</title></head>
    <body style="font-family: sans-serif; max-width: 400px; margin: 3rem auto; padding: 1rem;">
        <h2>🔐 Login</h2>
        <form action="/login" method="post">
            <input type="password" name="password" placeholder="Enter your password" style="width:100%; padding:0.5rem; margin:0.5rem 0;" required />
            <button type="submit" style="padding:0.5rem 1rem;">Login</button>
        </form>
        <div id="error" style="color:red; margin-top:0.5rem;">{error}</div>
        <script>
            const params = new URLSearchParams(window.location.search);
            if (params.get('error')) {
                document.getElementById('error').textContent = 'Invalid password. Try again.';
            }
        </script>
    </body>
    </html>
    """

@app.post("/login")
async def login(request: Request, response: Response):
    form = await request.form()
    password = form.get("password")
    if not password or not verify_password(password, PASSWORD_HASH):
        return RedirectResponse(url="/?error=1", status_code=303)
    access_token = create_access_token(data={"sub": "user"})
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    return response

@app.get("/logout")
async def logout(response: Response):
    response = RedirectResponse(url="/")
    response.delete_cookie("access_token")
    return response

# ===== DASHBOARD =====
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, username: str = Depends(get_current_user)):
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Telegram Cloud</title>
        <meta charset="utf-8">
        <style>
            body { font-family: sans-serif; max-width: 700px; margin: 2rem auto; padding: 0 1rem; }
            .file-item { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #eee; }
            .file-actions button { margin-left: 0.5rem; }
            .upload-area { margin: 2rem 0; }
            .logout { float: right; }
        </style>
    </head>
    <body>
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h2>📁 Telegram Cloud</h2>
            <a href="/logout" style="color: red; text-decoration: none;">Logout</a>
        </div>
        <div class="upload-area">
            <input type="file" id="fileInput" />
            <button id="uploadBtn">Upload</button>
            <span id="status"></span>
        </div>
        <hr />
        <h3>Your Files</h3>
        <div id="fileList"></div>

        <script>
            async function fetchFiles() {
                const res = await fetch('/list');
                if (res.status === 401) {
                    window.location.href = '/';
                    return;
                }
                const files = await res.json();
                const container = document.getElementById('fileList');
                if (files.length === 0) {
                    container.innerHTML = '<p>No files uploaded yet.</p>';
                    return;
                }
                container.innerHTML = files.map(f => `
                    <div class="file-item">
                        <span>📄 ${f.filename} (${(f.file_size / 1024).toFixed(1)} KB)</span>
                        <span class="file-actions">
                            <button onclick="downloadFile(${f.id})">⬇ Download</button>
                            <button onclick="deleteFile(${f.id})">🗑 Delete</button>
                        </span>
                    </div>
                `).join('');
            }

            function downloadFile(id) {
                window.location.href = `/download/${id}`;
            }

            async function deleteFile(id) {
                if (!confirm('Delete this file?')) return;
                const res = await fetch(`/delete/${id}`, { method: 'DELETE' });
                if (res.ok) {
                    alert('Deleted');
                    fetchFiles();
                } else {
                    alert('Delete failed');
                }
            }

            document.getElementById('uploadBtn').onclick = async () => {
                const fileInput = document.getElementById('fileInput');
                const file = fileInput.files[0];
                if (!file) return alert('Select a file');
                const formData = new FormData();
                formData.append('file', file);
                document.getElementById('status').textContent = 'Uploading...';
                const res = await fetch('/upload', { method: 'POST', body: formData });
                const data = await res.json();
                document.getElementById('status').textContent = data.message || data.detail;
                if (res.ok) {
                    fileInput.value = '';
                    fetchFiles();
                }
            };

            fetchFiles();
        </script>
    </body>
    </html>
    """

# ===== PROTECTED API =====
@app.post("/upload")
async def upload_file(file: UploadFile = File(...), username: str = Depends(get_current_user)):
    try:
        contents = await file.read()
        msg = await bot.send_document(
            chat_id=GROUP_CHAT_ID,
            document=contents,
            filename=file.filename,
            caption=f"Uploaded: {file.filename}"
        )
        query = files.insert().values(
            filename=file.filename,
            file_size=len(contents),
            mime_type=file.content_type,
            telegram_message_id=msg.message_id,
            telegram_file_id=msg.document.file_id,
            uploaded_at=datetime.utcnow().isoformat()
        )
        await database.execute(query)
        return {"message": f"✅ Uploaded '{file.filename}'"}
    except TelegramError as e:
        raise HTTPException(status_code=500, detail=f"Telegram error: {e}")

@app.get("/list")
async def list_files(username: str = Depends(get_current_user)):
    query = files.select().order_by(files.c.uploaded_at.desc())
    rows = await database.fetch_all(query)
    return [{"id": r.id, "filename": r.filename, "file_size": r.file_size, "uploaded_at": r.uploaded_at} for r in rows]

@app.get("/download/{file_id}")
async def download_file(file_id: int, username: str = Depends(get_current_user)):
    meta = await get_file_meta(file_id)
    try:
        file_obj = await bot.get_file(meta["telegram_file_id"])
        file_bytes = await file_obj.download_as_bytearray()
        return StreamingResponse(
            iter([file_bytes]),
            media_type=meta["mime_type"] or "application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{meta["filename"]}"'}
        )
    except TelegramError as e:
        raise HTTPException(status_code=500, detail=f"Download error: {e}")

@app.delete("/delete/{file_id}")
async def delete_file(file_id: int, username: str = Depends(get_current_user)):
    meta = await get_file_meta(file_id)
    try:
        await bot.delete_message(chat_id=GROUP_CHAT_ID, message_id=meta["telegram_message_id"])
        query = files.delete().where(files.c.id == file_id)
        await database.execute(query)
        return {"message": f"Deleted '{meta['filename']}'"}
    except TelegramError as e:
        raise HTTPException(status_code=500, detail=f"Delete error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

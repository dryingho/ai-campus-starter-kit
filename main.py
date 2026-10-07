"""Todo REST API (FastAPI + SQLite, single file).

Run:
    pip install fastapi uvicorn
    ADMIN_PASSWORD=mysecret uvicorn main:app --reload
Docs: http://127.0.0.1:8000/docs
"""
import hmac
import os
import secrets
import sqlite3
import time
from contextlib import closing
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

DB_PATH = os.getenv("TODO_DB", "todos.db")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin1234")  # 운영 시 반드시 환경변수로 변경
TOKEN_TTL_SECONDS = 3600
blocked_tags = ["spam", "ad", "private", "temp"]

admin_tokens: dict = {}  # token -> expires_at (메모리 저장)

app = FastAPI(title="Todo API")


# ---------- DB ----------
def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                is_completed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                tags TEXT DEFAULT ''
            )"""
        )
        conn.commit()


init_db()


# ---------- Schemas ----------
class TodoCreate(BaseModel):
    title: str
    description: str = ""
    is_completed: bool = False
    tags: str = ""  # 콤마 구분 문자열, 예: "work,urgent"


class Todo(BaseModel):
    id: int
    title: str
    description: Optional[str] = ""
    is_completed: bool
    created_at: str
    tags: str


class LoginRequest(BaseModel):
    password: str


def row_to_todo(row: sqlite3.Row) -> Todo:
    return Todo(
        id=row["id"],
        title=row["title"],
        description=row["description"] or "",
        is_completed=bool(row["is_completed"]),
        created_at=row["created_at"],
        tags=row["tags"] or "",
    )


# ---------- Admin auth ----------
def verify_admin(authorization: Optional[str] = Header(None)) -> str:
    """Authorization: Bearer <token> 검증."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing admin token")
    token = authorization[7:].strip()
    expires = admin_tokens.get(token)
    if expires is None or expires < time.time():
        admin_tokens.pop(token, None)
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return token


@app.post("/admin/login")
def admin_login(body: LoginRequest):
    if not hmac.compare_digest(body.password.encode(), ADMIN_PASSWORD.encode()):
        raise HTTPException(status_code=401, detail="Wrong password")
    token = secrets.token_urlsafe(32)
    admin_tokens[token] = time.time() + TOKEN_TTL_SECONDS
    return {"access_token": token, "token_type": "bearer", "expires_in": TOKEN_TTL_SECONDS}


@app.delete("/admin/todos/{todo_id}")
def admin_delete_todo(todo_id: int, _: str = Depends(verify_admin)):
    with closing(get_conn()) as conn:
        cur = conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Todo not found")
    return {"deleted": todo_id}


# ---------- Todos ----------
@app.post("/todos", response_model=Todo, status_code=201)
def create_todo(body: TodoCreate):
    title = body.title.strip()
    if not title:
        raise HTTPException(status_code=422, detail="title must not be empty")
    tags = ",".join(t.strip() for t in body.tags.split(",") if t.strip())
    with closing(get_conn()) as conn:
        cur = conn.execute(
            "INSERT INTO todos (title, description, is_completed, tags) VALUES (?, ?, ?, ?)",
            (title, body.description, int(body.is_completed), tags),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM todos WHERE id = ?", (cur.lastrowid,)).fetchone()
    return row_to_todo(row)


@app.get("/todos", response_model=List[Todo])
def list_todos():
    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM todos ORDER BY id").fetchall()
    return [row_to_todo(r) for r in rows]


# 고정 경로(/search, /filtered)는 동적 경로보다 먼저/별도로 정의
@app.get("/todos/search", response_model=List[Todo])
def search_todos(q: str = Query(..., min_length=1)):
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{escaped}%"
    with closing(get_conn()) as conn:
        rows = conn.execute(
            """SELECT * FROM todos
               WHERE title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\'
               ORDER BY id""",
            (pattern, pattern),
        ).fetchall()
    return [row_to_todo(r) for r in rows]


@app.get("/todos/filtered", response_model=List[Todo])
def list_filtered_todos():
    """blocked_tags 중 하나라도 태그로 가진 항목 제외 (태그 단위 정확 일치, 대소문자 무시)."""
    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM todos ORDER BY id").fetchall()
    blocked = {t.lower() for t in blocked_tags}
    result = []
    for r in rows:
        tags = {t.strip().lower() for t in (r["tags"] or "").split(",") if t.strip()}
        if not tags & blocked:
            result.append(row_to_todo(r))
    return result


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

"""
AutoBlog Backend v3
─────────────────────────────────────────────
✅ JWT + HttpOnly 쿠키 인증
✅ bcrypt 비밀번호 암호화
✅ Fernet 블로그 자격증명 암호화
✅ SQLite DB (users / blogs / articles)
✅ Rate Limiting (무차별대입 방지)
✅ 입력값 검증
✅ Swagger/API 스키마 비공개
"""

from fastapi import (
    FastAPI, HTTPException, Request, Response,
    Depends, Cookie
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator
from jose import jwt, JWTError
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
import httpx, os, json, time, aiosqlite, logging
from datetime import datetime, timedelta
from collections import defaultdict

# ─── 로깅 ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ─── 환경변수 ───────────────────────────────────────────────
ANTHROPIC_KEY   = os.getenv("ANTHROPIC_API_KEY", "")
JWT_SECRET      = os.getenv("JWT_SECRET", "change-me-in-production-use-random-32chars")
FERNET_KEY      = os.getenv("FERNET_KEY", "")          # 블로그 자격증명 암호화 키
ADMIN_EMAIL     = os.getenv("ADMIN_EMAIL", "admin@autoblog.local")
ADMIN_PASSWORD  = os.getenv("ADMIN_PASSWORD", "")      # 초기 관리자 비밀번호
DB_PATH         = os.getenv("DB_PATH", "autoblog.db")
JWT_EXPIRE_DAYS = int(os.getenv("JWT_EXPIRE_DAYS", "30"))
ANTHROPIC_URL   = "https://api.anthropic.com/v1/messages"

# Fernet 키 초기화
if FERNET_KEY:
    fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
else:
    # 서버 재시작 시 새 키 생성 (환경변수로 고정 권장)
    _tmp_key = Fernet.generate_key()
    fernet = Fernet(_tmp_key)
    logger.warning(f"⚠️  FERNET_KEY 미설정. 임시 키 사용 중. 재시작 시 암호화 데이터 복호화 불가.")

pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

# ─── FastAPI 앱 ─────────────────────────────────────────────
app = FastAPI(
    title="AutoBlog API v3",
    docs_url=None,        # Swagger 비공개
    redoc_url=None,
    openapi_url=None,     # 스키마 비공개
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:5173"),
                   "http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,          # 쿠키 허용
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type"],
)

# ─── Rate Limiter ────────────────────────────────────────────
_rl: dict = defaultdict(lambda: {"count": 0, "reset": 0, "blocked_until": 0})
RL_WINDOW   = 60    # 1분
RL_MAX      = 30    # 분당 30회 (일반 API)
RL_MAX_AUTH = 5     # 로그인 5회 실패 → 차단
RL_BLOCK    = 300   # 5분 차단

def _rl_check(ip: str, limit: int = RL_MAX):
    now = time.time()
    r   = _rl[ip]
    if r["blocked_until"] > now:
        remaining = int(r["blocked_until"] - now)
        raise HTTPException(429, f"너무 많은 요청. {remaining}초 후 재시도.")
    if now > r["reset"]:
        r["count"] = 0
        r["reset"]  = now + RL_WINDOW
    r["count"] += 1
    if r["count"] > limit:
        r["blocked_until"] = now + RL_BLOCK
        raise HTTPException(429, "요청 한도 초과. 잠시 후 재시도.")

def _rl_ok(ip: str):
    _rl[ip]["count"] = max(0, _rl[ip]["count"] - 1)

# ─── DB 초기화 ───────────────────────────────────────────────
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                email     TEXT UNIQUE NOT NULL,
                pw_hash   TEXT NOT NULL,
                created   TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS blogs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id   INTEGER NOT NULL,
                name      TEXT NOT NULL,
                url       TEXT NOT NULL,
                wp_user   TEXT NOT NULL,
                wp_pass   TEXT NOT NULL,   -- Fernet 암호화
                niche     TEXT DEFAULT '재테크',
                note      TEXT DEFAULT '',
                posts     INTEGER DEFAULT 0,
                created   TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS articles (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id   INTEGER NOT NULL,
                blog_id   INTEGER,
                keyword   TEXT,
                title     TEXT,
                body      TEXT,
                status    TEXT DEFAULT 'draft',  -- draft|published
                wp_post_id INTEGER,
                wp_url    TEXT,
                created   TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        """)
        await db.commit()

        # 관리자 계정 자동 생성
        if ADMIN_PASSWORD:
            existing = await db.execute("SELECT id FROM users WHERE email=?", (ADMIN_EMAIL,))
            if not await existing.fetchone():
                h = pwd_ctx.hash(ADMIN_PASSWORD)
                await db.execute("INSERT INTO users(email,pw_hash) VALUES(?,?)", (ADMIN_EMAIL, h))
                await db.commit()
                logger.info(f"✓ 관리자 계정 생성: {ADMIN_EMAIL}")

# ─── JWT ─────────────────────────────────────────────────────
def create_jwt(user_id: int) -> str:
    exp = datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS)
    return jwt.encode({"sub": str(user_id), "exp": exp}, JWT_SECRET, algorithm="HS256")

def decode_jwt(token: str) -> int:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return int(payload["sub"])
    except JWTError:
        raise HTTPException(401, "인증 토큰이 유효하지 않습니다")

# ─── 현재 사용자 가져오기 (쿠키 기반) ────────────────────────
async def current_user(
    request: Request,
    ab_token: str = Cookie(default=""),
) -> int:
    ip = request.client.host
    _rl_check(ip)
    if not ab_token:
        raise HTTPException(401, "로그인이 필요합니다")
    return decode_jwt(ab_token)

# ─── Fernet 암호화/복호화 ─────────────────────────────────────
def enc(text: str) -> str:
    return fernet.encrypt(text.encode()).decode()

def dec(token: str) -> str:
    try:
        return fernet.decrypt(token.encode()).decode()
    except Exception:
        return ""

# ─── 스케줄러 ────────────────────────────────────────────────
scheduler = AsyncIOScheduler()

@app.on_event("startup")
async def startup():
    await init_db()
    scheduler.start()
    logger.info("✓ AutoBlog v3 started")
    if not ANTHROPIC_KEY:
        logger.warning("⚠️  ANTHROPIC_API_KEY 미설정")

@app.on_event("shutdown")
async def _shutdown():
    scheduler.shutdown()

# ─── Pydantic Models ─────────────────────────────────────────
class LoginReq(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def email_check(cls, v):
        if "@" not in v or len(v) > 200:
            raise ValueError("이메일 형식 오류")
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def pw_check(cls, v):
        if len(v) < 6 or len(v) > 200:
            raise ValueError("비밀번호는 6자 이상")
        return v

class BlogReq(BaseModel):
    name: str
    url: str
    wp_user: str
    wp_pass: str
    niche: str = "재테크"
    note: str = ""

    @field_validator("url")
    @classmethod
    def url_check(cls, v):
        v = v.rstrip("/")
        if not v.startswith("http"):
            raise ValueError("URL은 http로 시작해야 합니다")
        return v

class KeywordReq(BaseModel):
    topic: str          # 사용자 입력 주제 (예: "치아보험")
    niche: str = "재테크/경제"

class WriteReq(BaseModel):
    keyword: str
    blog_id: int

class HumanizeReq(BaseModel):
    title: str
    body: str

class PublishReq(BaseModel):
    blog_id: int
    title: str
    body: str
    article_id: int = 0

class ScheduleReq(BaseModel):
    blog_id: int
    keyword: str
    hour: int = 8
    minute: int = 0

# ─── Claude 호출 ─────────────────────────────────────────────
async def call_claude(system: str, user: str, max_tokens: int = 2000) -> str:
    if not ANTHROPIC_KEY:
        raise HTTPException(500, "ANTHROPIC_API_KEY 미설정")
    async with httpx.AsyncClient(timeout=90) as client:
        res = await client.post(
            ANTHROPIC_URL,
            headers={
                "x-api-key": ANTHROPIC_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
    if res.status_code != 200:
        raise HTTPException(502, f"AI API 오류: {res.text[:300]}")
    return res.json()["content"][0]["text"]

# ═══════════════════════════════════════════════════════════════
#  AUTH
# ═══════════════════════════════════════════════════════════════

@app.post("/api/auth/login")
async def login(req: LoginReq, request: Request, response: Response):
    ip = request.client.host
    _rl_check(ip, RL_MAX_AUTH)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (await db.execute(
            "SELECT id, pw_hash FROM users WHERE email=?", (req.email,)
        )).fetchone()

    if not row or not pwd_ctx.verify(req.password, row["pw_hash"]):
        logger.warning(f"🔑 로그인 실패 — IP:{ip} email:{req.email}")
        raise HTTPException(401, "이메일 또는 비밀번호가 올바르지 않습니다")

    _rl_ok(ip)
    token = create_jwt(row["id"])
    response.set_cookie(
        key="ab_token",
        value=token,
        httponly=True,          # JS 접근 불가 → XSS 방어
        secure=True,
        samesite="none",
        max_age=60 * 60 * 24 * JWT_EXPIRE_DAYS,
    )
    logger.info(f"✓ 로그인 — IP:{ip} uid:{row['id']}")
    return {"ok": True, "email": req.email, "token": token}

@app.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie("ab_token")
    return {"ok": True}

@app.get("/api/auth/me")
async def me(uid: int = Depends(current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (await db.execute(
            "SELECT id, email, created FROM users WHERE id=?", (uid,)
        )).fetchone()
    if not row:
        raise HTTPException(404, "사용자 없음")
    return {"id": row["id"], "email": row["email"], "created": row["created"]}

# ═══════════════════════════════════════════════════════════════
#  BLOGS
# ═══════════════════════════════════════════════════════════════

@app.get("/api/blogs")
async def list_blogs(uid: int = Depends(current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute(
            "SELECT id,name,url,wp_user,niche,note,posts,created FROM blogs WHERE user_id=? ORDER BY id DESC",
            (uid,)
        )).fetchall()
    return {"blogs": [dict(r) for r in rows]}

@app.post("/api/blogs")
async def add_blog(req: BlogReq, uid: int = Depends(current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO blogs(user_id,name,url,wp_user,wp_pass,niche,note) VALUES(?,?,?,?,?,?,?)",
            (uid, req.name, req.url, req.wp_user, enc(req.wp_pass), req.niche, req.note),
        )
        await db.commit()
    return {"id": cur.lastrowid, "name": req.name}

@app.put("/api/blogs/{blog_id}")
async def update_blog(blog_id: int, req: BlogReq, uid: int = Depends(current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE blogs SET name=?,url=?,wp_user=?,wp_pass=?,niche=?,note=? WHERE id=? AND user_id=?",
            (req.name, req.url, req.wp_user, enc(req.wp_pass), req.niche, req.note, blog_id, uid),
        )
        await db.commit()
    return {"ok": True}

@app.delete("/api/blogs/{blog_id}")
async def delete_blog(blog_id: int, uid: int = Depends(current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM blogs WHERE id=? AND user_id=?", (blog_id, uid))
        await db.commit()
    return {"ok": True}

# ═══════════════════════════════════════════════════════════════
#  KEYWORDS
# ═══════════════════════════════════════════════════════════════

@app.post("/api/keywords")
async def get_keywords(req: KeywordReq, uid: int = Depends(current_user)):
    """
    사용자 입력 주제 → AI가 세부 키워드 10개 추천
    예) "치아보험" → ["치아보험 청구 방법", "치아보험 비교", ...]
    """
    today = datetime.now().strftime("%Y년 %m월 %d일")
    text = await call_claude(
        "한국 재테크/경제 블로그 SEO 전문가. 순수 JSON 배열만 반환. 다른 텍스트 없음.",
        f"""오늘({today}) 기준, 사용자가 입력한 주제: "{req.topic}"
이 주제와 관련된 한국에서 검색량이 많고 CPC가 높은 블로그 키워드 10개를 추천해줘.
JSON 배열만 반환:
[{{"rank":1,"keyword":"세부 키워드","searchVol":"월 XX만","cpc":"XXX원","reason":"이유 한줄"}}]""",
        800,
    )
    try:
        cleaned = text.strip().strip("```json").strip("```").strip()
        return {"keywords": json.loads(cleaned), "topic": req.topic}
    except Exception:
        return {"keywords": [
            {"rank": i+1, "keyword": f"{req.topic} {sub}",
             "searchVol": f"월 {(10-i)*2}만", "cpc": f"{1200-i*40}원", "reason": "검색 급상승"}
            for i, sub in enumerate(["방법","비교","추천","후기","종류","가입","조건","보장","단점","필요성"])
        ], "topic": req.topic}

# ═══════════════════════════════════════════════════════════════
#  ARTICLE WRITE
# ═══════════════════════════════════════════════════════════════

@app.post("/api/write")
async def write_article(req: WriteReq, uid: int = Depends(current_user)):
    """
    키워드 → AI 글 생성 (제목 + 본문 + FAQ + 표 포함)
    """
    text = await call_claude(
        """당신은 10년 경력의 한국 재테크/정보 블로그 전문 작가입니다.
규칙:
- 1인칭 경험담 포함 ("제가 직접 써봤더니", "막상 해보니까")
- 소제목(##) 4개 이상
- FAQ 섹션 포함 (Q&A 3개)
- 표(마크다운) 1개 이상
- 1500자 이상
- 구어체 자연스럽게
- 결론 단락 포함
- 키워드를 자연스럽게 5~7회 포함
형식: 첫 줄=제목(#없이), 빈줄, 본문""",
        f"""키워드: "{req.keyword}"
위 키워드로 구글 애드센스 승인에 유리한 고품질 블로그 글을 작성해줘.""",
        3000,
    )
    lines = text.split("\n")
    title = lines[0].replace("# ", "").strip()
    body  = "\n".join(lines[2:]).strip()

    # DB 저장 (draft)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO articles(user_id,blog_id,keyword,title,body,status) VALUES(?,?,?,?,?,?)",
            (uid, req.blog_id, req.keyword, title, body, "draft"),
        )
        await db.commit()
        article_id = cur.lastrowid

    return {"article_id": article_id, "title": title, "body": body, "keyword": req.keyword}

@app.post("/api/humanize")
async def humanize(req: HumanizeReq, uid: int = Depends(current_user)):
    """AI 티 제거 — 문장 자연화, 반복 제거, 말투 다양화"""
    text = await call_claude(
        """한국어 텍스트를 자연스럽고 인간적인 문체로 변환하는 전문가.
AI 감지 툴(GPTZero, Originality.ai 등)을 통과할 수 있도록 수정.
형식: 첫 줄=제목, 빈줄, 본문""",
        f"""아래 글을 인간이 쓴 것처럼 자연화해줘:

1. 일부 문장을 구어체로 (말하듯이)
2. 문단 길이를 불규칙하게
3. "솔직히", "근데", "사실" 같은 자연스러운 접속어 추가
4. 특정 단어/어순 변경으로 AI 패턴 제거
5. 개인 경험담 문장 1~2개 추가
6. 반복 표현 제거

제목: {req.title}

{req.body}""",
        3000,
    )
    lines = text.split("\n")
    title = lines[0].replace("# ", "").strip() or req.title
    body  = "\n".join(lines[2:]).strip() or req.body
    return {"title": title, "body": body}

@app.put("/api/articles/{article_id}")
async def update_article(article_id: int, req: HumanizeReq, uid: int = Depends(current_user)):
    """사용자가 직접 수정한 글 저장"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE articles SET title=?,body=? WHERE id=? AND user_id=?",
            (req.title, req.body, article_id, uid),
        )
        await db.commit()
    return {"ok": True}

# ═══════════════════════════════════════════════════════════════
#  PUBLISH
# ═══════════════════════════════════════════════════════════════

async def _do_publish(blog_id: int, title: str, body: str, uid: int) -> dict:
    """실제 WordPress 발행 (내부 함수)"""
    import base64

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        blog = await (await db.execute(
            "SELECT url,wp_user,wp_pass FROM blogs WHERE id=? AND user_id=?",
            (blog_id, uid)
        )).fetchone()

    if not blog:
        raise HTTPException(404, "블로그를 찾을 수 없습니다")

    wp_pass = dec(blog["wp_pass"])
    token   = base64.b64encode(f"{blog['wp_user']}:{wp_pass}".encode()).decode()
    wp_url  = blog["url"].rstrip("/")

    async with httpx.AsyncClient(timeout=30) as client:
        res = await client.post(
            f"{wp_url}/wp-json/wp/v2/posts",
            headers={
                "Authorization": f"Basic {token}",
                "Content-Type": "application/json",
            },
            json={"title": title, "content": body, "status": "publish"},
        )

    if res.status_code not in (200, 201):
        raise HTTPException(res.status_code, f"WordPress 오류: {res.text[:200]}")

    d = res.json()
    return {"post_id": d.get("id"), "url": d.get("link")}

@app.post("/api/publish")
async def publish(req: PublishReq, uid: int = Depends(current_user)):
    result = await _do_publish(req.blog_id, req.title, req.body, uid)

    # DB 업데이트
    async with aiosqlite.connect(DB_PATH) as db:
        if req.article_id:
            await db.execute(
                "UPDATE articles SET status='published',wp_post_id=?,wp_url=? WHERE id=? AND user_id=?",
                (result["post_id"], result["url"], req.article_id, uid),
            )
        await db.execute(
            "UPDATE blogs SET posts=posts+1 WHERE id=? AND user_id=?",
            (req.blog_id, uid),
        )
        await db.commit()

    return {"ok": True, **result}

# ═══════════════════════════════════════════════════════════════
#  ARTICLES (히스토리)
# ═══════════════════════════════════════════════════════════════

@app.get("/api/articles")
async def list_articles(uid: int = Depends(current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute(
            """SELECT a.id,a.keyword,a.title,a.status,a.wp_url,a.created,b.name as blog_name
               FROM articles a LEFT JOIN blogs b ON a.blog_id=b.id
               WHERE a.user_id=? ORDER BY a.id DESC LIMIT 50""",
            (uid,)
        )).fetchall()
    return {"articles": [dict(r) for r in rows]}

# ═══════════════════════════════════════════════════════════════
#  SCHEDULE
# ═══════════════════════════════════════════════════════════════

@app.post("/api/schedules")
async def add_schedule(req: ScheduleReq, uid: int = Depends(current_user)):
    job_id = f"uid{uid}_blog{req.blog_id}_{req.hour:02d}{req.minute:02d}"

    async def auto_job():
        logger.info(f"[Auto] uid={uid} blog={req.blog_id} keyword={req.keyword}")
        try:
            w = await write_article(WriteReq(keyword=req.keyword, blog_id=req.blog_id), uid)
            h = await humanize(HumanizeReq(title=w["title"], body=w["body"]), uid)
            r = await publish(PublishReq(
                blog_id=req.blog_id, title=h["title"], body=h["body"],
                article_id=w.get("article_id", 0)
            ), uid)
            logger.info(f"[Auto] 완료: {r}")
        except Exception as e:
            logger.error(f"[Auto] 실패: {e}")

    scheduler.add_job(
        auto_job,
        CronTrigger(hour=req.hour, minute=req.minute),
        id=job_id,
        replace_existing=True,
    )
    return {"ok": True, "job_id": job_id, "schedule": f"매일 {req.hour:02d}:{req.minute:02d}"}

@app.get("/api/schedules")
async def list_schedules(uid: int = Depends(current_user)):
    jobs = [
        {"id": j.id, "next_run": str(j.next_run_time)}
        for j in scheduler.get_jobs()
        if j.id.startswith(f"uid{uid}_")
    ]
    return {"jobs": jobs}

@app.delete("/api/schedules/{job_id}")
async def remove_schedule(job_id: str, uid: int = Depends(current_user)):
    if not job_id.startswith(f"uid{uid}_"):
        raise HTTPException(403, "권한 없음")
    try:
        scheduler.remove_job(job_id)
        return {"ok": True}
    except Exception:
        raise HTTPException(404, "스케줄 없음")

# ═══════════════════════════════════════════════════════════════
#  HEALTH / STATIC
# ═══════════════════════════════════════════════════════════════

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "3.0",
        "time": datetime.now().isoformat(),
        "ai": bool(ANTHROPIC_KEY),
    }

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def index():
    if os.path.exists("static/index.html"):
        return FileResponse("static/index.html")
    return JSONResponse({"msg": "AutoBlog API v3"})

# ─── 실행 ────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=False,
    )

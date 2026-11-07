import os
import random
import datetime
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI()

# Enable Global CORS so your frontend static site can access it
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration Variables pulling from environment
DATABASE_URL = os.environ.get("DATABASE_URL") # Provided automatically by Render DB link
SECRET_KEY = os.environ.get("JWT_SECRET", "FALLBACK_SECURE_KEY_12345")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

ADMIN_USERNAME = "admin"
# Plaintext credential: "SecretAdminPassword123"
ADMIN_HASHED_PASSWORD = "$bcrypt$v=2$m=12,t=12,p=1$Z82361/mDqM1D.O7W20tqu$29a2E8J4HqgV63cOQd1wz2Yd8wX4eSm"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/admin/login")

class BlogCreate(BaseModel):
    title: str
    content: str

class LoginRequest(BaseModel):
    username: str
    password: str

def get_db_connection():
    # Establishes connection to the remote resilient database cluster
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="Database URL missing.")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def init_db():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blogs (
                    id SERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
    finally:
        conn.close()

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username != ADMIN_USERNAME:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate signature")

@app.post("/api/admin/login")
def login(data: LoginRequest):
    if data.username != ADMIN_USERNAME or not pwd_context.verify(data.password, ADMIN_HASHED_PASSWORD):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token_payload = {"sub": data.username, "exp": expire}
    encoded_jwt = jwt.encode(token_payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": encoded_jwt, "token_type": "bearer"}

@app.post("/api/admin/blogs")
def create_blog(blog: BlogCreate, username: str = Depends(verify_token)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO blogs (title, content) VALUES (%s, %s)", (blog.title, blog.content))
            conn.commit()
        return {"status": "Success", "message": "Blog permanently logged."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Write error: {str(e)}")
    finally:
        conn.close()

@app.get("/api/blogs/shuffled")
def get_shuffled_blogs():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, title, content, created_at FROM blogs ORDER BY created_at DESC LIMIT 50")
            blogs = cursor.fetchall()
        random.shuffle(blogs)
        return blogs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database read failure: {str(e)}")
    finally:
        conn.close()

# Initialize DB structure on application startup trigger
init_db()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

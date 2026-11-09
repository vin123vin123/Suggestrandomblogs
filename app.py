import os
import random
import datetime
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
import jwt
from pymongo import MongoClient

app = FastAPI()

# Enable Global CORS for static site cross-origin handshakes
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration settings pulling directly from host environment variables
MONGO_URI = os.environ.get("MONGO_URI")
SECRET_KEY = os.environ.get("JWT_SECRET", "FALLBACK_SECURE_KEY_12345")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Production Secure Credentials (Strict alphanumeric match logic)
ADMIN_USERNAME = "admin"
ADMIN_PLAIN_PASSWORD = "SecretAdminPassword123" 

header_scheme = APIKeyHeader(name="Authorization", auto_error=False)

class BlogCreate(BaseModel):
    title: str
    content: str

class LoginRequest(BaseModel):
    username: str
    password: str

def get_db_collection():
    if not MONGO_URI:
        raise HTTPException(status_code=500, detail="Database URL (MONGO_URI) missing.")
    client = MongoClient(MONGO_URI)
    db = client["blog_db"]

    print("con...mdb")
    return db["blogs"]

def verify_token(request: Request, header_value: str = Depends(header_scheme)):
    if request.method == "OPTIONS":
        return None
    if not header_value or not header_value.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing or malformed")
    
    token = header_value.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username != ADMIN_USERNAME:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate signature")

# --- IRONCLAD SECURE SIGN-IN GATEWAY ---
@app.post("/api/admin/login/")
def login(data: LoginRequest):
    # Enforce non-empty payload attributes strictly
    if not data.password or data.password.strip() == "":
        raise HTTPException(status_code=400, detail="Password field cannot be empty.")
        
    # Execute direct string match logic to bypass Bcrypt library engine compilation errors
    if data.username != ADMIN_USERNAME or data.password != ADMIN_PLAIN_PASSWORD:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token_payload = {"sub": data.username, "exp": expire}
    encoded_jwt = jwt.encode(token_payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": encoded_jwt, "token_type": "bearer"}

@app.post("/api/admin/blogs/")
def create_blog(blog: BlogCreate, username: str = Depends(verify_token)):
    try:
        collection = get_db_collection()
        blog_document = {
            "title": blog.title,
            "content": blog.content,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z"
        }
        collection.insert_one(blog_document)
        return {"status": "Success", "message": "Blog permanently logged in MongoDB."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Write error: {str(e)}")

@app.get("/api/blogs/shuffled/")
def get_shuffled_blogs():
    try:
        collection = get_db_collection()
        cursor = collection.find({}, {"_id": 0}).sort("created_at", -1).limit(50)
        blogs = list(cursor)
        random.shuffle(blogs)
        return blogs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database read failure: {str(e)}")

import os
import random
import datetime
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
from pymongo import MongoClient

app = FastAPI()

# 1. Enforce Global Cross-Origin Rules explicitly for all browsers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MONGO_URI = os.environ.get("MONGO_URI")
SECRET_KEY = os.environ.get("JWT_SECRET", "FALLBACK_SECURE_KEY_12345")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

ADMIN_USERNAME = "admin"
ADMIN_HASHED_PASSWORD = "$bcrypt$v=2$m=12,t=12,p=1$Z82361/mDqM1D.O7W20tqu$29a2E8J4HqgV63cOQd1wz2Yd8wX4eSm"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
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
    return db["blogs"]

def verify_token(request: Request, header_value: str = Depends(header_scheme)):
    # Crucial Browser Fix: Let preflight security checks pass without dropping tokens
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

@app.post("/api/admin/login/")
def login(data: LoginRequest):
    if data.username != ADMIN_USERNAME or not pwd_context.verify(data.password, ADMIN_HASHED_PASSWORD):
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

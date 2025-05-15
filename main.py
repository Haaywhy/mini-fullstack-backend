from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError
from pydantic import BaseModel
from database import SessionLocal, engine, Base
from auth import hash_password, verify_password, create_access_token, decode_access_token
import logging

# Initialize app
app = FastAPI()

# ✅ Allow Vercel frontend and local dev frontend
origins = [
    "https://mini-fullstack-frontend.vercel.app",
    "http://localhost:5173",
]

# ✅ Apply CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Logger
logger = logging.getLogger("uvicorn.error")

# ✅ SQLAlchemy user model
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)

# ✅ Pydantic model
class User(BaseModel):
    username: str
    password: str

# ✅ Create DB tables
Base.metadata.create_all(bind=engine)

# ✅ Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ✅ Auth scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ✅ Root route
@app.get("/")
def read_root():
    return {"message": "Hello from backend"}

# ✅ Signup route
@app.post("/signup")
def signup(user: User, db: Session = Depends(get_db)):
    try:
        # Check if the username already exists
        existing = db.query(UserDB).filter(UserDB.username == user.username).first()
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")

        # Hash password and save new user
        hashed = hash_password(user.password)
        new_user = UserDB(username=user.username, password=hashed)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return {"message": "User created successfully", "user_id": new_user.id}
    except Exception as e:
        logger.error(f"Signup error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# ✅ Login route
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

# ✅ Dashboard route
@app.get("/dashboard")
def dashboard(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        users = db.query(UserDB).all()
        usernames = [user.username for user in users]
        return {"users": usernames}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ✅ Hardcoded users route (optional test route)
@app.get("/users")
def get_users(token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    hardcoded_users = [
        {"id": 1, "username": "alice"},
        {"id": 2, "username": "bob"},
        {"id": 3, "username": "charlie"},
    ]
    return {"users": hardcoded_users}

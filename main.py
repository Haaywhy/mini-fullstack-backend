from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError

from pydantic import BaseModel
from database import SessionLocal, engine, Base
from auth import hash_password, verify_password, create_access_token, decode_access_token

# Initialize app
app = FastAPI()

# Allow frontend on localhost:3000 to communicate
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SQLAlchemy model
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)

# Pydantic model
class User(BaseModel):
    username: str
    password: str

# Initialize DB
Base.metadata.create_all(bind=engine)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Auth scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Signup route
@app.post("/signup")
def signup(user: User, db: Session = Depends(get_db)):
    existing = db.query(UserDB).filter(UserDB.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed = hash_password(user.password)
    new_user = UserDB(username=user.username, password=hashed)
    db.add(new_user)
    db.commit()
    return {"message": "User created successfully"}

# Login route
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

# dashboard
@app.get("/dashboard")
def dashboard(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        # ✅ Get all usernames from the database
        users = db.query(UserDB).all()
        usernames = [user.username for user in users]

        # ✅ Return them as a list in a dictionary
        return {"users": usernames}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Protected: return all users
@app.get("/users")
def get_users(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    users = db.query(UserDB).all()
    return [{"id": u.id, "username": u.username} for u in users]

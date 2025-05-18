from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

# ------------------- Models ------------------- #
class User(BaseModel):
    username: str
    password: str
    full_name: str  # ✅ added full name here

class UserInDB(User):
    hashed_password: str

class UserOut(BaseModel):
    id: int
    username: str
    full_name: str  # ✅ include full name in user output

class Token(BaseModel):
    access_token: str
    token_type: str

# ------------------- App Setup ------------------- #
app = FastAPI()

# ✅ CORS setup
origins = [
    "https://mini-fullstack-frontend.vercel.app",
    "https://mini-fullstack-frontend-cs99-5kdfk4wk1-ayokunle-ajepes-projects.vercel.app",
    "http://localhost:5173",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- Auth Setup ------------------- #
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ------------------- Fake DB ------------------- #
users_db = []
id_counter = 1

# ------------------- Utils ------------------- #
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(username: str):
    return next((u for u in users_db if u['username'] == username), None)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = get_user(username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ------------------- Routes ------------------- #

@app.post("/signup")
def signup(user: User = Body(...)):
    global id_counter
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = get_password_hash(user.password)
    users_db.append({
        "id": id_counter,
        "username": user.username,
        "full_name": user.full_name,  # ✅ store full name
        "hashed_password": hashed_password,
    })
    id_counter += 1
    return {"msg": "User created successfully"}

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users", response_model=List[UserOut])
def get_users(current_user: dict = Depends(get_current_user)):
    return [{"id": u["id"], "username": u["username"], "full_name": u["full_name"]} for u in users_db]

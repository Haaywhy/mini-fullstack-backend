from fastapi import FastAPI, HTTPException, Depends, Body, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi.openapi.utils import get_openapi

# ------------------- Models ------------------- #
class User(BaseModel):
    username: str
    password: str
    full_name: str
    role: Optional[str] = "user"

class UserInDB(User):
    hashed_password: str
    is_active: bool = False

class UserOut(BaseModel):
    id: int
    username: str
    full_name: str
    role: str
    is_active: bool

class Token(BaseModel):
    access_token: str
    token_type: str
    is_active: bool
    role: str

# ------------------- App Setup ------------------- #
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://mini-fullstack-frontend-cs99-git-main-ayokunle-ajepes-projects.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Mini Fullstack API",
        version="1.0.0",
        description="API with RBAC using FastAPI",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"].values():
        for operation in path.values():
            operation["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

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

def require_role(current_user: dict, required_role: str):
    roles = ["user", "admin", "superadmin"]
    if roles.index(current_user["role"]) < roles.index(required_role):
        raise HTTPException(status_code=403, detail=f"{required_role} access required")

# ------------------- Routes ------------------- #

@app.post("/signup")
def signup(user: User = Body(...)):
    global id_counter
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = get_password_hash(user.password)
    is_active = user.role == "superadmin"  # Superadmin auto-activated

    new_user = {
        "id": id_counter,
        "username": user.username,
        "full_name": user.full_name,
        "hashed_password": hashed_password,
        "role": user.role,
        "is_active": is_active
    }

    users_db.append(new_user)
    id_counter += 1

    return {"msg": "Account created successfully. Awaiting activation." if not is_active else "Superadmin created and activated."}

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)

    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    if not user.get("is_active"):
        raise HTTPException(status_code=403, detail="Your account is not yet activated.")

    access_token = create_access_token(data={"sub": user["username"]})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "is_active": user["is_active"],
        "role": user["role"]
    }

@app.get("/me", response_model=UserOut)
def read_users_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "full_name": current_user["full_name"],
        "role": current_user["role"],
        "is_active": current_user["is_active"]
    }

@app.get("/users", response_model=List[UserOut])
def get_users(current_user: dict = Depends(get_current_user)):
    require_role(current_user, "superadmin")
    return [
        {
            "id": u["id"],
            "username": u["username"],
            "full_name": u["full_name"],
            "role": u["role"],
            "is_active": u["is_active"]
        }
        for u in users_db
    ]

@app.post("/activate")
def activate_user(
    user_id: int = Query(..., description="ID of the user to activate"),
    current_user: dict = Depends(get_current_user)
):
    require_role(current_user, "superadmin")
    user = next((u for u in users_db if u["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["is_active"] = True
    return {"msg": f"User {user['username']} activated successfully"}

@app.put("/profile")
def update_profile(
    full_name: str = Body(...),
    password: Optional[str] = Body(None),
    current_user: dict = Depends(get_current_user)
):
    current_user["full_name"] = full_name
    if password:
        current_user["hashed_password"] = get_password_hash(password)
    return {"msg": "Profile updated successfully"}

@app.delete("/profile")
def delete_profile(current_user: dict = Depends(get_current_user)):
    raise HTTPException(status_code=403, detail="You cannot delete your own account")

@app.delete("/admin/delete-user/{username}")
def admin_delete_user(username: str, current_user: dict = Depends(get_current_user)):
    require_role(current_user, "admin")
    if username == current_user["username"]:
        raise HTTPException(status_code=403, detail="You cannot delete your own account")
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    users_db.remove(user)
    return {"msg": f"User '{username}' deleted successfully"}

@app.get("/superadmin/feature")
def superadmin_only(current_user: dict = Depends(get_current_user)):
    require_role(current_user, "superadmin")
    return {"msg": "Superadmin-only feature accessed"}

from fastapi import FastAPI, HTTPException, Request, Form, File, UploadFile, status, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from typing import List, Optional
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, String, Boolean, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from fastapi.responses import RedirectResponse
from datetime import datetime, timedelta
import os


app = FastAPI()
templates = Jinja2Templates(directory="music_templates")
app.mount('/static', StaticFiles(directory="static"), name="static")

SECRET_KEY = "secret_key_example"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=False)
    songs = relationship("SongModel", back_populates="owner")


class SongModel(Base):
    __tablename__ = "songs"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    artist = Column(String)
    file_path = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("UserModel", back_populates="songs")


Base.metadata.create_all(bind=engine)

# Pydantic модели
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    full_name: Optional[str] = None

class Song(BaseModel):
    id: int
    name: str
    artist: str
    file_path: str

class SongCreate(BaseModel):
    name: str
    artist: str

class Token(BaseModel):
    access_token: str
    token_type: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_user(db: Session, user: UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = UserModel(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user_by_username(db: Session, username: str):
    return db.query(UserModel).filter(UserModel.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

async def get_current_user(request: Request, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = request.cookies.get("access_token")
    if not token:
        raise credentials_exception

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user_by_username(db, username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: UserModel = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.get("/", response_class = HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("logup_user.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
async def register_form(request: Request):
    return templates.TemplateResponse("logup_user.html", {"request": request})

@app.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    email: Optional[str] = Form(None),
    full_name: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    db_user = get_user_by_username(db, username)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    existing_user = db.query(UserModel).filter_by(email=email).first()
    if existing_user:   
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    user = UserCreate(username=username, password=password, email=email, full_name=full_name)
    create_user(db, user)
    return templates.TemplateResponse("login_form.html", {"request": request, "user": user})

@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse("login_form.html", {"request": request})

@app.post("/token")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

    response = RedirectResponse(url="/songs", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True)
    return response

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: UserModel = Depends(get_current_active_user)):
    return current_user

@app.get("/songs", response_class=HTMLResponse)
async def get_user_songs(request: Request, current_user: UserModel = Depends(get_current_active_user)):
    return templates.TemplateResponse("index.html", {"request": request, "songs": current_user.songs, "user": current_user})

@app.get("/profile", response_class=HTMLResponse)
async def get_user_profile(request: Request, current_user: UserModel = Depends(get_current_active_user)):
    return templates.TemplateResponse("user_profile.html", {"request": request, "username": current_user.username, "email": current_user.email, "full_name": current_user.full_name})

@app.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token")  
    return response


@app.post("/songs/add", response_class=HTMLResponse)
async def add_song(
    request: Request,
    name: str = Form(...),
    artist: str = Form(...),
    file: UploadFile = File(...),
    current_user: UserModel = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):

    file_path = f"static/{file.filename}"
    os.makedirs("static", exist_ok=True)
    

    with open(file_path, "wb") as f:
        f.write(await file.read())


    new_song = SongModel(
        name=name,
        artist=artist,
        file_path=file_path,
        owner_id=current_user.id
    )

    db.add(new_song)
    db.commit()
    return templates.TemplateResponse("song_added.html", {"request": request, "new_song": new_song})


@app.post("/songs/edit", response_class=HTMLResponse)
async def edit_song(
    request: Request,
    name: str = Form(...),
    artist: str = Form(...),
    new_name: str = Form(...),
    new_artist: str = Form(...),
    current_user: UserModel = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    song = db.query(SongModel).filter(SongModel.name == name, SongModel.artist == artist).first()
    if not song:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Song not found or you do not have permission to edit it"
        )
    
    if name:
        song.name = new_name
    if artist:
        song.artist = new_artist

    db.commit()
    db.refresh(song)

    return templates.TemplateResponse("song_edited.html", {"request": request, "song": song})

@app.post("/songs/delete", response_class=HTMLResponse)
async def delete_song(
    request: Request,
    name: str = Form(...),
    artist: str = Form(...),
    current_user: UserModel = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    song = db.query(SongModel).filter(SongModel.name == name, SongModel.artist == artist).first()
    if not song:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Song not found or you dont have permission to delete it"
        )
    
    if os.path.exists(song.file_path):
        os.remove(song.file_path)

    db.delete(song)
    db.commit()

    return templates.TemplateResponse("song_deleted.html", {"request": request})
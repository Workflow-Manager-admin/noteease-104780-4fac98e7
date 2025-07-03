import os
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship, scoped_session
from dotenv import load_dotenv

# --- ENVIRONMENT/DB CONFIG ---

load_dotenv()

DB_URL = os.getenv("NOTES_DATABASE_URL", "sqlite:///./notes.db")
SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret_temp_replace")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

# --- DB SETUP ---

Base = declarative_base()
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = scoped_session(sessionmaker(bind=engine))

# --- PASSWORD CONTEXT ---

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

# --- DB MODELS ---

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(32), unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    notes = relationship("Note", back_populates="owner", cascade="all, delete-orphan")

class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), nullable=False)
    body = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner = relationship("User", back_populates="notes")

Base.metadata.create_all(bind=engine)

# --- Pydantic MODELS ---

class NoteBase(BaseModel):
    title: str = Field(..., max_length=100, description="Title of the note")
    body: Optional[str] = Field(None, description="Body of the note")

class NoteCreate(NoteBase):
    pass

class NoteUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=100, description="Edited note title")
    body: Optional[str] = Field(None, description="Edited note body")

class NoteOut(NoteBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=6, max_length=128)

class UserOut(BaseModel):
    id: int
    username: str

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# --- UTILS ---

# PUBLIC_INTERFACE
def verify_password(plain, hashed):
    """Verify a plain password against its hash."""
    return pwd_context.verify(plain, hashed)

# PUBLIC_INTERFACE
def get_password_hash(password):
    """Generate a secure hash for a password."""
    return pwd_context.hash(password)

# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: timedelta = None):
    """Create a JWT for authenticated user."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=60))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# PUBLIC_INTERFACE
def get_db():
    """Yield the SQLAlchemy DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# PUBLIC_INTERFACE
def get_user_by_username(db: Session, username: str):
    """Retrieve a User object by username."""
    return db.query(User).filter(User.username == username).first()

# PUBLIC_INTERFACE
def authenticate_user(db: Session, username: str, password: str):
    """Check credentials: returns user if correct, else False."""
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

# PUBLIC_INTERFACE
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Decode JWT & return the current authenticated user object."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    return user

# --- FASTAPI APP ---

app = FastAPI(
    title="Notes Backend API",
    description="Backend API for the NoteEase application: User accounts, authentication, & secure personal notes CRUD.",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "User authentication and account endpoints"},
        {"name": "notes", "description": "CRUD and search for notes"},
    ]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------
# Public health endpoint
# --------------------------------
@app.get("/", tags=["health"])
def health_check():
    """Simple health check endpoint."""
    return {"message": "Healthy"}

# --------------------------------
# AUTHENTICATION
# --------------------------------

@app.post("/auth/register", tags=["auth"], response_model=UserOut, summary="Register a new user")
def register(user: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user. Username must be unique. Password will be >6 chars.
    """
    if get_user_by_username(db, user.username):
        raise HTTPException(status_code=400, detail="Username already taken")
    hashed = get_password_hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post('/auth/token', tags=["auth"], response_model=Token, summary="Authenticate and get a JWT token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Authenticate user and return JWT token.
    Frontend should POST username/password via form-data.
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", tags=["auth"], response_model=UserOut, summary="Get current user info")
def get_me(current_user: User = Depends(get_current_user)):
    """
    Get details for the current authenticated user (no password).
    """
    return current_user

# --------------------------------
# NOTES CRUD
# --------------------------------

@app.post("/notes/", tags=["notes"], response_model=NoteOut, status_code=status.HTTP_201_CREATED, summary="Create a new note")
def create_note(note: NoteCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Create a new note for the authenticated user. Title required. Body optional.
    """
    db_note = Note(title=note.title, body=note.body or "", owner_id=current_user.id)
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    return db_note

@app.get("/notes/", tags=["notes"], response_model=List[NoteOut], summary="List notes (paginated)")
def list_notes(
    skip: int = Query(0, ge=0, description="How many notes to skip"),
    limit: int = Query(20, ge=1, le=100, description="Limit number of notes to return"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all notes for the logged-in user. Paginated.
    """
    notes = db.query(Note).filter(Note.owner_id == current_user.id).order_by(Note.updated_at.desc()).offset(skip).limit(limit).all()
    return notes

@app.get("/notes/{note_id}", tags=["notes"], response_model=NoteOut, summary="Get a single note")
def read_note(note_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Get a single note by ID, only if owned by current user.
    """
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    return note

@app.put("/notes/{note_id}", tags=["notes"], response_model=NoteOut, summary="Update a note")
def update_note(note_id: int, note: NoteUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Update title and/or body for the given note. Only the owner can update.
    """
    db_note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if not db_note:
        raise HTTPException(status_code=404, detail="Note not found")
    # Only update provided fields
    if note.title is not None:
        db_note.title = note.title
    if note.body is not None:
        db_note.body = note.body
    db.commit()
    db.refresh(db_note)
    return db_note

@app.delete("/notes/{note_id}", tags=["notes"], status_code=204, summary="Delete a note")
def delete_note(note_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Delete a note. Only the owner can delete their note.
    """
    db_note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if not db_note:
        raise HTTPException(status_code=404, detail="Note not found")
    db.delete(db_note)
    db.commit()
    return

@app.get("/notes/search/", tags=["notes"], response_model=List[NoteOut], summary="Search notes by query string")
def search_notes(
    q: str = Query(..., min_length=1, description="Query string for searching title/body"),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Search notes (for this user) whose title or body contains the given string (case-insensitive, partial match).
    """
    like_query = f"%{q}%"
    notes = db.query(Note).filter(
        Note.owner_id == current_user.id,
        (Note.title.ilike(like_query)) | (Note.body.ilike(like_query))
    ).order_by(Note.updated_at.desc()).offset(skip).limit(limit).all()
    return notes

# -- SWAGGER USAGE HELP FOR WEBSOCKETS (none here, but included as per requirements) --

@app.get("/docs/websocket_help", tags=["auth"], summary="WebSocket Usage Help")
def websocket_usage_help():
    """
    NOTE: This API does not support websocket endpoints. 
    All communication happens via JWT-protected REST endpoints.
    """
    return {
        "websocket_support": False,
        "message": "This API is designed for RESTful communication for the note-taking app. No websocket endpoints are provided."
    }

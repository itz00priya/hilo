import time
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from . import models, database
from .services.google_books import fetch_book_details
from .database import engine
from . import models
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from . import auth, schemas, crud
from fastapi import Depends
from .database import get_db
app = FastAPI(title="Book Library API")

time.sleep(3) 
models.Base.metadata.create_all(bind=database.engine)

@app.post("/")
def home():
    return {"message": "welcome to the Book Library API!"}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.post("/register", response_model=schemas.User)
def register_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_pw = auth.get_password_hash(user.password)
    user.password = hashed_pw
    return crud.create_user(db=db, user=user)

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = crud.get_user_by_username(db, username=form_data.username)
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/books/{isbn}")
async def add_book(
    isbn: str, 
    db: Session = Depends(database.get_db),
    token: str = Depends(oauth2_scheme)  
): 
    # Check if book already exists
    db_book = db.query(models.Book).filter(models.Book.isbn == isbn).first()
    if db_book:
        raise HTTPException(status_code=400, detail="Book already exists in library")
    
    # Fetch from Google
    book_data = await fetch_book_details(isbn)
    if not book_data:
        raise HTTPException(status_code=404, detail="Book not found on Google Books")
    
    # Save to DB
    new_book = models.Book(**book_data)
    db.add(new_book)
    db.commit()
    db.refresh(new_book)
    return new_book

@app.get("/books")
def list_books(db: Session = Depends(database.get_db)):
    return db.query(models.Book).all()

@app.get("/books/category/{cat_name}")
def get_books_by_category(cat_name: str, db: Session = Depends(get_db)):
    
    books = db.query(models.Book).filter(models.Book.category == cat_name).all()
    return books







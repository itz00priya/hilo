import time 
from fastapi import FastAPI, Request, Form, Depends, status, HTTPException, UploadFile, File
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from sqlalchemy import func
from typing import Optional
from datetime import datetime, timedelta
import random
import string
import shutil
import os
import math
import csv
import io
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.db.session import get_db
from app.api.v1.router import router as v1_router
from app.services.auth_service import authenticate_user
from app.utils.email import send_otp_email 
from app.models import User, Category, Expense, Transfer, Role
from app.services.report_service import (
    get_monthly_expense_report,
    get_monthly_transfers,
    get_recent_expenses,
    get_recent_transfers,
    get_user_categories,
    get_category_pie_data,
    get_paginated_expenses,
    get_paginated_transfers,
    get_total_transaction_count,
    get_filtered_expenses,     
    get_filtered_transfers     
)
from app.services.category_service import create_category
app = FastAPI()


limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Custom Handler for Rate Limit Errors (Shows HTML instead of JSON for Login)
@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    # If API call, return JSON error
    if request.url.path.startswith("/api"):
        return JSONResponse(
            {"error": f"Rate limit exceeded: {exc.detail}"}, 
            status_code=429
        )
    
    # If Login page, return HTML with error
    return templates.TemplateResponse("login.html", {
        "request": request, 
        "error": "Too many login attempts! Please wait 1 minute."
    }, status_code=429)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WARNING: Change this secret key for production!
app.add_middleware(SessionMiddleware, secret_key="super-secret-key-change-this")

# --- Static Files & Templates ---
os.makedirs("static/profile_pics", exist_ok=True) 
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- API Router ---
app.include_router(v1_router, prefix="/api/v1")


# ================= DEPENDENCIES =================

def get_current_user(request: Request, db: Session = Depends(get_db)):
    """Retrieves the currently logged-in user from the session."""
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()

def get_admin_user(user: User = Depends(get_current_user)):
    """Checks if the current user has 'admin' privileges."""
    if not user or user.role.name != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Admins can perform this action!"
        )
    return user


# ================= AUTH ROUTES =================

@app.get("/", response_class=HTMLResponse)
async def root_redirect():
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

# --- APPLY RATE LIMIT HERE ---
@app.post("/login", response_class=HTMLResponse)
@limiter.limit("5/minute") 
async def login_post(
    request: Request, 
    username: str = Form(...), 
    password: str = Form(...), 
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, username, password)
    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Invalid username or password"
        })
    
    request.session["user_id"] = user.id
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register", response_class=HTMLResponse)
async def register_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # 1. Check if user already exists
    existing_user = db.query(User).filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Username or Email already exists!"
        })

    # 2. Hash password
    hashed_pw = pwd_context.hash(password)
    
    # 3. Generate Account Number
    generated_account_num = "".join(random.choices(string.digits, k=10))

    # 4. Assign Default Role ('user')
    user_role = db.query(Role).filter(Role.name == "user").first()
    if not user_role:
        # Create default roles if they don't exist
        user_role = Role(name="user")
        db.add(user_role)
        db.commit()
        db.refresh(user_role)

    # 5. Create User
    new_user = User(
        username=username, 
        email=email, 
        hashed_password=hashed_pw, 
        role_id=user_role.id,
        account_number=generated_account_num
    )
    
    db.add(new_user)
    db.commit()

    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login")



# Helper Function for Date Filtering
def get_date_range(filter_type: str):
    now = datetime.now()
    if filter_type == "today":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now.replace(hour=23, minute=59, second=59, microsecond=999999)
    elif filter_type == "last_7_days":
        start = now - timedelta(days=7)
        end = now
    elif filter_type == "this_month":
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end = now
    elif filter_type == "last_month":
        last_month_end = now.replace(day=1) - timedelta(days=1)
        start = last_month_end.replace(day=1, hour=0, minute=0, second=0)
        end = last_month_end.replace(hour=23, minute=59, second=59)
    else:
        return None, None # All Time
    return start, end

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request, 
    filter: str = "all", # Default 'All Time'
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")

    # 1. Calculate Dates
    start_date, end_date = get_date_range(filter)

    # 2. Fetch Filtered Data
    expenses = get_filtered_expenses(db, user, start_date, end_date)
    transfers = get_filtered_transfers(db, user, start_date, end_date)

    # 3. Calculate Totals Manually
    total_income = sum(t.amount for t in transfers)
    total_expense = sum(e.debit for e in expenses)
    balance = total_income - total_expense

    # 4. Prepare Chart Data
    chart_labels = []
    chart_data = []
    category_map = {}
    
    for exp in expenses:
        cat_name = exp.category.name if exp.category else "Uncategorized"
        category_map[cat_name] = category_map.get(cat_name, 0) + exp.debit
        
    chart_labels = list(category_map.keys())
    chart_data = list(category_map.values())

    # 5. Categories for Dropdown
    categories = get_user_categories(db, user)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "monthly_expenses": total_expense,
        "monthly_transfers": total_income,
        "balance": balance,
        "recent_expenses": expenses[:5],
        "recent_transfers": transfers[:5],
        "chart_labels": chart_labels,
        "chart_data": chart_data,
        "categories": categories,
        "current_filter": filter
    })


# ================= TRANSACTIONS ROUTES =================

@app.get("/transactions", response_class=HTMLResponse)
async def transactions_page(
    request: Request, 
    page: int = 1, 
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")

    PAGE_SIZE = 10 
    
    expenses = get_paginated_expenses(db, user, page, PAGE_SIZE)
    transfers = get_paginated_transfers(db, user, page, PAGE_SIZE)
    
    all_transactions = []
    for exp in expenses:
        t = exp.__dict__.copy()
        if '_sa_instance_state' in t: del t['_sa_instance_state']
        t['type'] = 'expense'
        t['amount'] = exp.debit
        all_transactions.append(t)
        
    for tr in transfers:
        t = tr.__dict__.copy()
        if '_sa_instance_state' in t: del t['_sa_instance_state']
        t['type'] = 'transfer'
        if not t.get('description'): t['description'] = "Transfer"
        all_transactions.append(t)

    all_transactions.sort(key=lambda x: x['created_at'], reverse=True)
    
    total_items = get_total_transaction_count(db, user)
    total_pages = math.ceil(total_items / PAGE_SIZE) if total_items > 0 else 1
    
    # --- FETCH CATEGORIES FOR MODAL ---
    categories = get_user_categories(db, user)
    
    return templates.TemplateResponse("transactions.html", {
        "request": request,
        "user": user, 
        "transactions": all_transactions, 
        "current_page": page,
        "total_pages": total_pages,
        "categories": categories
    })


@app.post("/transactions/add")
async def add_transaction(
    request: Request,
    description: str = Form(...),
    amount: float = Form(...),
    type: str = Form(...),
    category_id: str = Form(""),
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")
    
    if type == "expense":
        # Calculate Balance First
        total_income = db.query(func.sum(Transfer.amount)).filter(Transfer.receiver_id == user.id).scalar() or 0.0
        total_expense = db.query(func.sum(Expense.debit)).filter(Expense.user_id == user.id).scalar() or 0.0
        current_balance = total_income - total_expense

        if current_balance < amount:
            return RedirectResponse(url="/dashboard?error=insufficient_balance", status_code=status.HTTP_303_SEE_OTHER)

        category_id_int = int(category_id) if category_id and category_id.isdigit() else None

        new_entry = Expense(
            description=description,
            debit=amount,
            user_id=user.id,
            category_id=category_id_int
        )
        db.add(new_entry)

    else:
        # Income
        new_entry = Transfer(
            description=description,
            amount=amount,
            sender_id=user.id,
            receiver_id=user.id
        )
        db.add(new_entry)
        
    db.commit()
    return RedirectResponse(url="/transactions", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/transactions/delete/{type}/{id}")
async def delete_transaction(
    type: str,
    id: int,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    if type == "expense":
        entry = db.query(Expense).filter(Expense.id == id, Expense.user_id == user.id).first()
    else:
        entry = db.query(Transfer).filter(Transfer.id == id, (Transfer.sender_id == user.id) | (Transfer.receiver_id == user.id)).first()

    if entry:
        db.delete(entry)
        db.commit()

    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


# ================= CATEGORIES ROUTES =================

@app.get("/categories", response_class=HTMLResponse)
async def categories_page(
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")

    categories = get_user_categories(db, user)

    return templates.TemplateResponse("categories.html", {
        "request": request,
        "user": user,
        "categories": categories
    })

@app.post("/categories/add")
async def add_category(
    request: Request,
    name: str = Form(...),
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")
    
    clean_name = name.strip()
    
    # Use the service function to create category safely
    # This handles checking for existing categories to avoid IntegrityError
    from app.schemas import CategoryCreate
    from app.services.category_service import create_category
    
    cat_schema = CategoryCreate(name=clean_name)
    try:
        new_cat = create_category(db, cat_schema, user.id)
        return RedirectResponse(url="/categories?msg=Category Added Successfully", status_code=303)
    except Exception as e:
        # If create_category raises an exception (other than IntegrityError which it handles), catch it here
        print(f"Error adding category: {e}")
        return RedirectResponse(url=f"/categories?error=Server Error: {e}", status_code=303)

@app.post("/categories/delete/{cat_id}")
async def delete_category(
    cat_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user) 
):
    category = db.query(Category).filter(Category.id == cat_id).first()
    
    if category:
        if user.role.name == 'admin' or category.user_id == user.id:
            db.delete(category)
            db.commit()
            
    return RedirectResponse(url="/categories", status_code=status.HTTP_303_SEE_OTHER)


# ================= SETTINGS & ADMIN PANEL =================

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    page: int = 1, 
    user_page: int = 1, 
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")

    all_users = []
    global_transactions = []
    PAGE_SIZE = 10
    USER_PAGE_SIZE = 5
    total_pages = 1
    user_total_pages = 1

    if user.role.name == "admin":
        # 1. Fetch Users
        total_users = db.query(User).count()
        user_total_pages = math.ceil(total_users / USER_PAGE_SIZE) if total_users > 0 else 1
        user_start = (user_page - 1) * USER_PAGE_SIZE
        all_users = db.query(User).offset(user_start).limit(USER_PAGE_SIZE).all()

        # 2. Fetch Transactions
        all_expenses = db.query(Expense).all()
        all_transfers = db.query(Transfer).all()

        for exp in all_expenses:
            t = exp.__dict__.copy()
            if '_sa_instance_state' in t: del t['_sa_instance_state']
            t['type'] = 'expense'
            t['amount'] = exp.debit
            t['user_name'] = exp.user.username if exp.user else "Unknown"
            global_transactions.append(t)
            
        for tr in all_transfers:
            t = tr.__dict__.copy()
            if '_sa_instance_state' in t: del t['_sa_instance_state']
            t['type'] = 'transfer'
            t['description'] = t.get('description', 'Transfer')
            t['user_name'] = tr.receiver.username if tr.receiver else "Unknown"
            global_transactions.append(t)

        # Sort and Paginate
        global_transactions.sort(key=lambda x: x['created_at'], reverse=True)
        total_items = len(global_transactions)
        total_pages = math.ceil(total_items / PAGE_SIZE) if total_items > 0 else 1
        
        start = (page - 1) * PAGE_SIZE
        end = start + PAGE_SIZE
        global_transactions = global_transactions[start:end]

    return templates.TemplateResponse("settings.html", {
        "request": request, 
        "user": user,
        "all_users": all_users,
        "global_transactions": global_transactions,
        "current_page": page,
        "total_pages": total_pages,
        "user_current_page": user_page,
        "user_total_pages": user_total_pages
    })


# --- PROFILE & PASSWORD UPDATE ROUTES ---

@app.post("/settings/update-profile")
async def update_profile(
    username: str = Form(...),
    email: str = Form(...),
    profile_pic: UploadFile = File(None),
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")

    existing = db.query(User).filter(
        (User.username == username) | (User.email == email),
        User.id != user.id
    ).first()

    if existing:
        return RedirectResponse(url="/settings?error=Username or Email already taken", status_code=303)

    if profile_pic and profile_pic.filename:
        upload_dir = "static/profile_pics"
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)

        file_extension = profile_pic.filename.split(".")[-1]
        # Use timestamp to ensure unique filename and bypass browser caching
        timestamp = int(time.time())
        file_name = f"{user.id}_profile_{timestamp}.{file_extension}"
        file_path = f"{upload_dir}/{file_name}"
        
        # Remove old profile picture if exists
        if user.profile_picture:
            old_path = f"{upload_dir}/{user.profile_picture}"
            if os.path.exists(old_path):
                os.remove(old_path)
        
        await profile_pic.seek(0)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(profile_pic.file, buffer)

        user.profile_picture = file_name

    user.username = username
    user.email = email
    db.commit()
    
    return RedirectResponse(url="/settings?msg=Profile Updated", status_code=303)


@app.post("/settings/change-password")
async def change_password(
    current_password: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")

    if not pwd_context.verify(current_password, user.hashed_password):
        return RedirectResponse(url="/settings?error=Incorrect Old Password", status_code=303)

    user.hashed_password = pwd_context.hash(new_password)
    db.commit()

    return RedirectResponse(url="/settings?msg=Password Changed Successfully", status_code=303)


# --- ADMIN ACTIONS ---

@app.post("/users/promote/{user_id}")
async def promote_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_user = Depends(get_admin_user) 
):
    target_user = db.query(User).filter(User.id == user_id).first()
    if target_user:
        admin_role = db.query(Role).filter(Role.name == "admin").first()
        if admin_role:
            target_user.role_id = admin_role.id
            db.commit()
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/users/demote/{user_id}")
async def demote_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_user = Depends(get_admin_user) 
):
    if user_id == admin_user.id:
        return RedirectResponse(url="/settings?error=Cannot demote yourself", status_code=303)

    target_user = db.query(User).filter(User.id == user_id).first()
    if target_user:
        user_role = db.query(Role).filter(Role.name == "user").first()
        if user_role:
            target_user.role_id = user_role.id
            db.commit()
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/admin/transactions/delete/{type}/{id}")
async def admin_delete_transaction(
    type: str, 
    id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_admin_user)
):
    entry = None
    if type == "expense":
        entry = db.query(Expense).filter(Expense.id == id).first()
    else:
        entry = db.query(Transfer).filter(Transfer.id == id).first()
        
    if entry:
        db.delete(entry)
        db.commit()
        
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


# --- API: Get Single User Details (For Admin Modal) ---
@app.get("/admin/user-details/{target_user_id}")
async def get_user_details(
    target_user_id: int,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: Session = Depends(get_db),
    admin_user = Depends(get_admin_user)
):
    user = db.query(User).filter(User.id == target_user_id).first()
    if not user:
        return JSONResponse({"error": "User not found"}, status_code=404)

    # Base queries
    exp_query = db.query(Expense).filter(Expense.user_id == user.id)
    tr_query = db.query(Transfer).filter((Transfer.sender_id == user.id) | (Transfer.receiver_id == user.id))

    # Apply Filters
    if start_date:
        try:
            s_date = datetime.strptime(start_date, "%Y-%m-%d")
            exp_query = exp_query.filter(Expense.created_at >= s_date)
            tr_query = tr_query.filter(Transfer.created_at >= s_date)
        except ValueError:
            pass 
            
    if end_date:
        try:
            e_date = datetime.strptime(end_date, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            exp_query = exp_query.filter(Expense.created_at <= e_date)
            tr_query = tr_query.filter(Transfer.created_at <= e_date)
        except ValueError:
            pass

    expenses = exp_query.all()
    transfers = tr_query.all()

    transactions = []
    total_income = 0
    total_expense = 0

    for exp in expenses:
        total_expense += exp.debit
        transactions.append({
            "type": "expense",
            "description": exp.description,
            "amount": exp.debit,
            "date": exp.created_at.strftime('%Y-%m-%d'),
            "category": exp.category.name if exp.category else "General"
        })

    for tr in transfers:
        total_income += tr.amount
        transactions.append({
            "type": "transfer",
            "description": tr.description or "Transfer",
            "amount": tr.amount,
            "date": tr.created_at.strftime('%Y-%m-%d'),
            "category": "Income"
        })

    transactions.sort(key=lambda x: x['date'], reverse=True)

    return JSONResponse({
        "username": user.username,
        "email": user.email,
        "profile_pic": user.profile_picture,
        "role": user.role.name,
        "balance": total_income - total_expense,
        "total_income": total_income,
        "total_expense": total_expense,
        "transactions": transactions
    })

# --- ADMIN ONLY: EXPORT SPECIFIC USER DATA (Filtered) ---
@app.get("/admin/export/{target_user_id}")
async def admin_export_user_csv(
    target_user_id: int,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: Session = Depends(get_db),
    admin_user = Depends(get_admin_user)
):
    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Base Queries
    exp_query = db.query(Expense).filter(Expense.user_id == target_user.id)
    tr_query = db.query(Transfer).filter((Transfer.sender_id == target_user.id) | (Transfer.receiver_id == target_user.id))

    # Apply Date Filter
    if start_date:
        try:
            s_date = datetime.strptime(start_date, "%Y-%m-%d")
            exp_query = exp_query.filter(Expense.created_at >= s_date)
            tr_query = tr_query.filter(Transfer.created_at >= s_date)
        except ValueError:
            pass 
            
    if end_date:
        try:
            e_date = datetime.strptime(end_date, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            exp_query = exp_query.filter(Expense.created_at <= e_date)
            tr_query = tr_query.filter(Transfer.created_at <= e_date)
        except ValueError:
            pass

    expenses = exp_query.all()
    transfers = tr_query.all()

    # CSV Generation
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Type', 'Category', 'Description', 'Amount'])

    all_data = []
    for exp in expenses:
        cat_name = exp.category.name if exp.category else "General"
        all_data.append([exp.created_at, "Expense", cat_name, exp.description, -exp.debit])

    for tr in transfers:
        all_data.append([tr.created_at, "Income", "Transfer", tr.description, tr.amount])

    all_data.sort(key=lambda x: x[0], reverse=True)

    for row in all_data:
        row[0] = row[0].strftime("%Y-%m-%d %H:%M")
        writer.writerow(row)

    output.seek(0)
    filename = f"{target_user.username}_report.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# --- EXPORT DATA TO CSV (For Logged-in User) ---
@app.get("/export/csv")
async def export_transactions_csv(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")

    exp_query = db.query(Expense).filter(Expense.user_id == user.id)
    tr_query = db.query(Transfer).filter((Transfer.sender_id == user.id) | (Transfer.receiver_id == user.id))

    if start_date:
        try:
            s_date = datetime.strptime(start_date, "%Y-%m-%d")
            exp_query = exp_query.filter(Expense.created_at >= s_date)
            tr_query = tr_query.filter(Transfer.created_at >= s_date)
        except ValueError:
            pass

    if end_date:
        try:
            e_date = datetime.strptime(end_date, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            exp_query = exp_query.filter(Expense.created_at <= e_date)
            tr_query = tr_query.filter(Transfer.created_at <= e_date)
        except ValueError:
            pass

    expenses = exp_query.all()
    transfers = tr_query.all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Type', 'Category', 'Description', 'Amount'])

    all_data = []
    for exp in expenses:
        cat_name = exp.category.name if exp.category else "General"
        all_data.append([exp.created_at, "Expense", cat_name, exp.description, -exp.debit])

    for tr in transfers:
        all_data.append([tr.created_at, "Income", "Transfer", tr.description, tr.amount])

    all_data.sort(key=lambda x: x[0], reverse=True)

    for row in all_data:
        row[0] = row[0].strftime("%Y-%m-%d %H:%M")
        writer.writerow(row)

    output.seek(0)
    filename = "transactions_report.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# --- FORGOT PASSWORD LOGIC ---

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.post("/forgot-password")
async def send_reset_otp(
    request: Request, 
    email: str = Form(...), 
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Email not found!"})

    otp = "".join(random.choices(string.digits, k=6))
    user.reset_otp = otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    db.commit()

    try:
        await send_otp_email(email, otp)
    except Exception as e:
        print(f"Mail Error: {e}")
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Failed to send email."})

    return RedirectResponse(url=f"/reset-password?email={email}", status_code=303)

@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request, email: str):
    return templates.TemplateResponse("reset_password.html", {"request": request, "email": email})

@app.post("/reset-password")
async def perform_reset(
    request: Request,
    email: str = Form(...),
    otp: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        return templates.TemplateResponse("reset_password.html", {"request": request, "email": email, "error": "User not found"})

    if user.reset_otp != otp:
        return templates.TemplateResponse("reset_password.html", {"request": request, "email": email, "error": "Invalid OTP"})
    
    if user.otp_expiry and datetime.utcnow() > user.otp_expiry:
        return templates.TemplateResponse("reset_password.html", {"request": request, "email": email, "error": "OTP Expired"})

    if len(new_password) > 72:
         return templates.TemplateResponse("reset_password.html", {
            "request": request, 
            "email": email, 
            "error": "Password too long! Keep it under 72 characters."
        })

    user.hashed_password = pwd_context.hash(new_password)
    user.reset_otp = None
    user.otp_expiry = None
    db.commit()

    return RedirectResponse(url="/login?msg=Password Reset Successful", status_code=303)

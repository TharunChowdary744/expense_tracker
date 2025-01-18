from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson.objectid import ObjectId
import os

# App setup
app = FastAPI()

# MongoDB setup
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = MongoClient(MONGO_URI)
db = client.auth_db
users_collection = db.users
expenses_collection = db.expenses

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT setup
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Pydantic models
class UserBase(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=3, max_length=50)
    currency: str = Field(..., min_length=3, max_length=3)  # Added currency to user profile

class UserCreate(UserBase):
    password: str = Field(..., min_length=6)

class UserInDB(UserBase):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None

class ExpenseBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    category: str = Field(..., min_length=3, max_length=50)
    type: str = Field(..., pattern="^(income|expense)$")  # Either 'income' or 'expense'
    amount: float = Field(..., gt=0)
    currency: str = Field(..., min_length=3, max_length=3)
    created_date: datetime | None = None
    last_updated_date: datetime | None = None
    is_recurring: bool = False
    recurrence_interval: str | None = None  # daily, weekly, monthly

class ExpenseCreate(ExpenseBase):
    pass

class ExpenseInDB(ExpenseBase):
    id: str

# OAuth2 scheme for bearer token authentication
oauth2_scheme = HTTPBearer()

# Utility functions
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_email(email: str):
    user = users_collection.find_one({"email": email})
    if user:
        return UserInDB(**user)
    return None

# Dependencies
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials.")
        user = get_user_by_email(email)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials.")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials.")

# API Endpoints
@app.post("/register", response_model=UserBase)
def register(user: UserCreate):
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered.")

    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict["hashed_password"] = hashed_password
    del user_dict["password"]

    result = users_collection.insert_one(user_dict)
    user_dict["id"] = str(result.inserted_id)

    return UserBase(**user_dict)

@app.post("/login", response_model=Token)
def login(email: EmailStr, password: str):
    user = get_user_by_email(email)
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)

    return Token(access_token=access_token, token_type="bearer")

@app.get("/profile", response_model=UserBase)
def get_profile(current_user: UserBase = Depends(get_current_user)):
    return current_user

# Expense Management Endpoints
@app.post("/expenses", response_model=ExpenseInDB)
def create_expense(expense: ExpenseCreate, current_user: UserBase = Depends(get_current_user)):
    if expense.is_recurring and not expense.recurrence_interval:
        raise HTTPException(status_code=400, detail="Recurring expenses must have a recurrence interval.")

    expense_dict = expense.dict()
    expense_dict.update({
        "created_date": datetime.utcnow(),
        "last_updated_date": datetime.utcnow(),
        "user_id": current_user.email
    })
    result = expenses_collection.insert_one(expense_dict)
    expense_dict["id"] = str(result.inserted_id)

    return ExpenseInDB(**expense_dict)

@app.put("/expenses/{expense_id}", response_model=ExpenseInDB)
def update_expense(expense_id: str, expense: ExpenseCreate, current_user: UserBase = Depends(get_current_user)):
    existing_expense = expenses_collection.find_one({"_id": ObjectId(expense_id), "user_id": current_user.email})
    if not existing_expense:
        raise HTTPException(status_code=404, detail="Expense not found.")

    if expense.is_recurring and not expense.recurrence_interval:
        raise HTTPException(status_code=400, detail="Recurring expenses must have a recurrence interval.")

    update_data = expense.dict()
    update_data["last_updated_date"] = datetime.utcnow()

    expenses_collection.update_one({"_id": ObjectId(expense_id)}, {"$set": update_data})

    existing_expense.update(update_data)
    existing_expense["id"] = str(existing_expense["_id"])
    return ExpenseInDB(**existing_expense)

@app.get("/expenses", response_model=list[ExpenseInDB])
def get_expenses(start_date: datetime | None = None, end_date: datetime | None = None, category: str | None = None, type: str | None = None, current_user: UserBase = Depends(get_current_user)):
    query = {"user_id": current_user.email}
    if start_date:
        query["created_date"] = {"$gte": start_date}
    if end_date:
        query["created_date"] = query.get("created_date", {})
        query["created_date"].update({"$lte": end_date})
    if category:
        query["category"] = category
    if type:
        query["type"] = type

    expenses = expenses_collection.find(query)
    return [
        ExpenseInDB(
            id=str(expense["_id"]),
            name=expense["name"],
            category=expense["category"],
            type=expense["type"],
            amount=expense["amount"],
            currency=expense["currency"],
            created_date=expense["created_date"],
            last_updated_date=expense["last_updated_date"],
            is_recurring=expense.get("is_recurring", False),
            recurrence_interval=expense.get("recurrence_interval")
        ) for expense in expenses
    ]

@app.delete("/expenses/{expense_id}", response_model=dict)
def delete_expense(expense_id: str, current_user: UserBase = Depends(get_current_user)):
    existing_expense = expenses_collection.find_one({"_id": ObjectId(expense_id), "user_id": current_user.email})
    if not existing_expense:
        raise HTTPException(status_code=404, detail="Expense not found.")

    if existing_expense.get("is_recurring"):
        expenses_collection.delete_many({"recurrence_group": existing_expense.get("recurrence_group")})
    else:
        result = expenses_collection.delete_one({"_id": ObjectId(expense_id)})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Expense not found.")

    return {"message": "Expense deleted successfully."}

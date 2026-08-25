"""
الباشا للسجائر - Backend API (v2)
POS, Inventory, Mixes (single-active workflow), Debt Ledger, Expenses, role-aware analytics.
"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from typing import List, Optional, Literal
from datetime import datetime, timezone, timedelta, date
from pathlib import Path
import os, uuid, logging, bcrypt, jwt
try:
    from zoneinfo import ZoneInfo
    PS_TZ = ZoneInfo("Asia/Hebron")
except Exception:  # pragma: no cover
    PS_TZ = timezone(timedelta(hours=2))

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET = os.environ.get("JWT_SECRET", "al-basha-super-secret-key-change-me-in-prod")
JWT_ALG = "HS256"
TOKEN_HOURS = 24 * 7

client = AsyncIOMotorClient(MONGO_URL, tz_aware=True, tzinfo=timezone.utc)
db = client[DB_NAME]

app = FastAPI(title="Al-Basha Cigarettes API")
api = APIRouter(prefix="/api")
bearer = HTTPBearer(auto_error=False)

MIX_CIG_NAME = "سجائر نيكوتين"
MIX_HERB_NAME = "أعشاب بالجرام"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def clean(doc: dict) -> dict:
    if doc:
        doc.pop("_id", None)
    return doc

def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(10)).decode()

def check_pw(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode())
    except Exception:
        return False

def issue_token(user: dict) -> str:
    payload = {
        "sub": user["id"], "username": user["username"], "role": user["role"],
        "iat": now_utc(), "exp": now_utc() + timedelta(hours=TOKEN_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

async def current_user(cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> dict:
    if not cred or cred.scheme.lower() != "bearer":
        raise HTTPException(401, "غير مصرح")
    try:
        payload = jwt.decode(cred.credentials, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(401, "الجلسة منتهية")
    user = await db.users.find_one({"id": payload["sub"], "disabled": {"$ne": True}}, {"_id": 0, "hashed_password": 0})
    if not user:
        raise HTTPException(401, "المستخدم غير موجود")
    return user

def require_owner(user: dict = Depends(current_user)) -> dict:
    if user.get("role") != "owner":
        raise HTTPException(403, "هذه العملية للمالك فقط")
    return user

def day_bounds(d: date):
    # Palestine-local midnight → UTC range
    start_local = datetime.combine(d, datetime.min.time()).replace(tzinfo=PS_TZ)
    start = start_local.astimezone(timezone.utc)
    return start, start + timedelta(days=1)

def ps_today() -> date:
    return datetime.now(PS_TZ).date()

def parse_date(s: Optional[str]) -> date:
    if not s:
        return ps_today()
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        return ps_today()

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class LoginIn(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: str
    username: str
    display_name: str
    role: str

class UserCreate(BaseModel):
    username: str
    password: str
    display_name: str
    role: Literal["owner", "employee"] = "employee"

class UserPatch(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    display_name: Optional[str] = None
    disabled: Optional[bool] = None

class InventoryCreate(BaseModel):
    name: str
    unit: str
    quantity: float = 0
    cost_price: float = 0
    selling_price: float = 0
    min_threshold: float = 5
    category: Optional[str] = None

class InventoryUpdate(BaseModel):
    name: Optional[str] = None
    unit: Optional[str] = None
    quantity: Optional[float] = None
    cost_price: Optional[float] = None
    selling_price: Optional[float] = None
    min_threshold: Optional[float] = None
    category: Optional[str] = None

class RestockIn(BaseModel):
    quantity: float

class CartItem(BaseModel):
    item_id: str
    name: str
    quantity: float
    unit_price: float
    is_mix: bool = False
    is_herb: bool = False

class SaleCreate(BaseModel):
    transaction_type: Literal["sale", "debt_payment"] = "sale"
    customer_name: Optional[str] = None
    customer_phone: Optional[str] = None
    items: List[CartItem] = []
    discount: float = 0
    payment_method: str
    debt_payment_amount: Optional[float] = None
    created_by_role: Optional[str] = None

class MixCreate(BaseModel):
    nicotine_ml: float = 0
    herb_grams: float = 0
    price_per_cig: float
    cost_per_cig: float = 0.018
    herb_price_per_gram: float = 0
    nicotine_item_id: Optional[str] = None
    herb_item_id: Optional[str] = None
    created_by_role: Optional[str] = None

class MixUpdate(BaseModel):
    price_per_cig: Optional[float] = None
    cost_per_cig: Optional[float] = None
    herb_price_per_gram: Optional[float] = None
    nicotine_ml: Optional[float] = None
    herb_grams: Optional[float] = None

class CustomerPatch(BaseModel):
    notes: Optional[str] = None
    debt_blocked: Optional[bool] = None

class ManualDebtIn(BaseModel):
    name: str
    phone: Optional[str] = None
    amount: float
    note: Optional[str] = None

class ExpenseCreate(BaseModel):
    category: str
    amount: float
    note: Optional[str] = None
    expense_date: Optional[str] = None
    created_by_role: Optional[str] = None

class ExpenseUpdate(BaseModel):
    category: Optional[str] = None
    amount: Optional[float] = None
    note: Optional[str] = None
    expense_date: Optional[str] = None

# ---------------------------------------------------------------------------
# Auth / Users
# ---------------------------------------------------------------------------

@api.post("/auth/login")
async def login(data: LoginIn):
    user = await db.users.find_one({"username": data.username.lower().strip()}, {"_id": 0})
    if not user or user.get("disabled") or not check_pw(data.password, user.get("hashed_password", "")):
        raise HTTPException(401, "اسم المستخدم أو كلمة المرور غير صحيحة")
    token = issue_token(user)
    public = {k: user[k] for k in ("id", "username", "display_name", "role")}
    return {"access_token": token, "token_type": "bearer", "user": public}

@api.get("/auth/me", response_model=UserOut)
async def me(user: dict = Depends(current_user)):
    return {k: user[k] for k in ("id", "username", "display_name", "role")}

@api.get("/users")
async def list_users(_: dict = Depends(require_owner)):
    return await db.users.find({}, {"_id": 0, "hashed_password": 0}).to_list(500)

@api.post("/users", response_model=UserOut)
async def create_user(data: UserCreate, _: dict = Depends(require_owner)):
    if await db.users.find_one({"username": data.username.lower().strip()}):
        raise HTTPException(409, "اسم المستخدم مستخدم بالفعل")
    doc = {
        "id": str(uuid.uuid4()), "username": data.username.lower().strip(),
        "display_name": data.display_name, "role": data.role,
        "hashed_password": hash_pw(data.password), "disabled": False, "created_at": now_utc(),
    }
    await db.users.insert_one(doc)
    return {k: doc[k] for k in ("id", "username", "display_name", "role")}

@api.patch("/users/{user_id}", response_model=UserOut)
async def update_user(user_id: str, data: UserPatch, _: dict = Depends(require_owner)):
    target = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not target:
        raise HTTPException(404, "المستخدم غير موجود")
    changes: dict = {}
    if data.display_name is not None:
        if not data.display_name.strip():
            raise HTTPException(422, "الاسم لا يمكن أن يكون فارغاً")
        changes["display_name"] = data.display_name.strip()
    if data.username is not None:
        uname = data.username.lower().strip()
        if len(uname) < 3:
            raise HTTPException(422, "اسم المستخدم قصير جداً")
        clash = await db.users.find_one({"username": uname, "id": {"$ne": user_id}})
        if clash:
            raise HTTPException(409, "اسم المستخدم مستخدم بالفعل")
        changes["username"] = uname
    if data.password is not None:
        if len(data.password.encode("utf-8")) > 72:
            raise HTTPException(422, "كلمة المرور طويلة جداً")
        if len(data.password) < 4:
            raise HTTPException(422, "كلمة المرور قصيرة جداً")
        changes["hashed_password"] = hash_pw(data.password)
    if data.disabled is not None:
        if target.get("role") == "owner" and data.disabled:
            owners = await db.users.count_documents({"role": "owner", "disabled": {"$ne": True}})
            if owners <= 1:
                raise HTTPException(400, "لا يمكن تعطيل المالك الوحيد")
        changes["disabled"] = data.disabled
    if not changes:
        raise HTTPException(400, "لا يوجد بيانات للتحديث")
    changes["updated_at"] = now_utc()
    try:
        await db.users.update_one({"id": user_id}, {"$set": changes})
    except Exception:
        raise HTTPException(409, "اسم المستخدم مستخدم بالفعل")
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "hashed_password": 0})
    return {k: updated[k] for k in ("id", "username", "display_name", "role")}

@api.delete("/users/{user_id}")
async def delete_user(user_id: str, owner: dict = Depends(require_owner)):
    target = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not target:
        raise HTTPException(404, "المستخدم غير موجود")
    if target["id"] == owner["id"]:
        raise HTTPException(400, "لا يمكنك حذف حسابك")
    if target.get("role") == "owner":
        owners = await db.users.count_documents({"role": "owner"})
        if owners <= 1:
            raise HTTPException(400, "لا يمكن حذف المالك الوحيد")
    await db.users.delete_one({"id": user_id})
    return {"ok": True}

# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

@api.get("/inventory")
async def list_inventory(_: dict = Depends(current_user)):
    return await db.inventory.find({}, {"_id": 0}).sort("name", 1).to_list(1000)

@api.post("/inventory")
async def create_inventory(data: InventoryCreate, _: dict = Depends(current_user)):
    doc = {"id": str(uuid.uuid4()), **data.dict(), "created_at": now_utc()}
    await db.inventory.insert_one(doc)
    return clean(doc)

@api.patch("/inventory/{item_id}")
async def update_inventory(item_id: str, data: InventoryUpdate, _: dict = Depends(current_user)):
    patch = {k: v for k, v in data.dict().items() if v is not None}
    if not patch:
        raise HTTPException(400, "لا يوجد بيانات للتحديث")
    r = await db.inventory.update_one({"id": item_id}, {"$set": patch})
    if r.matched_count == 0:
        raise HTTPException(404, "الصنف غير موجود")
    return {"ok": True}

@api.post("/inventory/{item_id}/restock")
async def restock(item_id: str, data: RestockIn, _: dict = Depends(current_user)):
    r = await db.inventory.update_one({"id": item_id}, {"$inc": {"quantity": data.quantity}})
    if r.matched_count == 0:
        raise HTTPException(404, "الصنف غير موجود")
    return {"ok": True}

@api.delete("/inventory/{item_id}")
async def delete_inventory(item_id: str, _: dict = Depends(current_user)):
    r = await db.inventory.delete_one({"id": item_id})
    if r.deleted_count == 0:
        raise HTTPException(404, "الصنف غير موجود")
    return {"ok": True}

# ---------------------------------------------------------------------------
# Mixes
# ---------------------------------------------------------------------------

async def recompute_mix(mix: dict) -> dict:
    material = mix.get("nicotine_cost", 0) + mix.get("herb_cost", 0)
    consumables = mix.get("cost_per_cig", 0) * mix.get("sold_cigarettes", 0)
    mix["material_cost"] = material
    mix["total_cost"] = material + consumables
    mix["total_sales"] = (mix.get("price_per_cig", 0) * mix.get("sold_cigarettes", 0)
                          + mix.get("herb_price_per_gram", 0) * mix.get("herb_sold_grams", 0))
    mix["profit"] = mix["total_sales"] - mix["total_cost"]
    return mix

def strip_mix_for_employee(mix: dict) -> dict:
    for k in ("total_cost", "material_cost", "profit", "nicotine_cost", "herb_cost", "cost_per_cig", "total_sales", "created_by"):
        mix.pop(k, None)
    return mix

def strip_sale_for_employee(sale: dict) -> dict:
    if not sale:
        return sale
    sale.pop("profit", None); sale.pop("cost_total", None)
    for it in sale.get("items", []):
        it.pop("cost_price", None)
    return sale

@api.get("/mixes")
async def list_mixes(user: dict = Depends(current_user)):
    mixes = await db.mixes.find({}, {"_id": 0}).sort("mix_number", -1).to_list(500)
    if user.get("role") != "owner":
        mixes = [strip_mix_for_employee(m) for m in mixes]
    return mixes

@api.get("/mixes/active")
async def active_mix(user: dict = Depends(current_user)):
    m = await db.mixes.find_one({"status": "active"}, {"_id": 0})
    if not m:
        return {}
    if user.get("role") != "owner":
        m = strip_mix_for_employee(m)
    return m

@api.post("/mixes")
async def create_mix(data: MixCreate, user: dict = Depends(current_user)):
    # Validate the new mix first. The current mix must stay active if the
    # new mix cannot be created (for example, because stock is insufficient).
    nic_cost = 0.0
    herb_cost = 0.0
    nic_id = data.nicotine_item_id
    herb_id = data.herb_item_id

    # Auto-detect nicotine/herb items if not provided
    if not nic_id and data.nicotine_ml > 0:
        it = await db.inventory.find_one({"unit": "مل"}, {"_id": 0})
        nic_id = it["id"] if it else None
    if not herb_id and data.herb_grams > 0:
        it = await db.inventory.find_one({"unit": "جرام"}, {"_id": 0})
        herb_id = it["id"] if it else None

    nic = None
    herb = None
    if nic_id and data.nicotine_ml > 0:
        nic = await db.inventory.find_one({"id": nic_id}, {"_id": 0})
        if not nic:
            raise HTTPException(404, "صنف النيكوتين غير موجود")
        if nic["quantity"] < data.nicotine_ml:
            raise HTTPException(400, "كمية النيكوتين غير كافية")
        nic_cost = nic["cost_price"] * data.nicotine_ml

    if herb_id and data.herb_grams > 0:
        herb = await db.inventory.find_one({"id": herb_id}, {"_id": 0})
        if not herb:
            raise HTTPException(404, "صنف العشبة غير موجود")
        if herb["quantity"] < data.herb_grams:
            raise HTTPException(400, "كمية العشبة غير كافية")
        herb_cost = herb["cost_price"] * data.herb_grams

    # The business rule is single-active-mix: creating a new mix means the
    # previous one has finished. Its profit is finalized and transferred to
    # the main profit reports exactly once at this point.
    active = await db.mixes.find_one({"status": "active"}, {"_id": 0})
    if active:
        await recompute_mix(active)
        settlement = {
            "id": str(uuid.uuid4()),
            "mix_id": active["id"],
            "mix_number": active.get("mix_number"),
            "profit": active.get("profit", 0.0),
            "total_sales": active.get("total_sales", 0.0),
            "total_cost": active.get("total_cost", 0.0),
            "created_at": now_utc(),
        }
        # Upsert makes the transfer idempotent: a mix can only contribute
        # one settlement record to the main profit totals.
        await db.mix_profit_settlements.update_one(
            {"mix_id": active["id"]},
            {"$setOnInsert": settlement},
            upsert=True,
        )
        await db.mixes.update_one(
            {"id": active["id"]},
            {"$set": {
                "status": "ended",
                "ended_at": settlement["created_at"],
                "profit_transferred_at": settlement["created_at"],
            }},
        )

    # Only after validation/finalization do we consume the raw materials.
    if nic_id and data.nicotine_ml > 0:
        await db.inventory.update_one({"id": nic_id}, {"$inc": {"quantity": -data.nicotine_ml}})
    if herb_id and data.herb_grams > 0:
        await db.inventory.update_one({"id": herb_id}, {"$inc": {"quantity": -data.herb_grams}})

    last = await db.mixes.find_one({"mix_number": {"$exists": True}}, {"_id": 0}, sort=[("mix_number", -1)])
    mix_number = (last.get("mix_number", 0) + 1) if last else 1

    doc = {
        "id": str(uuid.uuid4()),
        "mix_number": mix_number,
        "nicotine_ml": data.nicotine_ml,
        "herb_grams": data.herb_grams,
        "price_per_cig": data.price_per_cig,
        "cost_per_cig": data.cost_per_cig,
        "herb_price_per_gram": data.herb_price_per_gram,
        "nicotine_item_id": nic_id,
        "herb_item_id": herb_id,
        "nicotine_cost": nic_cost,
        "herb_cost": herb_cost,
        "sold_cigarettes": 0,
        "herb_sold_grams": 0,
        "status": "active",
        "created_by": user["username"],
        "created_by_role": data.created_by_role or user.get("role"),
        "created_at": now_utc(),
        "ended_at": None,
        "profit_transferred_at": None,
    }
    await recompute_mix(doc)
    await db.mixes.insert_one(doc)
    result = clean(dict(doc))
    if user.get("role") != "owner":
        result = strip_mix_for_employee(result)
    return result

@api.patch("/mixes/{mix_id}")
async def update_mix(mix_id: str, data: MixUpdate, user: dict = Depends(current_user)):
    mix = await db.mixes.find_one({"id": mix_id}, {"_id": 0})
    if not mix:
        raise HTTPException(404, "الخلطة غير موجودة")
    updates: dict = {}

    # Adjust nicotine stock (deduct/return the delta from the linked inventory item)
    if data.nicotine_ml is not None and data.nicotine_ml != mix.get("nicotine_ml", 0):
        new_ml = data.nicotine_ml
        if new_ml < 0:
            raise HTTPException(400, "كمية النيكوتين غير صحيحة")
        delta = new_ml - mix.get("nicotine_ml", 0)
        nic_id = mix.get("nicotine_item_id")
        if nic_id:
            nic = await db.inventory.find_one({"id": nic_id}, {"_id": 0})
            if nic:
                if delta > 0 and nic["quantity"] < delta:
                    raise HTTPException(400, "كمية النيكوتين غير كافية في المخزون")
                await db.inventory.update_one({"id": nic_id}, {"$inc": {"quantity": -delta}})
                updates["nicotine_cost"] = nic.get("cost_price", 0) * new_ml
        updates["nicotine_ml"] = new_ml

    # Adjust herb stock (cannot drop below already-sold grams)
    if data.herb_grams is not None and data.herb_grams != mix.get("herb_grams", 0):
        new_g = data.herb_grams
        sold = mix.get("herb_sold_grams", 0)
        if new_g < sold:
            raise HTTPException(400, f"لا يمكن أن تقل كمية العشبة عن المباع ({round(sold, 2)} جرام)")
        delta = new_g - mix.get("herb_grams", 0)
        herb_id = mix.get("herb_item_id")
        if herb_id:
            herb = await db.inventory.find_one({"id": herb_id}, {"_id": 0})
            if herb:
                if delta > 0 and herb["quantity"] < delta:
                    raise HTTPException(400, "كمية العشبة غير كافية في المخزون")
                await db.inventory.update_one({"id": herb_id}, {"$inc": {"quantity": -delta}})
                updates["herb_cost"] = herb.get("cost_price", 0) * new_g
        updates["herb_grams"] = new_g

    if data.price_per_cig is not None:
        if data.price_per_cig <= 0:
            raise HTTPException(400, "سعر السيجارة غير صحيح")
        updates["price_per_cig"] = data.price_per_cig
    if data.cost_per_cig is not None and user.get("role") == "owner":
        updates["cost_per_cig"] = data.cost_per_cig
    if data.herb_price_per_gram is not None:
        updates["herb_price_per_gram"] = data.herb_price_per_gram

    if updates:
        mix.update(updates)
        await recompute_mix(mix)
        updates["material_cost"] = mix["material_cost"]
        updates["total_cost"] = mix["total_cost"]
        updates["total_sales"] = mix["total_sales"]
        updates["profit"] = mix["profit"]
        await db.mixes.update_one({"id": mix_id}, {"$set": updates})
        mix = await db.mixes.find_one({"id": mix_id}, {"_id": 0})

    if user.get("role") != "owner":
        mix = strip_mix_for_employee(mix)
    return mix

@api.delete("/mixes/{mix_id}")
async def delete_mix(mix_id: str, user: dict = Depends(current_user)):
    mix = await db.mixes.find_one({"id": mix_id}, {"_id": 0})
    if not mix:
        raise HTTPException(404, "الخلطة غير موجودة")
    # Ended mixes can only be deleted by the owner; active mixes may be deleted
    # by anyone with blend access (owner or employee).
    if mix.get("status") != "active" and user.get("role") != "owner":
        raise HTTPException(403, "غير مصرح بحذف الخلطات المنتهية")
    # Deleting an ACTIVE mix undoes the production batch → return raw materials.
    if mix.get("status") == "active":
        nic_id = mix.get("nicotine_item_id")
        if nic_id and mix.get("nicotine_ml", 0) > 0:
            await db.inventory.update_one({"id": nic_id}, {"$inc": {"quantity": mix["nicotine_ml"]}})
        herb_id = mix.get("herb_item_id")
        if herb_id and mix.get("herb_grams", 0) > 0:
            await db.inventory.update_one({"id": herb_id}, {"$inc": {"quantity": mix["herb_grams"]}})
    await db.mixes.delete_one({"id": mix_id})
    return {"ok": True}

# ---------------------------------------------------------------------------
# Customers helper
# ---------------------------------------------------------------------------

async def _upsert_customer(name: Optional[str], phone: Optional[str]) -> Optional[str]:
    if not name and not phone:
        return None
    key = {"phone": phone} if phone else {"name": name}
    c = await db.customers.find_one(key, {"_id": 0})
    if c:
        return c["id"]
    doc = {"id": str(uuid.uuid4()), "name": name or "زبون", "phone": phone or "", "balance": 0, "created_at": now_utc()}
    await db.customers.insert_one(doc)
    return doc["id"]

# ---------------------------------------------------------------------------
# Sales / POS
# ---------------------------------------------------------------------------

@api.post("/sales")
async def create_sale(data: SaleCreate, user: dict = Depends(current_user)):
    # ---- Debt payment ----
    if data.transaction_type == "debt_payment":
        if not data.customer_phone and not data.customer_name:
            raise HTTPException(400, "الرجاء إدخال بيانات الزبون")
        amount = data.debt_payment_amount or 0
        if amount <= 0:
            raise HTTPException(400, "مبلغ السداد غير صحيح")
        # Strictly validate the customer exists in the debt ledger
        existing = None
        if data.customer_phone:
            existing = await db.customers.find_one({"phone": data.customer_phone}, {"_id": 0})
        if not existing and data.customer_name:
            existing = await db.customers.find_one({"name": data.customer_name}, {"_id": 0})
        if not existing:
            raise HTTPException(404, "الزبون غير موجود في دفتر الديون")
        cid = existing["id"]
        await db.customers.update_one({"id": cid}, {"$inc": {"balance": -amount}})
        sale = {
            "id": str(uuid.uuid4()), "transaction_type": "debt_payment", "customer_id": cid,
            "customer_name": data.customer_name, "customer_phone": data.customer_phone,
            "items": [], "subtotal": 0, "discount": 0, "total": amount,
            "payment_method": data.payment_method, "debt_amount": 0, "cost_total": 0,
            "profit": 0, "cashier": user["username"], "cashier_name": user.get("display_name"),
            "created_by_role": data.created_by_role or user.get("role"), "created_at": now_utc(),
        }
        await db.sales.insert_one(sale)
        await db.debt_ledger.insert_one({
            "id": str(uuid.uuid4()), "customer_id": cid, "sale_id": sale["id"],
            "type": "payment", "amount": amount, "note": f"سداد عبر {data.payment_method}", "created_at": now_utc(),
        })
        return clean(sale)

    # ---- Sale ----
    if not data.items:
        raise HTTPException(400, "السلة فارغة")

    active = await db.mixes.find_one({"status": "active"}, {"_id": 0})
    subtotal = 0.0
    cost_total = 0.0
    validated = []
    mix_sold_add = 0.0
    herb_sold_add = 0.0
    for it in data.items:
        line = it.unit_price * it.quantity
        if it.is_herb:
            if not active:
                raise HTTPException(400, "لا توجد خلطة نشطة لبيع الأعشاب بالجرام")
            remaining = active.get("herb_grams", 0) - active.get("herb_sold_grams", 0) - herb_sold_add
            if it.quantity > remaining + 1e-9:
                raise HTTPException(400, f"الكمية أكبر من المتوفر في الخلطة (المتبقي {round(max(0, remaining), 2)} جرام)")
            subtotal += line
            herb_sold_add += it.quantity
            validated.append({
                "item_id": "MIX_HERB", "name": MIX_HERB_NAME, "quantity": it.quantity,
                "unit_price": it.unit_price, "cost_price": 0,
                "line_total": line, "is_herb": True, "mix_number": active["mix_number"],
            })
        elif it.is_mix:
            if not active:
                raise HTTPException(400, "لا توجد خلطة نشطة لبيع سجائر النيكوتين")
            # Mix-cigarette cost/profit is finalized with the mix, not with
            # the individual sale. The sale still records its revenue.
            subtotal += line
            mix_sold_add += it.quantity
            validated.append({
                "item_id": "MIX_CIG", "name": MIX_CIG_NAME, "quantity": it.quantity,
                "unit_price": it.unit_price, "cost_price": active.get("cost_per_cig", 0),
                "line_total": line, "is_mix": True, "mix_number": active["mix_number"],
            })
        else:
            inv = await db.inventory.find_one({"id": it.item_id}, {"_id": 0})
            if not inv:
                raise HTTPException(404, f"الصنف غير موجود: {it.name}")
            if inv["quantity"] < it.quantity:
                raise HTTPException(400, f"الكمية غير كافية للصنف: {inv['name']}")
            subtotal += line
            cost_total += inv.get("cost_price", 0) * it.quantity
            validated.append({
                "item_id": it.item_id, "name": it.name, "quantity": it.quantity,
                "unit_price": it.unit_price, "cost_price": inv.get("cost_price", 0),
                "line_total": line, "is_mix": False,
            })
            await db.inventory.update_one({"id": it.item_id}, {"$inc": {"quantity": -it.quantity}})

    # Accumulate to active mix
    if (mix_sold_add > 0 or herb_sold_add > 0) and active:
        active["sold_cigarettes"] = active.get("sold_cigarettes", 0) + mix_sold_add
        active["herb_sold_grams"] = active.get("herb_sold_grams", 0) + herb_sold_add
        await recompute_mix(active)
        await db.mixes.update_one({"id": active["id"]}, {"$set": {
            "sold_cigarettes": active["sold_cigarettes"], "herb_sold_grams": active["herb_sold_grams"],
            "material_cost": active["material_cost"], "total_cost": active["total_cost"],
            "total_sales": active["total_sales"], "profit": active["profit"],
        }})

    total = max(0.0, subtotal - (data.discount or 0))

    # Only non-mix inventory items contribute profit immediately. Revenue
    # from mix cigarettes is deferred to the mix settlement. If a discount
    # exists, allocate it proportionally across the invoice lines so the mix
    # portion does not accidentally become immediate profit.
    discount = max(0.0, data.discount or 0)
    mix_sales = sum(it.get("line_total", 0) for it in validated if it.get("is_mix") or it.get("is_herb"))
    immediate_sales = sum(it.get("line_total", 0) for it in validated if not (it.get("is_mix") or it.get("is_herb")))
    immediate_discount = (discount * immediate_sales / subtotal) if subtotal > 0 else 0.0
    immediate_sales_after_discount = max(0.0, immediate_sales - immediate_discount)
    immediate_cost = sum(
        it.get("cost_price", 0) * it.get("quantity", 0)
        for it in validated
        if not (it.get("is_mix") or it.get("is_herb"))
    )
    profit = immediate_sales_after_discount - immediate_cost
    customer_id = await _upsert_customer(data.customer_name, data.customer_phone)
    debt_amount = 0.0
    if data.payment_method == "debt":
        if not customer_id:
            raise HTTPException(400, "لا يمكن إنشاء دين بدون بيانات زبون")
        # Customer-specific debt lock (always enforced)
        cust = await db.customers.find_one({"id": customer_id}, {"_id": 0})
        if cust and cust.get("debt_blocked"):
            raise HTTPException(403, "هذا الزبون ممنوع من الشراء بالدين")
        # Global debt freeze — blocks ONLY new customers with no prior debt history
        freeze = await db.settings.find_one({"key": "debt_freeze"}, {"_id": 0})
        if freeze and freeze.get("frozen_date") == ps_today().isoformat():
            prior_charges = await db.debt_ledger.count_documents({"customer_id": customer_id, "type": "charge"})
            had_debt = (cust and cust.get("balance", 0) > 0) or prior_charges > 0
            if not had_debt:
                raise HTTPException(403, "تم إيقاف الديون للعملاء الجدد اليوم — هذا الزبون ليس لديه سجل ديون سابق")
        debt_amount = total
        await db.customers.update_one({"id": customer_id}, {"$inc": {"balance": debt_amount}})

    used_mix = active["mix_number"] if ((mix_sold_add > 0 or herb_sold_add > 0) and active) else None
    sale = {
        "id": str(uuid.uuid4()), "transaction_type": "sale", "customer_id": customer_id,
        "customer_name": data.customer_name, "customer_phone": data.customer_phone,
        "items": validated, "subtotal": subtotal, "discount": data.discount or 0, "total": total,
        "payment_method": data.payment_method, "debt_amount": debt_amount, "cost_total": immediate_cost,
        "profit": profit, "mix_number": used_mix,
        "cashier": user["username"], "cashier_name": user.get("display_name"),
        "created_by_role": data.created_by_role or user.get("role"),
        "created_at": now_utc(),
    }
    await db.sales.insert_one(sale)
    if debt_amount > 0:
        await db.debt_ledger.insert_one({
            "id": str(uuid.uuid4()), "customer_id": customer_id, "sale_id": sale["id"],
            "type": "charge", "amount": debt_amount, "note": f"مبيعات دين ({len(validated)} صنف)", "created_at": now_utc(),
        })
    result = clean(dict(sale))
    if user.get("role") != "owner":
        result = strip_sale_for_employee(result)
    return result

@api.get("/sales")
async def list_sales(limit: int = 300, date: Optional[str] = None, user: dict = Depends(current_user)):
    query = {}
    if date:
        start, end = day_bounds(parse_date(date))
        query["created_at"] = {"$gte": start, "$lt": end}
    sales = await db.sales.find(query, {"_id": 0}).sort("created_at", -1).to_list(limit)
    if user.get("role") != "owner":
        for s in sales:
            s.pop("profit", None); s.pop("cost_total", None)
            for it in s.get("items", []):
                it.pop("cost_price", None)
    return sales

@api.get("/sales/{sale_id}")
async def get_sale(sale_id: str, user: dict = Depends(current_user)):
    sale = await db.sales.find_one({"id": sale_id}, {"_id": 0})
    if not sale:
        raise HTTPException(404, "الفاتورة غير موجودة")
    if user.get("role") != "owner":
        sale = strip_sale_for_employee(sale)
    return sale

@api.delete("/sales/{sale_id}")
async def refund_sale(sale_id: str, _: dict = Depends(require_owner)):
    sale = await db.sales.find_one({"id": sale_id}, {"_id": 0})
    if not sale:
        raise HTTPException(404, "الفاتورة غير موجودة")

    # Restore stock / reverse mix accumulation
    for it in sale.get("items", []):
        if it.get("is_mix") or it.get("is_herb"):
            mix = await db.mixes.find_one({"mix_number": it.get("mix_number")}, {"_id": 0})
            if mix:
                if it.get("is_mix"):
                    mix["sold_cigarettes"] = max(0, mix.get("sold_cigarettes", 0) - it.get("quantity", 0))
                if it.get("is_herb"):
                    mix["herb_sold_grams"] = max(0, mix.get("herb_sold_grams", 0) - it.get("quantity", 0))
                await recompute_mix(mix)
                await db.mixes.update_one({"id": mix["id"]}, {"$set": {
                    "sold_cigarettes": mix["sold_cigarettes"], "herb_sold_grams": mix.get("herb_sold_grams", 0),
                    "material_cost": mix["material_cost"], "total_cost": mix["total_cost"],
                    "total_sales": mix["total_sales"], "profit": mix["profit"],
                }})
                # If this mix was already finalized, keep its one settlement
                # record synchronized after a refund so the main profit report
                # remains correct and does not double-count the refunded sale.
                await db.mix_profit_settlements.update_one(
                    {"mix_id": mix["id"]},
                    {"$set": {
                        "profit": mix["profit"],
                        "total_sales": mix["total_sales"],
                        "total_cost": mix["total_cost"],
                    }},
                )
        else:
            await db.inventory.update_one({"id": it["item_id"]}, {"$inc": {"quantity": it.get("quantity", 0)}})

    # Reverse customer balance effects
    cid = sale.get("customer_id")
    if cid:
        if sale.get("transaction_type") == "sale" and sale.get("debt_amount", 0) > 0:
            await db.customers.update_one({"id": cid}, {"$inc": {"balance": -sale["debt_amount"]}})
        elif sale.get("transaction_type") == "debt_payment":
            await db.customers.update_one({"id": cid}, {"$inc": {"balance": sale.get("total", 0)}})

    await db.debt_ledger.delete_many({"sale_id": sale_id})
    await db.sales.delete_one({"id": sale_id})
    return {"ok": True}

# ---------------------------------------------------------------------------
# Expenses (owner only)
# ---------------------------------------------------------------------------

@api.get("/expenses")
async def list_expenses(date: Optional[str] = None, _: dict = Depends(require_owner)):
    query = {}
    if date:
        start, end = day_bounds(parse_date(date))
        query["created_at"] = {"$gte": start, "$lt": end}
    return await db.expenses.find(query, {"_id": 0}).sort("created_at", -1).to_list(500)

@api.post("/expenses")
async def create_expense(data: ExpenseCreate, user: dict = Depends(require_owner)):
    created = now_utc()
    if data.expense_date:
        d = parse_date(data.expense_date)
        created = datetime.combine(d, now_utc().time()).replace(tzinfo=timezone.utc)
    doc = {
        "id": str(uuid.uuid4()), "category": data.category, "amount": data.amount,
        "note": data.note or "", "created_by": user["username"],
        "created_by_role": data.created_by_role or user.get("role"), "created_at": created,
    }
    await db.expenses.insert_one(doc)
    return clean(doc)

@api.delete("/expenses/{eid}")
async def delete_expense(eid: str, _: dict = Depends(require_owner)):
    r = await db.expenses.delete_one({"id": eid})
    if r.deleted_count == 0:
        raise HTTPException(404, "المصروف غير موجود")
    return {"ok": True}

@api.patch("/expenses/{eid}")
async def update_expense(eid: str, data: ExpenseUpdate, _: dict = Depends(require_owner)):
    patch: dict = {}
    if data.category is not None:
        patch["category"] = data.category
    if data.amount is not None:
        if data.amount <= 0:
            raise HTTPException(422, "المبلغ غير صحيح")
        patch["amount"] = data.amount
    if data.note is not None:
        patch["note"] = data.note
    if data.expense_date is not None:
        d = parse_date(data.expense_date)
        patch["created_at"] = datetime.combine(d, now_utc().time()).replace(tzinfo=timezone.utc)
    if not patch:
        raise HTTPException(400, "لا يوجد بيانات للتحديث")
    r = await db.expenses.update_one({"id": eid}, {"$set": patch})
    if r.matched_count == 0:
        raise HTTPException(404, "المصروف غير موجود")
    updated = await db.expenses.find_one({"id": eid}, {"_id": 0})
    return updated

# ---------------------------------------------------------------------------
# Customers / Debts
# ---------------------------------------------------------------------------

@api.get("/customers")
async def list_customers(all: bool = False, _: dict = Depends(current_user)):
    query = {} if all else {"balance": {"$gt": 0.001}}
    return await db.customers.find(query, {"_id": 0}).sort("balance", -1).to_list(1000)

@api.get("/customers/{cid}")
async def get_customer(cid: str, user: dict = Depends(current_user)):
    c = await db.customers.find_one({"id": cid}, {"_id": 0})
    if not c:
        raise HTTPException(404, "الزبون غير موجود")
    ledger = await db.debt_ledger.find({"customer_id": cid}, {"_id": 0}).sort("created_at", -1).to_list(500)
    sales = await db.sales.find({"customer_id": cid}, {"_id": 0}).sort("created_at", -1).to_list(200)
    if user.get("role") != "owner":
        for s in sales:
            s.pop("profit", None); s.pop("cost_total", None)
    return {"customer": c, "ledger": ledger, "sales": sales}

@api.patch("/customers/{cid}")
async def patch_customer(cid: str, data: CustomerPatch, _: dict = Depends(current_user)):
    patch = {}
    if data.notes is not None:
        patch["notes"] = data.notes
    if data.debt_blocked is not None:
        patch["debt_blocked"] = data.debt_blocked
    if not patch:
        raise HTTPException(400, "لا يوجد بيانات للتحديث")
    r = await db.customers.update_one({"id": cid}, {"$set": patch})
    if r.matched_count == 0:
        raise HTTPException(404, "الزبون غير موجود")
    return {"ok": True}

@api.post("/customers/manual-debt")
async def manual_debt(data: ManualDebtIn, user: dict = Depends(current_user)):
    if data.amount <= 0:
        raise HTTPException(400, "المبلغ غير صحيح")
    cid = await _upsert_customer(data.name, data.phone)
    await db.customers.update_one({"id": cid}, {"$inc": {"balance": data.amount}})
    await db.debt_ledger.insert_one({
        "id": str(uuid.uuid4()), "customer_id": cid, "sale_id": None, "type": "charge",
        "amount": data.amount, "note": data.note or "دين سابق (يدوي)",
        "created_by": user["username"], "created_at": now_utc(),
    })
    c = await db.customers.find_one({"id": cid}, {"_id": 0})
    return c

@api.post("/customers/{cid}/forgive")
async def forgive_debt(cid: str, owner: dict = Depends(require_owner)):
    c = await db.customers.find_one({"id": cid}, {"_id": 0})
    if not c:
        raise HTTPException(404, "الزبون غير موجود")
    bal = c.get("balance", 0)
    await db.customers.update_one({"id": cid}, {"$set": {"balance": 0}})
    await db.debt_ledger.insert_one({
        "id": str(uuid.uuid4()), "customer_id": cid, "sale_id": None, "type": "forgive",
        "amount": bal, "note": "إعفاء / مسح الدين", "created_by": owner["username"], "created_at": now_utc(),
    })
    return {"ok": True}

# ---- Global debt freeze (settings) ----
@api.get("/settings/debt-freeze")
async def get_debt_freeze(_: dict = Depends(current_user)):
    doc = await db.settings.find_one({"key": "debt_freeze"}, {"_id": 0})
    frozen = bool(doc and doc.get("frozen_date") == ps_today().isoformat())
    return {"frozen_today": frozen, "date": ps_today().isoformat()}

@api.post("/settings/debt-freeze")
async def set_debt_freeze(_: dict = Depends(require_owner)):
    today = ps_today().isoformat()
    existing = await db.settings.find_one({"key": "debt_freeze"}, {"_id": 0})
    if existing and existing.get("frozen_date") == today:
        await db.settings.update_one({"key": "debt_freeze"}, {"$set": {"frozen_date": None}})
        return {"frozen_today": False}
    await db.settings.update_one({"key": "debt_freeze"}, {"$set": {"frozen_date": today}}, upsert=True)
    return {"frozen_today": True}

# ---- Profit report (custom range, owner) ----
@api.get("/reports/profit")
async def profit_report(start: str, end: str, owner: dict = Depends(require_owner)):
    s = parse_date(start)
    e = parse_date(end)
    start_dt, _ = day_bounds(s)
    _, end_dt = day_bounds(e)
    total_sales = 0.0
    gross = 0.0
    count = 0
    channels: dict = {}
    async for sale in db.sales.find({"created_at": {"$gte": start_dt, "$lt": end_dt}, "transaction_type": "sale"}, {"_id": 0}):
        total_sales += sale.get("total", 0)
        gross += sale.get("profit", 0)
        count += 1
        pm = sale.get("payment_method", "cash")
        ch = channels.setdefault(pm, {"sales": 0.0, "profit": 0.0, "count": 0})
        ch["sales"] += sale.get("total", 0); ch["profit"] += sale.get("profit", 0); ch["count"] += 1
    # Add finalized mix profits on the date the mix was closed.
    async for settlement in db.mix_profit_settlements.find(
        {"created_at": {"$gte": start_dt, "$lt": end_dt}}, {"_id": 0}
    ):
        gross += settlement.get("profit", 0)

    expenses = 0.0
    async for ex in db.expenses.find({"created_at": {"$gte": start_dt, "$lt": end_dt}}, {"_id": 0}):
        expenses += ex.get("amount", 0)
    return {
        "start": s.isoformat(), "end": e.isoformat(),
        "total_sales": total_sales, "gross_profit": gross,
        "expenses": expenses, "net_profit": gross - expenses,
        "sales_count": count, "channels": channels,
    }

# ---------------------------------------------------------------------------
# Dashboard (role-aware)
# ---------------------------------------------------------------------------

@api.get("/dashboard/summary")
async def dashboard_summary(date: Optional[str] = None, user: dict = Depends(current_user)):
    d = parse_date(date)
    start, end = day_bounds(d)
    is_owner = user.get("role") == "owner"

    total_sales = 0.0
    gross_profit = 0.0
    sales_count = 0
    channels: dict = {}
    async for s in db.sales.find({"created_at": {"$gte": start, "$lt": end}, "transaction_type": "sale"}, {"_id": 0}):
        total_sales += s.get("total", 0)
        gross_profit += s.get("profit", 0)
        sales_count += 1
        pm = s.get("payment_method", "cash")
        ch = channels.setdefault(pm, {"sales": 0.0, "profit": 0.0, "count": 0})
        ch["sales"] += s.get("total", 0)
        ch["profit"] += s.get("profit", 0)
        ch["count"] += 1

    # Finalized mix profits are realized on the day the mix is closed.
    async for settlement in db.mix_profit_settlements.find(
        {"created_at": {"$gte": start, "$lt": end}}, {"_id": 0}
    ):
        gross_profit += settlement.get("profit", 0)

    daily_expenses = 0.0
    async for e in db.expenses.find({"created_at": {"$gte": start, "$lt": end}}, {"_id": 0}):
        daily_expenses += e.get("amount", 0)
    net_profit = gross_profit - daily_expenses

    total_debt = 0.0
    debtors = 0
    async for c in db.customers.find({"balance": {"$gt": 0.001}}, {"_id": 0}):
        total_debt += c["balance"]
        debtors += 1

    low_stock = []
    async for i in db.inventory.find({}, {"_id": 0}):
        if i["quantity"] <= i.get("min_threshold", 0):
            low_stock.append(i)

    out = {
        "date": d.isoformat(),
        "daily_sales": total_sales,
        "sales_count": sales_count,
        "low_stock": low_stock,
        "low_stock_count": len(low_stock),
        "is_owner": is_owner,
    }
    if is_owner:
        out.update({
            "daily_gross_profit": gross_profit,
            "daily_expenses": daily_expenses,
            "daily_net_profit": net_profit,
            "channels": channels,
            "total_debt": total_debt,
            "debtors_count": debtors,
        })
    return out

# ---------------------------------------------------------------------------
# Seed
# ---------------------------------------------------------------------------

async def seed_defaults():
    if not await db.users.find_one({"username": "owner"}):
        await db.users.insert_one({
            "id": str(uuid.uuid4()), "username": "owner", "display_name": "الباشا (المالك)",
            "role": "owner", "hashed_password": hash_pw("owner123"), "disabled": False, "created_at": now_utc(),
        })
    if not await db.users.find_one({"username": "employee"}):
        await db.users.insert_one({
            "id": str(uuid.uuid4()), "username": "employee", "display_name": "موظف الكاشير",
            "role": "employee", "hashed_password": hash_pw("employee123"), "disabled": False, "created_at": now_utc(),
        })
    if await db.inventory.count_documents({}) == 0:
        items = [
            ("مارلبورو أحمر", "علبة", 40, 22, 30, 10, "سجائر"),
            ("مارلبورو أزرق", "علبة", 35, 22, 30, 10, "سجائر"),
            ("كامل أزرق", "علبة", 25, 20, 28, 8, "سجائر"),
            ("وينستون", "علبة", 18, 18, 25, 10, "سجائر"),
            ("لاكي سترايك", "علبة", 12, 20, 27, 10, "سجائر"),
            ("كرتونة مارلبورو", "كرتونة", 5, 200, 280, 2, "سجائر"),
            ("سائل النيكوتين 100مل", "مل", 500, 0.6, 0, 100, "خلطات"),
            ("عشبة طبيعية", "جرام", 800, 0.3, 0, 150, "خلطات"),
            ("ورق لف", "علبة", 60, 3, 5, 15, "خلطات"),
            ("فلاتر سجائر", "علبة", 55, 4, 7, 15, "خلطات"),
            ("ولاعة", "قطعة", 30, 2, 5, 10, "إكسسوارات"),
        ]
        for name, unit, qty, cost, sell, minthr, cat in items:
            await db.inventory.insert_one({
                "id": str(uuid.uuid4()), "name": name, "unit": unit, "quantity": qty,
                "cost_price": cost, "selling_price": sell, "min_threshold": minthr,
                "category": cat, "created_at": now_utc(),
            })
    if await db.customers.count_documents({}) == 0:
        for name, phone, balance in [("أبو أحمد", "0599123456", 150), ("سامر الحداد", "0598765432", 85), ("محمد العلي", "0597654321", 0)]:
            cid = str(uuid.uuid4())
            await db.customers.insert_one({"id": cid, "name": name, "phone": phone, "balance": balance, "created_at": now_utc()})
            if balance > 0:
                await db.debt_ledger.insert_one({
                    "id": str(uuid.uuid4()), "customer_id": cid, "sale_id": None,
                    "type": "charge", "amount": balance, "note": "رصيد سابق", "created_at": now_utc(),
                })

@app.on_event("startup")
async def on_startup():
    await db.users.create_index("username", unique=True)
    await db.inventory.create_index("id", unique=True)
    await db.sales.create_index("id", unique=True)
    await db.customers.create_index("id", unique=True)
    await seed_defaults()

@app.on_event("shutdown")
async def on_shutdown():
    client.close()

@api.get("/")
async def root():
    return {"app": "الباشا للسجائر", "status": "ok"}

app.include_router(api)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
logging.basicConfig(level=logging.INFO)

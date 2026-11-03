import uuid

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from deps import get_current_user, get_db
from models import Document, Invoice, Order, User
from schemas import (DocumentOut, InvoiceOut, InvoiceUpdate, LoginIn,
                     OrderOut, OrderUpdate, TokenOut, UserOut)
from security import create_token, verify_password

router = APIRouter()


def get_or_404(db: Session, model, object_id):
    obj = db.get(model, object_id)
    if obj is None:
        raise HTTPException(status_code=404, detail="Not found")
    return obj


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == body.username))
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return TokenOut(access_token=create_token(user.id))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


# ---------- invoices (integer IDs) ----------

@router.get("/invoices", response_model=list[InvoiceOut])
def list_my_invoices(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.scalars(
        select(Invoice).where(Invoice.owner_id == user.id).order_by(Invoice.id)
    ).all()


# VULNERABLE (BOLA, read): any logged-in user can read any invoice
@router.get("/invoices/{invoice_id}", response_model=InvoiceOut)
def get_invoice(invoice_id: int, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    return get_or_404(db, Invoice, invoice_id)


# SAFE (contrast): checks ownership, owner or admin only
@router.put("/invoices/{invoice_id}", response_model=InvoiceOut)
def update_invoice(invoice_id: int, body: InvoiceUpdate,
                   user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    invoice = get_or_404(db, Invoice, invoice_id)
    if invoice.owner_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    invoice.description = body.description
    db.commit()
    db.refresh(invoice)
    return invoice


# ---------- orders (integer IDs) ----------

@router.get("/orders", response_model=list[OrderOut])
def list_my_orders(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.scalars(
        select(Order).where(Order.owner_id == user.id).order_by(Order.id)
    ).all()


# VULNERABLE (BOLA, read)
@router.get("/orders/{order_id}", response_model=OrderOut)
def get_order(order_id: int, user: User = Depends(get_current_user),
              db: Session = Depends(get_db)):
    return get_or_404(db, Order, order_id)


# VULNERABLE (BOLA, write): any logged-in user can change any order
@router.put("/orders/{order_id}", response_model=OrderOut)
def update_order(order_id: int, body: OrderUpdate,
                 user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    order = get_or_404(db, Order, order_id)
    order.status = body.status
    db.commit()
    db.refresh(order)
    return order


# ---------- documents (UUID IDs) ----------

@router.get("/documents", response_model=list[DocumentOut])
def list_my_documents(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.scalars(
        select(Document).where(Document.owner_id == user.id).order_by(Document.created_at)
    ).all()


# VULNERABLE (BOLA, read)
@router.get("/documents/{document_id}", response_model=DocumentOut)
def get_document(document_id: uuid.UUID, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    return get_or_404(db, Document, document_id)


# VULNERABLE (BOLA, delete)
@router.delete("/documents/{document_id}", status_code=204)
def delete_document(document_id: uuid.UUID, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    document = get_or_404(db, Document, document_id)
    db.delete(document)
    db.commit()
    return Response(status_code=204)
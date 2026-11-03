import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class LoginIn(BaseModel):
    username: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: str


class InvoiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    owner_id: int
    amount_cents: int
    description: str
    created_at: datetime


class InvoiceUpdate(BaseModel):
    description: str


class OrderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    owner_id: int
    item: str
    quantity: int
    status: str
    created_at: datetime


class OrderUpdate(BaseModel):
    status: str


class DocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    owner_id: int
    title: str
    content: str
    created_at: datetime
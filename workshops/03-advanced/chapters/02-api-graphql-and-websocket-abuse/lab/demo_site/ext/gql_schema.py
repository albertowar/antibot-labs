"""
The Strawberry GraphQL schema of the store (W3 Ch2 ext, mounted by gql.py).

The schema is small but has the one shape that makes GraphQL abuse interesting: a *circular* relationship.
An ``Order`` has a ``user``, a ``User`` has ``orders``, and each ``Order`` has a ``user`` again. A client can
nest that chain as deep as it likes from a single HTTP request, and each level multiplies the backend work.
The circularity (and the fact that ``users`` hands out every account's e-mail address to anyone who asks) is
the Round 2/3 attack surface, not a modelling mistake.

Every resolver bumps ``context["cost"]`` once per object it produces. That counter is our stand-in for real
backend cost (a DB row read, a downstream call), reported back as ``extensions.cost``. The whole chapter turns
on one number: how much backend cost one HTTP request can buy. In a real system you would measure resolver
time or DB queries; the count is the same idea, made deterministic for the lab.

The types read the starter's own tables (Product, User, Order); nothing here has a table of its own.
"""

from __future__ import annotations

import typing

import strawberry

from demo_site.models import Order as OrderModel
from demo_site.models import Product as ProductModel
from demo_site.models import User as UserModel
from demo_site.models import db


def _bump(info, n: int = 1) -> None:
    ctx = info.context
    ctx["cost"] = ctx.get("cost", 0) + n


@strawberry.type
class Product:
    id: int
    sku: str
    name: str
    price: float
    stock: int


@strawberry.type
class Order:
    id: int
    number: str
    total_cents: int
    status: str
    _user_id: strawberry.Private[typing.Optional[int]]

    @strawberry.field
    def user(self, info: strawberry.Info) -> typing.Optional[User]:
        _bump(info)
        u = db.session.get(UserModel, self._user_id) if self._user_id else None
        return _to_user(u) if u else None


@strawberry.type
class User:
    id: int
    email: str
    _order_ids: strawberry.Private[typing.List[int]]

    @strawberry.field
    def orders(self, info: strawberry.Info) -> typing.List[Order]:
        _bump(info, len(self._order_ids))
        rows = [db.session.get(OrderModel, oid) for oid in self._order_ids]
        return [_to_order(o) for o in rows if o is not None]


def _to_product(p: ProductModel) -> Product:
    return Product(id=p.id, sku=p.sku, name=p.name, price=p.price, stock=p.stock)


def _to_order(o: OrderModel) -> Order:
    return Order(id=o.id, number=o.number, total_cents=o.total_cents, status=o.status, _user_id=o.user_id)


def _to_user(u: UserModel) -> User:
    oids = [oid for (oid,) in db.session.query(OrderModel.id).filter_by(user_id=u.id).order_by(OrderModel.id)]
    return User(id=u.id, email=u.email, _order_ids=oids)


@strawberry.type
class Query:
    @strawberry.field
    def products(self, info: strawberry.Info, first: int = 20) -> typing.List[Product]:
        first = max(1, min(first, 500))
        rows = ProductModel.query.filter_by(hidden=False).order_by(ProductModel.id).limit(first).all()
        _bump(info, len(rows))
        return [_to_product(p) for p in rows]

    @strawberry.field
    def product(self, info: strawberry.Info, id: int) -> typing.Optional[Product]:
        p = db.session.get(ProductModel, id)
        _bump(info)
        return _to_product(p) if p and not p.hidden else None

    @strawberry.field
    def users(self, info: strawberry.Info, first: int = 10) -> typing.List[User]:
        first = max(1, min(first, 100))
        rows = UserModel.query.order_by(UserModel.id).limit(first).all()
        _bump(info, len(rows))
        return [_to_user(u) for u in rows]


schema = strawberry.Schema(query=Query)

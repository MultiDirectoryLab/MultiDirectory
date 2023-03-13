"""LDAP filter asn1 syntax to sqlalchemy conditions interpreter.

RFC 4511 reference.
"""

from operator import eq, ge, le

from sqlalchemy import and_, func, not_, or_

from models.ldap3 import Attribute, Directory, User

from .asn1parser import ASN1Row


def _get_substring(right: ASN1Row) -> str:  # RFC 4511
    expr = right.value[0]
    value = expr.value
    index = expr.tag_id.value
    return [f"{value}%", f"%{value}%", f"%{value}"][index]


def _from_filter(model: type, item, attr, right):
    is_substring = item.tag_id.value == 4
    col = getattr(model, attr)

    if is_substring:
        return col.ilike(_get_substring(right))
    op_method = {3: eq, 5: ge, 6: le}[item.tag_id.value]
    return op_method(func.lower(col), right.value.lower())


def _cast_item(item):
    # present, for e.g. `attibuteName=*`, `(attibuteName)`
    if item.tag_id.value == 7:
        attr = item.value.lower()
        attr = attr.replace('objectcategory', 'objectclass')

        if attr in User.search_fields:
            return not_(eq(getattr(User, attr), None))

        if attr in Directory.search_fields:
            return not_(eq(getattr(Directory, attr), None))

        return func.lower(Attribute.value) == item.value.lower()

    left, right = item.value
    attr = left.value.lower()
    attr = attr.replace('objectcategory', 'objectclass')

    is_substring = item.tag_id.value == 4

    if attr in User.search_fields:
        return _from_filter(User, item, attr, right)
    elif attr in Directory.search_fields:
        return _from_filter(Directory, item, attr, right)

    else:
        if is_substring:
            cond = Attribute.value.ilike(_get_substring(right))
        else:
            cond = func.lower(
                Attribute.value) == right.value.lower()

        return and_(func.lower(Attribute.name) == attr, cond)


def cast_filter2sql(expr: ASN1Row):
    """Recursively cast Filter to SQLAlchemy conditions."""
    if expr.tag_id.value in range(3):
        conditions = []
        for item in expr.value:
            if item.tag_id.value in range(3):  # &|!
                conditions.append(cast_filter2sql(item))
                continue

            conditions.append(_cast_item(item))

        return [and_, or_, not_][expr.tag_id.value](*conditions)

    return _cast_item(expr)

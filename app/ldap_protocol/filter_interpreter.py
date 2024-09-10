"""LDAP filter asn1 syntax to sqlalchemy conditions interpreter.

RFC 4511 reference.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import uuid
from operator import eq, ge, le, ne
from typing import Callable

from ldap_filter import Filter
from sqlalchemy import and_, func, not_, or_, select
from sqlalchemy.sql.elements import UnaryExpression
from sqlalchemy.sql.operators import ColumnOperators

from models.ldap3 import Attribute, Directory, Group, User

from .asn1parser import ASN1Row
from .objects import LDAPMatchingRule
from .utils import find_members_recursive_cte, get_filter_from_path

MEMBERS_ATTRS = {
    'member',
    'memberof',
    f'memberof:{LDAPMatchingRule.LDAP_MATCHING_RULE_TRANSITIVE_EVAL}:',
}


def _get_substring(right: ASN1Row) -> str:  # RFC 4511
    expr = right.value[0]
    value = expr.value
    index = expr.tag_id.value
    return [f"{value}%", f"%{value}%", f"%{value}"][index]


def _from_filter(
    model: type, item: ASN1Row, attr: str, right: ASN1Row,
) -> UnaryExpression:
    is_substring = item.tag_id.value == 4
    col = getattr(model, attr)

    if is_substring:
        return col.ilike(_get_substring(right))
    op_method = {3: eq, 5: ge, 6: le, 8: ne}[item.tag_id.value]
    if attr == 'objectguid':
        col = col
        value = str(uuid.UUID(bytes_le=right.value))
    else:
        col = func.lower(col)
        value = right.value.lower()
    return op_method(col, value)


def _filter_memberof(method: ColumnOperators, dn: str) -> UnaryExpression:
    """Retrieve query conditions with the memberOF attribute."""
    group_id_subquery = select(Group.id).join(  # noqa: ECE001
        Directory.group).join(Directory.path).where(
            get_filter_from_path(dn)).scalar_subquery()

    return method((
        select(Directory.id)
        .join(Directory.groups)
        .where(Group.id == group_id_subquery)
    ))  # type: ignore


def _filter_member(method: ColumnOperators, dn: str) -> UnaryExpression:
    """Retrieve query conditions with the member attribute."""
    user_id_subquery = select(User.id).join(  # noqa: ECE001
        Directory.user).join(Directory.path).where(
            get_filter_from_path(dn)).scalar_subquery()

    return method((
        select(Group.directory_id)
        .join(Group.users)
        .where(User.id == user_id_subquery)
    ))  # type: ignore


def _recursive_filter_memberof(
        method: ColumnOperators, dn: str) -> UnaryExpression:
    """Retrieve query conditions with the memberOF attribute(recursive)."""
    cte = find_members_recursive_cte(dn)

    return method(select(cte.c.directory_id).offset(1))  # type: ignore


def _get_filter_function(column: str) -> Callable[..., UnaryExpression]:
    """Retrieve the appropriate filter function based on the attribute."""
    if len(column.split(':')) == 1:
        attribute = column
        oid = ''
    elif len(column.split(':')) == 3:
        attribute, oid = column.split(':')[:-1]
    else:
        ValueError('Incorrect attribute specified')

    if attribute == 'memberof':  # noqa: R505
        if oid == LDAPMatchingRule.LDAP_MATCHING_RULE_TRANSITIVE_EVAL:
            return _recursive_filter_memberof
        return _filter_memberof
    elif attribute == 'member':
        return _filter_member
    else:
        raise ValueError('Incorrect attribute specified')


def _ldap_filter_by_attribute(
        item: ASN1Row, right: ASN1Row, attribute: str) -> UnaryExpression:
    """Retrieve query conditions based on the specified LDAP attribute."""
    if item.tag_id.value == 3:
        method = Directory.id.in_
    elif item.tag_id.value == 8:
        method = Directory.id.not_in
    else:
        raise ValueError('Incorrect operation method')

    filter_func = _get_filter_function(attribute)
    return filter_func(method, right.value)


def _cast_item(item: ASN1Row) -> UnaryExpression:
    # present, for e.g. `attibuteName=*`, `(attibuteName)`
    if item.tag_id.value == 7:
        attr = item.value.lower().replace('objectcategory', 'objectclass')

        if attr in User.search_fields:
            return not_(eq(getattr(User, attr), None))

        if attr in Directory.search_fields:
            return not_(eq(getattr(Directory, attr), None))

        return func.lower(Attribute.name) == item.value.lower()

    left, right = item.value
    attr = left.value.lower().replace('objectcategory', 'objectclass')

    is_substring = item.tag_id.value == 4

    if attr in User.search_fields:  # noqa: R505
        return _from_filter(User, item, attr, right)
    elif attr in Directory.search_fields:
        return _from_filter(Directory, item, attr, right)
    elif attr in MEMBERS_ATTRS:
        return _ldap_filter_by_attribute(item, right, attr)
    else:
        if is_substring:
            cond = Attribute.value.ilike(_get_substring(right))
        else:
            if isinstance(right.value, str):
                cond = func.lower(Attribute.value) == right.value.lower()
            else:
                cond = func.lower(Attribute.bvalue) == right.value

        return Directory.attributes.any(
            and_(func.lower(Attribute.name) == attr, cond))


def cast_filter2sql(expr: ASN1Row) -> UnaryExpression:
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


def _from_str_filter(
        model: type, is_substring: bool, item: Filter) -> UnaryExpression:
    col = getattr(model, item.attr)

    if is_substring:
        return col.ilike(item.val.replace('*', '%'))
    op_method = {'=': eq, '>=': ge, '<=': le, '~=': ne}[item.comp]
    col = col if item.attr == 'objectguid' else func.lower(col)
    return op_method(col, item.val)


def _api_filter(item: Filter) -> UnaryExpression:
    """Retrieve query conditions based on the specified LDAP attribute."""
    if item.comp == '=':
        method = Directory.id.in_
    elif item.comp == '~=':
        method = Directory.id.not_in
    else:
        raise ValueError('Incorrect operation method')

    filter_func = _get_filter_function(item.attr)
    return filter_func(method, item.val)


def _cast_filt_item(item: Filter) -> UnaryExpression:
    if item.val == '*':
        if item.attr in User.search_fields:
            return not_(eq(getattr(User, item.attr), None))

        if item.attr in Directory.search_fields:
            return not_(eq(getattr(Directory, item.attr), None))

        return func.lower(Attribute.name) == item.attr

    is_substring = item.val.startswith('*') or item.val.endswith('*')

    if item.attr in User.search_fields:  # noqa: R505
        return _from_str_filter(User, is_substring, item)
    elif item.attr in Directory.search_fields:
        return _from_str_filter(Directory, is_substring, item)
    elif item.attr in MEMBERS_ATTRS:
        return _api_filter(item)
    else:
        if is_substring:
            cond = Attribute.value.ilike(item.val.replace('*', '%'))
        else:
            cond = func.lower(Attribute.value) == item.val

        return Directory.attributes.any(
            and_(func.lower(Attribute.name) == item.attr, cond))


def cast_str_filter2sql(expr: Filter) -> UnaryExpression:
    """Cast ldap filter to sa query."""
    if expr.type == "group":
        conditions = []
        for item in expr.filters:
            if expr.type == "group":
                conditions.append(cast_str_filter2sql(item))
                continue

            conditions.append(_cast_filt_item(item))

        return {  # type: ignore
            '&': and_,
            '|': or_,
            '!': not_,
        }[expr.comp](*conditions)

    return _cast_filt_item(expr)

"""LDAP filter asn1 syntax to sqlalchemy conditions interpreter.

RFC 4511 reference.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import uuid
from abc import abstractmethod
from contextlib import suppress
from operator import eq, ge, le, ne
from typing import Callable, Protocol

from ldap_filter import Filter
from sqlalchemy import and_, func, not_, or_, select
from sqlalchemy.sql.elements import (
    BinaryExpression,
    ColumnElement,
    UnaryExpression,
)

from models import Attribute, Directory, EntityType, Group, User

from .asn1parser import ASN1Row, TagNumbers
from .objects import LDAPMatchingRule
from .utils.cte import find_members_recursive_cte, get_filter_from_path

MEMBERS_ATTRS = {
    "member",
    "memberof",
    f"memberof:{LDAPMatchingRule.LDAP_MATCHING_RULE_TRANSITIVE_EVAL}:",
}

class FilterInterpreterProtocol(Protocol):
    """Protocol for filter interpreters."""

    attributes: set[str]

    @abstractmethod
    def cast_to_sql(
        self, expr: ASN1Row | Filter
    ) -> UnaryExpression | ColumnElement:
        """Cast filter expression to SQLAlchemy conditions."""
        ...

    @abstractmethod
    def _cast_item(
        self, item: ASN1Row | Filter
    ) -> UnaryExpression | ColumnElement:
        """Cast a single item to SQLAlchemy condition."""
        ...

    def _get_filter_condition(
        self,
        attr: str,
        condition: BinaryExpression | None = None,
    ) -> ColumnElement:
        if condition is None:
            f = Directory.attributes.any(Attribute.name.ilike(attr))
        else:
            f = Directory.attributes.any(
                and_(Attribute.name.ilike(attr), condition)
            )

        return f

    def _get_filter_function(
        self, column: str
    ) -> Callable[..., UnaryExpression]:
        """Retrieve the appropriate filter function based on the attribute."""
        if len(column.split(":")) == 1:
            attribute = column
            oid = ""
        elif len(column.split(":")) == 3:
            attribute, oid = column.split(":")[:-1]
        else:
            ValueError("Incorrect attribute specified")

        if attribute == "memberof":
            if oid == LDAPMatchingRule.LDAP_MATCHING_RULE_TRANSITIVE_EVAL:
                return self._recursive_filter_memberof
            return self._filter_memberof
        elif attribute == "member":
            return self._filter_member
        else:
            raise ValueError("Incorrect attribute specified")

    def _recursive_filter_memberof(self, dn: str) -> UnaryExpression:
        """Retrieve query conditions with the memberOF attribute(recursive)."""
        cte = find_members_recursive_cte(dn)

        return Directory.id.in_(select(cte.c.directory_id).offset(1))  # type: ignore

    def _filter_memberof(self, dn: str) -> UnaryExpression:
        """Retrieve query conditions with the memberOF attribute."""
        group_id_subquery = (
            select(Group.id)
            .join(Group.directory)
            .where(get_filter_from_path(dn))
            .scalar_subquery()
        )

        return Directory.id.in_(
            (
                select(Directory.id)
                .join(Directory.groups)
                .where(Group.id == group_id_subquery)
                .distinct(Directory.id)
            ),
        )  # type: ignore

    def _filter_member(self, dn: str) -> UnaryExpression:
        """Retrieve query conditions with the member attribute."""
        user_id_subquery = (
            select(User.id)
            .join(User.directory)
            .where(get_filter_from_path(dn))
            .scalar_subquery()
        )

        return Directory.id.in_(
            (
                select(Group.directory_id)
                .join(Group.users)
                .where(User.id == user_id_subquery)
                .distinct(Group.directory_id)
            ),
        )  # type: ignore


class LDAPFilterInterpreter(FilterInterpreterProtocol):
    """LDAP filter interpreter for SQLAlchemy."""

    def __init__(self) -> None:
        """Initialize the interpreter."""
        self.attributes = set()

    def cast_to_sql(self, expr: ASN1Row) -> UnaryExpression | ColumnElement:
        """Recursively cast Filter to SQLAlchemy conditions."""
        if expr.tag_id in range(3):
            conditions = []
            for item in expr.value:
                if item.tag_id in range(3):  # &|!
                    conditions.append(self.cast_to_sql(item))
                    continue

                conditions.append(self._cast_item(item))

            return [and_, or_, not_][expr.tag_id](*conditions)  # type: ignore

        return self._cast_item(expr)

    def _cast_item(self, item: ASN1Row) -> UnaryExpression | ColumnElement:
        # present, for e.g. `attibuteName=*`, `(attibuteName)`
        if item.tag_id == 7:
            attr = item.value.lower().replace("objectcategory", "objectclass")

            self.attributes.add(attr)

            if attr in User.search_fields:
                return not_(eq(getattr(User, attr), None))

            if attr in Directory.search_fields:
                return not_(eq(getattr(Directory, attr), None))

            return self._get_filter_condition(attr)

        if (
            len(item.value) == 3
            and isinstance(item.value[1].value, bytes)
            and item.value[1].value.decode("utf-8").lower() in MEMBERS_ATTRS
        ):
            return self._ldap_filter_by_attribute(*item.value)  # NOTE: oid

        left, right = item.value
        attr = left.value.lower().replace("objectcategory", "objectclass")

        self.attributes.add(attr)

        is_substring = item.tag_id == TagNumbers.SUBSTRING

        if attr in User.search_fields:
            return self._from_filter(User, item, attr, right)
        elif attr in Directory.search_fields:
            return self._from_filter(Directory, item, attr, right)
        elif attr in MEMBERS_ATTRS:  # NOTE: without oid
            return self._ldap_filter_by_attribute(None, left, right)
        elif attr == "entitytypename":
            return func.lower(EntityType.name) == right.lower()
        else:
            if is_substring:
                cond = Attribute.value.ilike(self._get_substring(right))
            else:
                if isinstance(right.value, str):
                    cond = Attribute.value.ilike(right.value)
                else:
                    cond = Attribute.bvalue == right.value

            return self._get_filter_condition(attr, cond)

    def _ldap_filter_by_attribute(
        self,
        oid: ASN1Row | None,
        attr: ASN1Row,
        search_value: ASN1Row,
    ) -> UnaryExpression:
        """Retrieve query conditions based on the specified LDAP attribute."""
        if oid is None:
            attribute = attr.value.lower()
        else:
            attribute = f"{attr.value.decode('utf-8').lower()}:{oid.value}:"

        self.attributes.add(attribute)

        value = search_value.value
        filter_func = self._get_filter_function(attribute)
        return filter_func(value)

    def _get_substring(self, right: ASN1Row) -> str:  # RFC 4511
        expr = right.value[0]
        value = expr.value
        if isinstance(value, bytes):
            with suppress(UnicodeDecodeError):
                value = value.decode()
        index = expr.tag_id
        return [f"{value}%", f"%{value}%", f"%{value}"][index]

    def _from_filter(
        self,
        model: type,
        item: ASN1Row,
        attr: str,
        right: ASN1Row,
    ) -> UnaryExpression:
        is_substring = item.tag_id == TagNumbers.SUBSTRING
        col = getattr(model, attr)

        if is_substring:
            return col.ilike(self._get_substring(right))
        op_method = {3: eq, 5: ge, 6: le, 8: ne}[item.tag_id]
        if attr == "objectguid":
            col = col
            value = str(uuid.UUID(bytes_le=right.value))
        else:
            col = func.lower(col)
            value = right.value.lower()
        return op_method(col, value)


class StringFilterInterpreter(FilterInterpreterProtocol):
    """String filter interpreter for SQLAlchemy."""

    def __init__(self) -> None:
        """Initialize the interpreter."""
        self.attributes = set()

    def cast_to_sql(self, expr: Filter) -> UnaryExpression | ColumnElement:
        """Cast ldap filter to sa query."""
        if expr.type == "group":
            conditions = []
            for item in expr.filters:
                if expr.type == "group":
                    conditions.append(self.cast_to_sql(item))
                    continue

                conditions.append(self._cast_item(item))

            return {  # type: ignore
                "&": and_,
                "|": or_,
                "!": not_,
            }[expr.comp](*conditions)

        return self._cast_item(expr)

    def _cast_item(self, item: Filter) -> UnaryExpression | ColumnElement:
        if item.val == "*":
            if item.attr in User.search_fields:
                return not_(eq(getattr(User, item.attr), None))

            if item.attr in Directory.search_fields:
                return not_(eq(getattr(Directory, item.attr), None))

            return self._get_filter_condition(item.attr)

        is_substring = item.val.startswith("*") or item.val.endswith("*")

        if item.attr in User.search_fields:
            return self._from_str_filter(User, is_substring, item)
        elif item.attr in Directory.search_fields:
            return self._from_str_filter(Directory, is_substring, item)
        elif item.attr in MEMBERS_ATTRS:
            return self._api_filter(item)
        elif item.attr == "entitytypename":
            return func.lower(EntityType.name) == item.val.lower()
        else:
            if is_substring:
                cond = Attribute.value.ilike(item.val.replace("*", "%"))
            else:
                cond = Attribute.value.ilike(item.val)

            return self._get_filter_condition(item.attr, cond)

    def _from_str_filter(
        self,
        model: type,
        is_substring: bool,
        item: Filter,
    ) -> UnaryExpression:
        col = getattr(model, item.attr)

        if is_substring:
            return col.ilike(item.val.replace("*", "%"))
        op_method = {"=": eq, ">=": ge, "<=": le, "~=": ne}[item.comp]
        col = col if item.attr == "objectguid" else func.lower(col)
        return op_method(col, item.val)

    def _api_filter(self, item: Filter) -> UnaryExpression:
        """Retrieve query conditions based on the specified LDAP attribute."""
        filter_func = self._get_filter_function(item.attr)
        return filter_func(item.val)

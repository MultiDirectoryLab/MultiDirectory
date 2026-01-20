"""LDAP filter asn1 syntax to sqlalchemy conditions interpreter.

RFC 4511 reference.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import uuid
from abc import abstractmethod
from contextlib import suppress
from datetime import datetime
from operator import eq, ge, le, ne
from typing import Callable, Protocol

from ldap_filter import Filter
from sqlalchemy import BigInteger, and_, cast, func, not_, or_, select
from sqlalchemy.sql.elements import (
    BinaryExpression,
    ColumnElement,
    UnaryExpression,
)
from sqlalchemy.sql.expression import false as sql_false

from entities import (
    Attribute,
    AttributeType,
    Directory,
    EntityType,
    Group,
    User,
)
from ldap_protocol.utils.helpers import ft_to_dt
from ldap_protocol.utils.queries import get_path_filter, get_search_path
from repo.pg.tables import groups_table, queryable_attr as qa, users_table

from .asn1parser import ASN1Row, TagNumbers
from .objects import LDAPMatchingRule
from .utils.cte import find_members_recursive_cte, get_filter_from_path

_MEMBERS_ATTRS = {
    "member",
    "memberof",
    f"memberof:{LDAPMatchingRule.LDAP_MATCHING_RULE_TRANSITIVE_EVAL}:",
}

_RULE_POS = 0
_ATTR_POS = 1
_VALUE_POS = 2


class FilterInterpreterProtocol(Protocol):
    """Protocol for filter interpreters."""

    attributes: set[str]

    @abstractmethod
    def cast_to_sql(
        self,
        expr: ASN1Row | Filter,
    ) -> UnaryExpression | ColumnElement:
        """Cast filter expression to SQLAlchemy conditions."""
        ...

    @abstractmethod
    def _cast_item(
        self,
        item: ASN1Row | Filter,
    ) -> UnaryExpression | ColumnElement:
        """Cast a single item to SQLAlchemy condition."""
        ...

    def _get_filter_condition(
        self,
        attr: str,
        condition: BinaryExpression | None = None,
    ) -> ColumnElement:
        if condition is None:
            f = qa(Directory).attributes.any(
                qa(Attribute.name).ilike(attr),
            )
        else:
            f = qa(Directory).attributes.any(
                and_(qa(Attribute.name).ilike(attr), condition),
            )

        return f

    def _get_anr_filter(self, val: str) -> ColumnElement[bool]:
        """Get query expressions by rule aNR. Let P1=False and let P2=False.

        Docs:
            ms-adts/1a9177f4-0272-4ab8-aa22-3c3eafd39e4b
        """
        if val.startswith("*"):
            return sql_false()

        attributes_expr = []
        dir_user_expr = []
        normalized: str = val.strip().lower().replace("*", "")

        is_first_char_equal = normalized.startswith("=")  # NOTE: algorithm 6.a
        is_space_contains = bool(" " in normalized)  # NOTE: algorithm 6.c.ii.i

        if is_first_char_equal:
            vl = normalized.replace("=", "")
            attributes_expr.append(
                and_(
                    qa(Attribute.name).in_(
                        select(qa(AttributeType.name))
                        .where(qa(AttributeType.is_included_anr).is_(True)),
                    ),
                    func.lower(Attribute.value) == vl,
                ),
            )  # fmt: skip

            attributes_expr.append(
                and_(
                    qa(Attribute.name) == "cn",
                    func.lower(Attribute.value) == vl,
                ),
            )  # fmt: skip

            dir_user_expr.extend(
                [
                    qa(Directory.name) == vl,
                    qa(User.mail) == vl,
                    qa(User.samaccountname) == vl,
                    qa(User.displayname) == vl,
                ],
            )  # fmt: skip
        else:
            vl = f"{normalized}%"
            attributes_expr.append(
                and_(
                    qa(Attribute.name).in_(
                        select(qa(AttributeType.name))
                        .where(qa(AttributeType.is_included_anr).is_(True)),
                    ),
                    qa(Attribute.value).ilike(vl),
                ),
            )  # fmt: skip

            attributes_expr.append(
                and_(
                    qa(Attribute.name) == "cn",
                    qa(Attribute.value).ilike(vl),
                ),
            )  # fmt: skip

            dir_user_expr.extend(
                [
                    qa(Directory.name).ilike(vl),
                    qa(User.mail).ilike(vl),
                    qa(User.samaccountname).ilike(vl),
                    qa(User.displayname).ilike(vl),
                ],
            )  # fmt: skip

        if is_space_contains:
            # NOTE: algorithm 6.c.i
            fn, sn = normalized.replace("=", "").split(" ")[:2]

            givenname_fn = qa(Directory).attributes.any(
                and_(
                    func.lower(Attribute.name) == "givenname",
                    qa(Attribute.value).ilike(f"{fn}%"),
                ),
            )
            surname_sn = qa(Directory).attributes.any(
                and_(
                    func.lower(Attribute.name) == "surname",
                    qa(Attribute.value).ilike(f"{sn}%"),
                ),
            )
            givenname_sn = qa(Directory).attributes.any(
                and_(
                    func.lower(Attribute.name) == "givenname",
                    qa(Attribute.value).ilike(f"{sn}%"),
                ),
            )
            surname_fn = qa(Directory).attributes.any(
                and_(
                    func.lower(Attribute.name) == "surname",
                    qa(Attribute.value).ilike(f"{fn}%"),
                ),
            )

            attributes_expr.append(
                or_(
                    and_(givenname_fn, surname_sn),
                    and_(givenname_sn, surname_fn),
                ),
            )

        # NOTE: algorithm 6.c.iii.i
        attributes_expr.append(
            and_(
                qa(Attribute.name).in_(
                    select(qa(AttributeType.name)).where(
                        qa(AttributeType.name) == "legacyExchangeDN",
                        qa(AttributeType.is_included_anr).is_(True),
                    ),
                ),
                qa(Attribute.value) == normalized.replace("=", ""),
            ),
        )

        return and_(
            or_(
                qa(Directory).attributes.any(or_(*attributes_expr)),
                or_(*dir_user_expr),
            ),
        )  # fmt: skip

    def _get_bit_filter_function(
        self,
        oid: str,
    ) -> Callable[[str, int], UnaryExpression]:
        """Retrieve the appropriate filter function based on the attribute."""
        if oid == LDAPMatchingRule.LDAP_MATCHING_RULE_BIT_AND:
            return self._filter_bit_and
        elif oid == LDAPMatchingRule.LDAP_MATCHING_RULE_BIT_OR:
            return self._filter_bit_or

        raise ValueError("Incorrect attribute specified")

    def _filter_bit_and(
        self,
        attr_name: str,
        bit_mask: int,
    ) -> UnaryExpression:
        """Equivalent to a bitwise "AND" operation.

        Docs:
            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6dd1d7b4-2b2f-4e55-b164-7047c4c5bb00

        Examples:
            (userAccountControl & filter_value) == filter_value
            (00000000 & 00000011) == 00000011  # False
            (00000011 & 00000011) == 00000011  # True
            (00000110 & 00000011) == 00000011  # False
            (00000111 & 00000011) == 00000011  # True

        """
        return qa(Directory).attributes.any(
            and_(
                func.lower(Attribute.name) == attr_name.lower(),
                cast(Attribute.value, BigInteger).op("&")(bit_mask) == bit_mask,  # noqa: E501
            ),
        )  # fmt: skip

    def _filter_bit_or(self, attr_name: str, bit_mask: int) -> UnaryExpression:
        """Equivalent to a bitwise "OR" operation.

        Docs:
            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4e5b2424-642a-40da-acb1-9fff381b46e4

        Examples:
            (userAccountControl & filter_value) > 0
            (00000000 & 00000010) > 0  # False
            (00000010 & 00000010) > 0  # True
            (00000110 & 00000010) > 0  # True
            (00000111 & 00000010) > 0  # True

        """
        return qa(Directory).attributes.any(
            and_(
                func.lower(Attribute.name) == attr_name.lower(),
                cast(Attribute.value, BigInteger).op("&")(bit_mask) > 0,
            ),
        )

    def _get_member_filter_function(
        self,
        column: str,
    ) -> Callable[[str], UnaryExpression]:
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
        cte = find_members_recursive_cte([dn])

        return qa(Directory.id).in_(select(cte.c.directory_id).offset(1))  # type: ignore

    def _filter_memberof(self, dn: str) -> UnaryExpression:
        """Retrieve query conditions with the memberOF attribute."""
        group_id_subquery = (
            select(groups_table.c.id)
            .join(qa(Group.directory))
            .where(get_filter_from_path(dn))
            .scalar_subquery()
        )

        return qa(Directory.id).in_(
            (
                select(qa(Directory.id))
                .join(qa(Directory.groups))
                .where(groups_table.c.id == group_id_subquery)
                .distinct(qa(Directory.id))
            ),
        )  # type: ignore

    def _filter_member(self, dn: str) -> UnaryExpression:
        """Retrieve query conditions with the member attribute."""
        user_id_subquery = (
            select(users_table.c.id)
            .join(qa(User.directory))
            .where(get_filter_from_path(dn))
            .scalar_subquery()
        )

        return qa(Directory.id).in_(
            (
                select(groups_table.c.directory_id)
                .join(qa(Group.users))
                .where(users_table.c.id == user_id_subquery)
                .distinct(groups_table.c.directory_id)
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

    def _cast_item(self, item: ASN1Row) -> UnaryExpression | ColumnElement:  # noqa: C901
        # present, for e.g. `attibuteName=*`, `(attibuteName)`
        if item.tag_id == TagNumbers.PRESENT:
            attr = item.value.lower().replace("objectcategory", "objectclass")

            self.attributes.add(attr)

            if attr in User.search_fields:
                return not_(eq(getattr(User, attr), None))
            elif attr in Directory.search_fields:
                return not_(eq(getattr(Directory, attr), None))

            return self._get_filter_condition(attr)

        elif item.tag_id == TagNumbers.EXTENSIBLE_MATCH:
            attr = item.value[_ATTR_POS].value.decode("utf-8").lower()
            attr = attr.split(":")[0]
            self.attributes.add(attr)

            if item.value[_RULE_POS].value in (
                LDAPMatchingRule.LDAP_MATCHING_RULE_BIT_AND,
                LDAPMatchingRule.LDAP_MATCHING_RULE_BIT_OR,
            ):
                return self._bit_filter(item)

            elif (
                len(item.value) == 3
                and isinstance(item.value[_ATTR_POS].value, bytes)
                and attr in _MEMBERS_ATTRS
            ):  # fmt: skip
                return self._ldap_filter_by_attribute(*item.value)  # NOTE: oid

            else:
                raise ValueError("Unsupported matching rule")

        left, right = item.value
        attr = left.value.lower().replace("objectcategory", "objectclass")
        self.attributes.add(attr)

        is_substring = item.tag_id == TagNumbers.SUBSTRING

        if attr == "distinguishedname" and not is_substring:
            try:
                dn_search_path = get_search_path(right.value)
            except Exception:  # noqa: S110
                pass
            else:
                return get_path_filter(dn_search_path)

        if attr == "anr":
            if is_substring:
                expr = right.value[0]
                value = expr.value
                if isinstance(value, bytes):
                    with suppress(UnicodeDecodeError):
                        value = value.decode()
            else:
                value = right.value

            return self._get_anr_filter(value)
        if attr in User.search_fields:
            return self._from_filter(User, item, attr, right)
        elif attr in Directory.search_fields:
            return self._from_filter(Directory, item, attr, right)
        elif attr in _MEMBERS_ATTRS:  # NOTE: without oid
            return self._ldap_filter_by_attribute(None, left, right)
        elif attr == "entitytypename":
            return func.lower(EntityType.name) == right.lower()
        else:
            if is_substring:
                cond = qa(Attribute.value).ilike(
                    self._get_substring(right),
                )
            else:
                if isinstance(right.value, str):
                    cond = qa(Attribute.value).ilike(right.value)
                else:
                    cond = qa(Attribute.bvalue) == right.value

            return self._get_filter_condition(attr, cond)

    def _bit_filter(self, item: ASN1Row) -> UnaryExpression:
        filter_func = self._get_bit_filter_function(item.value[0].value)
        return filter_func(
            item.value[_ATTR_POS].value.decode("utf-8"),
            int(item.value[_VALUE_POS].value),
        )

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
        filter_func = self._get_member_filter_function(attribute)
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

        op_method = {
            TagNumbers.EQUALITY_MATCH: eq,
            TagNumbers.GE: ge,
            TagNumbers.LE: le,
            TagNumbers.APPROX_MATCH: ne,
        }[item.tag_id]  # type: ignore

        value: str | datetime
        if attr == "objectguid":
            col = col
            value = str(uuid.UUID(bytes_le=right.value))
        elif attr == "accountexpires":
            col = col
            value = ft_to_dt(int(right.value))
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

        if item.attr == "anr":
            return self._get_anr_filter(item.val)
        elif (
            LDAPMatchingRule.LDAP_MATCHING_RULE_BIT_AND in item.attr
            or LDAPMatchingRule.LDAP_MATCHING_RULE_BIT_OR in item.attr
        ):
            return self._bit_filter(item)
        elif item.attr in User.search_fields:
            return self._from_str_filter(User, is_substring, item)
        elif item.attr in Directory.search_fields:
            return self._from_str_filter(Directory, is_substring, item)
        elif item.attr in _MEMBERS_ATTRS:
            return self._api_filter(item)
        elif item.attr == "entitytypename":
            return func.lower(EntityType.name) == item.val.lower()
        else:
            if is_substring:
                cond = qa(Attribute.value).ilike(
                    item.val.replace("*", "%"),
                )
            else:
                cond = qa(Attribute.value).ilike(item.val)

            return self._get_filter_condition(item.attr, cond)

    def _bit_filter(self, item: Filter) -> UnaryExpression:
        filter_func = self._get_bit_filter_function(item.attr.split(":")[1])
        return filter_func(item.attr.split(":")[0], int(item.val))

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

        if item.attr == "objectguid":
            col = col
        elif item.attr == "accountexpires":
            item.val = ft_to_dt(int(item.val))
        else:
            col = func.lower(col)

        return op_method(col, item.val)

    def _api_filter(self, item: Filter) -> UnaryExpression:
        """Retrieve query conditions based on the specified LDAP attribute."""
        filter_func = self._get_member_filter_function(item.attr)
        return filter_func(item.val)

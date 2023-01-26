"""Utils module for different functions."""
from functools import cache

from ldap_filter import Filter
from sqlalchemy import and_, or_, select

from models.database import async_session
from models.ldap3 import Attrubute, CatalogueSetting, User


# @cache
async def get_base_dn() -> str:
    """Get base dn for e.g. DC=multifactor,DC=dev.

    :return str: name for the base distinguished name.
    """
    async with async_session() as session:
        cat_result = await session.execute(
            select(CatalogueSetting)
            .filter(CatalogueSetting.name == 'defaultNamingContext'),
        )
        return ','.join((
            f'DC={value}' for value in
            cat_result.scalar_one().value.split('.')))


def cast_filter2sql(root_q: str):
    op_map = {
        '!': 'ne',
        '=': 'eq',
        '>=': 'ge',
        '<=': 'le',
    }

    def cast(expr: Filter):
        conditions = []
        for item in expr.filters:
            if item.comp not in '&|!':
                attr = item.attr.lower()
                if attr in User.attrs:
                    col = getattr(User, attr)
                    conditions.append(
                        getattr(col, op_map[item.comp])(
                            attr, item.val.lower()))
                else:
                    conditions.append(and_(
                        Attrubute.name.ilike(attr),
                        Attrubute.value.ilike(item.val),
                    ))
            else:
                conditions.append(cast(item))


        if expr.comp == '&':
            return and_(*conditions)
        elif expr.comp == '|':
            return or_(*conditions)
        else:
            raise TypeError

    return cast(Filter.parse(root_q))

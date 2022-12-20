create or replace view view_directory_distinguishedNames as
(
    with recursive tree as (
        select
            directory.id,
            directory.parentId,
            (case
                when directory.objectClass = 'organizationalUnit' then 'ou='
                when directory.objectClass = 'domain' then 'dc='
                else 'cn='
            end) || directory.cn as dnPart
        from directory
        where
            directory.parentId is null
        union all
            select
                directory.id,
                directory.parentId,
                (case
                    when directory.objectClass = 'organizationalUnit' then 'ou='
                    when directory.objectClass = 'domain' then 'dc='
                    else 'cn='
                end) || directory.cn as dnPart
        from tree
            inner join
                directory
                    on directory.parentId = tree.id
    )
    select
        string_agg(dnPart, ',') as dn
    from
        tree

)
"""Tests for RID Manager."""


# @pytest.mark.asyncio
# @pytest.mark.usefixtures("setup_session")
# @pytest.mark.parametrize(
#     "sid_prefix",
#     [SidPrefix.DOMAIN_IDENTIFIER, SidPrefix.BUILT_IN_DOMAIN],
# )
# async def test_set_object_sid(
#     session: AsyncSession,
#     rid_manager_gateway: RIDManagerGateway,
#     rid_manager_use_case: RIDManagerUseCase,
#     sid_prefix: SidPrefix,
# ) -> None:
#     """Test RID Manager use case."""
#     directory = (
#         await session.scalars(
#             select(Directory)
#             .options(selectinload(qa(Directory.attributes)))
#             .filter(get_filter_from_path("cn=user0,cn=Users,dc=md,dc=test")),
#         )
#     ).one()

#     rid_set = await rid_manager_use_case.get_rid_set()
#     assert rid_set
#     rid_manager = await rid_manager_gateway.get_rid_manager()
#     pool_before = await rid_manager_gateway.get_rid_available_pool(rid_manager)
#     next_before = await rid_manager_gateway.get_next_rid(rid_set)

#     await rid_manager_use_case.set_object_sid(
#         directory,
#         rid=None,
#         sid_prefix=sid_prefix,
#     )
#     await session.commit()

#     expected_rid = next_before + 1
#     pool_after = await rid_manager_gateway.get_rid_available_pool(rid_manager)
#     assert (pool_after & 0xFFFFFFFF) == expected_rid
#     assert pool_after != pool_before

#     assert await rid_manager_gateway.get_next_rid(rid_set) == expected_rid

#     await session.refresh(directory, ["attributes"])
#     sid = await rid_manager_use_case.get_object_sid(directory)
#     if sid_prefix == SidPrefix.BUILT_IN_DOMAIN:
#         assert sid == f"{sid_prefix}-{expected_rid}"
#     else:
#         assert sid.startswith(f"{sid_prefix}-")
#         assert sid.endswith(f"-{expected_rid}")

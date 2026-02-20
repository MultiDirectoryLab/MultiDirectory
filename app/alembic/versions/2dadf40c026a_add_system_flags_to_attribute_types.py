"""Add systemFlags for AttributeTypes.

Revision ID: 2dadf40c026a
Revises: f4e6cd18a01d
Create Date: 2026-02-04 09:33:33.218126

"""

import contextlib

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import Session

from ldap_protocol.ldap_schema.appendix.attribute_type.use_case import (
    AttributeTypeUseCaseDeprecated,
)
from ldap_protocol.ldap_schema.exceptions import AttributeTypeNotFoundError

# revision identifiers, used by Alembic.
revision: None | str = "2dadf40c026a"
down_revision: None | str = "f4e6cd18a01d"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


_NON_REPLICATED_ATTRIBUTES_TYPE_NAMES = (
    "badPasswordTime",
    "badPwdCount",
    "bridgeheadServerListBL",
    "dSCorePropagationData",
    "frsComputerReferenceBL",
    "fRSMemberReferenceBL",
    "isMemberOfDL",
    "isPrivilegeHolder",
    "lastLogoff",
    "lastLogon",
    "logonCount",
    "managedObjects",
    "masteredBy",
    "modifiedCount",
    "msCOMPartitionSetLink",
    "msCOMUserLink",
    "msDSAuthenticatedToAccountlist",
    "msDSCachedMembership",
    "msDSCachedMembershipTimeStamp",
    "msDSEnabledFeatureBL",
    "msDSExecuteScriptPassword",
    "msDSHostServiceAccountBL",
    "msDSMasteredBy",
    "msDSOIDToGroupLinkBL",
    "msDSPSOApplied",
    "msDSMembersForAzRoleBL",
    "msDSNCType",
    "msDSNonMembersBL",
    "msDSObjectReferenceBL",
    "msDSOperationsForAzRoleBL",
    "msDSOperationsForAzTaskBL",
    "msDSNCROReplicaLocationsBL",
    "msDSReplicationEpoch",
    "msDSRetiredReplNCSignatures",
    "msDSTasksForAzRoleBL",
    "msDSTasksForAzTaskBL",
    "msDSRevealedDSAs",
    "msDSKrbTgtLinkBL",
    "msDSIsFullReplicaFor",
    "msDSIsDomainFor",
    "msDSIsPartialReplicaFor",
    "msDSUSNLastSyncSuccess",
    "msDSValueTypeReferenceBL",
    "msDSTokenGroupNames",
    "msDSTokenGroupNamesGlobalAndUniversal",
    "msDSTokenGroupNamesNoGCAcceptable",
    "msExchOwnerBL",
    "msDFSRMemberReferenceBL",
    "msDFSRComputerReferenceBL",
    "netbootSCPBL",
    "nonSecurityMemberBL",
    "objDistName",
    "objectGuid",
    "partialAttributeDeletionList",
    "partialAttributeSet",
    "pekList",
    "prefixMap",
    "queryPolicyBL",
    "replPropertyMetaData",
    "replUpToDateVector",
    "reports",
    "repsFrom",
    "repsTo",
    "rIDNextRID",
    "rIDPreviousAllocationPool",
    "schemaUpdate",
    "serverReferenceBL",
    "serverState",
    "siteObjectBL",
    "subRefs",
    "uSNChanged",
    "uSNCreated",
    "uSNLastObjRem",
    "whenChanged",
    "msSFU30PosixMemberOf",
    "msTSPrimaryDesktopBL",
    "msTSSecondaryDesktopBL",
    "msDSBridgeHeadServersUsed",
    "msDSClaimSharesPossibleValuesWithBL",
    "msDSMembersOfResourcePropertyListBL",
    "msTPMTpmInformationForComputerBL",
    "msAuthzMemberRulesInCentralAccessPolicyBL",
    "msDSGenerationId",
    "msDSIsPrimaryComputerFor",
    "msDSTDOEgressBL",
    "msDSTDOIngressBL",
    "msDSTransformationRulesCompiled",
    "msDSIsMemberOfDLTransitive",
    "msDSMemberTransitive",
    "msDSParentDistName",
    "msDSAssignedAuthNPolicySiloBL",
    "msDSAuthNPolicySiloMembersBL",
    "msDSUserAuthNPolicyBL",
    "msDSComputerAuthNPolicyBL",
    "msDSServiceAuthNPolicyBL",
    "msDSAssignedAuthNPolicyBL",
    "msDSKeyPrincipalBL",
    "msDSKeyCredentialLinkBL",
)


def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    op.add_column(
        "AttributeTypes",
        sa.Column(
            "system_flags",
            sa.Integer(),
            nullable=True,
            server_default=sa.text("0"),
        ),
    )

    async def _set_attr_replication_flag1(connection: AsyncConnection) -> None:  # noqa: ARG001   # TODO rename
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            at_type_use_case = await cnt.get(AttributeTypeUseCaseDeprecated)

        await at_type_use_case.zero_all_replicated_flags_deprecated()
        await session.commit()

    op.run_async(_set_attr_replication_flag1)

    async def _set_attr_replication_flag2(connection: AsyncConnection) -> None:  # noqa: ARG001   # TODO rename
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            at_type_use_case = await cnt.get(AttributeTypeUseCaseDeprecated)

        for name in _NON_REPLICATED_ATTRIBUTES_TYPE_NAMES:
            with contextlib.suppress(AttributeTypeNotFoundError):
                await at_type_use_case.set_attr_replication_flag_deprecated(
                    name,
                    need_to_replicate=False,
                )

        await session.commit()

    op.run_async(_set_attr_replication_flag2)

    op.alter_column("AttributeTypes", "system_flags", nullable=False)

    session.commit()


def downgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Downgrade."""
    op.drop_column("AttributeTypes", "system_flags")

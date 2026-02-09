"""Add systemFlags for AttributeTypes.

Revision ID: 2dadf40c026a
Revises: f4e6cd18a01d
Create Date: 2026-02-04 09:33:33.218126

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer
from sqlalchemy.orm import Session

from entities import AttributeType
from ldap_protocol.ldap_schema.attribute_type_system_flags_use_case import (
    AttributeTypeSystemFlags,
)
from repo.pg.tables import queryable_attr as qa

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


def upgrade(container: AsyncContainer) -> None:  # noqa: ARG001
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

    session.execute(sa.update(AttributeType).values({"system_flags": 0}))

    session.execute(
        sa.update(AttributeType)
        .where(
            qa(AttributeType.name).in_(_NON_REPLICATED_ATTRIBUTES_TYPE_NAMES),
        )
        .values(
            {
                "system_flags": int(
                    AttributeTypeSystemFlags.ATTR_NOT_REPLICATED,
                ),
            },
        ),
    )

    op.alter_column("AttributeTypes", "system_flags", nullable=False)

    session.commit()


def downgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Downgrade."""
    op.drop_column("AttributeTypes", "system_flags")

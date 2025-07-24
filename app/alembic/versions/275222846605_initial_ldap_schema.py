"""Initialise LDAP schema.

Revision ID: 275222846605
Revises: 4442d1d982a4
Create Date: 2025-03-05 12:19:03.407487

"""

import json

import sqlalchemy as sa
from alembic import op
from ldap3.protocol.schemas.ad2012R2 import ad_2012_r2_schema
from sqlalchemy import delete, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from extra.alembic_utils import temporary_stub_entity_type_name
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.raw_definition_parser import (
    RawDefinitionParser as RDParser,
)
from models import Attribute

# revision identifiers, used by Alembic.
revision = "275222846605"
down_revision = "4442d1d982a4"
branch_labels = None
depends_on = None

# NOTE: ad_2012_r2_schema_json is AD schema for Windows Server 2012 R2
ad_2012_r2_schema_json = json.loads(ad_2012_r2_schema)


@temporary_stub_entity_type_name
def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    op.create_table(
        "AttributeTypes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("oid", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("syntax", sa.String(length=255), nullable=False),
        sa.Column("single_value", sa.Boolean(), nullable=False),
        sa.Column("no_user_modification", sa.Boolean(), nullable=False),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_AttributeTypes_oid"),
        "AttributeTypes",
        ["oid"],
        unique=True,
    )
    op.create_index(
        op.f("ix_AttributeTypes_name"),
        "AttributeTypes",
        ["name"],
        unique=True,
    )

    op.create_table(
        "ObjectClasses",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("oid", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("superior_name", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(
            ["superior_name"],
            ["ObjectClasses.name"],
            ondelete="SET NULL",
        ),
        sa.Column(
            "kind",
            sa.Enum(
                "AUXILIARY",
                "STRUCTURAL",
                "ABSTRACT",
                name="objectclasskinds",
            ),
            nullable=False,
        ),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(
        op.f("ix_ObjectClasses_oid"),
        "ObjectClasses",
        ["oid"],
        unique=True,
    )
    op.create_index(
        op.f("ix_ObjectClasses_name"),
        "ObjectClasses",
        ["name"],
        unique=True,
    )

    op.create_table(
        "ObjectClassAttributeTypeMayMemberships",
        sa.Column(
            "attribute_type_name",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "object_class_name",
            sa.String(length=255),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["attribute_type_name"],
            ["AttributeTypes.name"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["object_class_name"],
            ["ObjectClasses.name"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("attribute_type_name", "object_class_name"),
    )
    op.create_unique_constraint(
        "object_class_may_attribute_type_uc",
        "ObjectClassAttributeTypeMayMemberships",
        ["attribute_type_name", "object_class_name"],
    )

    op.create_table(
        "ObjectClassAttributeTypeMustMemberships",
        sa.Column(
            "attribute_type_name",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "object_class_name",
            sa.String(length=255),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["attribute_type_name"],
            ["AttributeTypes.name"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["object_class_name"],
            ["ObjectClasses.name"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("attribute_type_name", "object_class_name"),
    )
    op.create_unique_constraint(
        "object_class_must_attribute_type_uc",
        "ObjectClassAttributeTypeMustMemberships",
        ["attribute_type_name", "object_class_name"],
    )
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.create_index(
        "idx_attribute_types_name_gin_trgm",
        "AttributeTypes",
        [sa.literal_column("name gin_trgm_ops")],
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )
    op.create_index(
        "idx_object_classes_name_gin_trgm",
        "ObjectClasses",
        [sa.literal_column("name gin_trgm_ops")],
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )

    # NOTE: catalog is a non-existent object class
    session.execute(
        delete(Attribute).where(
            or_(
                Attribute.name == "objectClass",
                Attribute.name == "objectclass",
            ),
            Attribute.value == "catalog",
        )
    )

    # NOTE: Load attributeTypes into the database
    at_raw_definitions: list[str] = ad_2012_r2_schema_json["raw"][
        "attributeTypes"
    ]
    at_raw_definitions.extend(
        [
            "( 1.2.840.113556.1.4.9999 NAME 'entityTypeName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE NO-USER-MODIFICATION )",  # noqa: E501
            #
            # Kerberos schema: https://github.com/krb5/krb5/blob/master/src/plugins/kdb/ldap/libkdb_ldap/kerberos.schema
            "( 2.16.840.1.113719.1.301.4.1.1 NAME 'krbPrincipalName' EQUALITY caseExactIA5Match SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26)",  # noqa: E501
            "( 1.2.840.113554.1.4.1.6.1 NAME 'krbCanonicalName' EQUALITY caseExactIA5Match SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.3.1 NAME 'krbPrincipalType' EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.5.1 NAME 'krbUPEnabled' DESC 'Boolean' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.6.1 NAME 'krbPrincipalExpiration' EQUALITY generalizedTimeMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.8.1 NAME 'krbTicketFlags' EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.9.1 NAME 'krbMaxTicketLife' EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.10.1 NAME 'krbMaxRenewableAge' EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.14.1 NAME 'krbRealmReferences' EQUALITY distinguishedNameMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.12)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.15.1 NAME 'krbLdapServers' EQUALITY caseIgnoreMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.15)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.17.1 NAME 'krbKdcServers' EQUALITY distinguishedNameMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.12)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.18.1 NAME 'krbPwdServers' EQUALITY distinguishedNameMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.12)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.24.1 NAME 'krbHostServer' EQUALITY caseExactIA5Match SYNTAX 1 3.6.1.4.1.1466.115.121.1.26)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.25.1 NAME 'krbSearchScope' EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.26.1 NAME 'krbPrincipalReferences' EQUALITY distinguishedNameMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.12)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.28.1 NAME 'krbPrincNamingAttr' EQUALITY caseIgnoreMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.29.1 NAME 'krbAdmServers' EQUALITY distinguishedNameMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.12)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.30.1 NAME 'krbMaxPwdLife' EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27  SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.31.1 NAME 'krbMinPwdLife' EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27  SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.32.1 NAME 'krbPwdMinDiffChars'  EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27  SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.33.1 NAME 'krbPwdMinLength'  EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27  SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.34.1 NAME 'krbPwdHistoryLength'  EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27  SINGLE-VALUE)",  # noqa: E501
            "( 1.3.6.1.4.1.5322.21.2.1 NAME 'krbPwdMaxFailure'  EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",  # noqa: E501
            "( 1.3.6.1.4.1.5322.21.2.2 NAME 'krbPwdFailureCountInterval'  EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",  # noqa: E501
            "( 1.3.6.1.4.1.5322.21.2.3 NAME 'krbPwdLockoutDuration'  EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",  # noqa: E501
            "( 1.2.840.113554.1.4.1.6.2 NAME 'krbPwdAttributes' EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",  # noqa: E501
            "( 1.2.840.113554.1.4.1.6.3 NAME 'krbPwdMaxLife' EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",  # noqa: E501
            "( 1.2.840.113554.1.4.1.6.4 NAME 'krbPwdMaxRenewableLife' EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",  # noqa: E501
            "( 1.2.840.113554.1.4.1.6.5 NAME 'krbPwdAllowedKeysalts' EQUALITY caseIgnoreIA5Match SYNTAX 1 3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.36.1 NAME 'krbPwdPolicyReference' EQUALITY distinguishedNameMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.37.1 NAME 'krbPasswordExpiration' EQUALITY generalizedTimeMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.39.1 NAME 'krbPrincipalKey' EQUALITY octetStringMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.40)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.40.1 NAME 'krbTicketPolicyReference' EQUALITY distinguishedNameMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.41.1 NAME 'krbSubTrees' EQUALITY distinguishedNameMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.12)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.42.1 NAME 'krbDefaultEncSaltTypes' EQUALITY caseIgnoreMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.15)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.43.1 NAME 'krbSupportedEncSaltTypes' EQUALITY caseIgnoreMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.15)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.44.1 NAME 'krbPwdHistory' EQUALITY octetStringMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.40)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.45.1 NAME 'krbLastPwdChange' EQUALITY generalizedTimeMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE)",  # noqa: E501
            "( 1.3.6.1.4.1.5322.21.2.5 NAME 'krbLastAdminUnlock' EQUALITY generalizedTimeMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.46.1 NAME 'krbMKey' EQUALITY octetStringMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.40)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.47.1 NAME 'krbPrincipalAliases' EQUALITY caseExactIA5Match SYNTAX 1 3.6.1.4.1.1466.115.121.1.26)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.48.1 NAME 'krbLastSuccessfulAuth' EQUALITY generalizedTimeMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.49.1 NAME 'krbLastFailedAuth' EQUALITY generalizedTimeMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.50.1 NAME 'krbLoginFailedCount'  EQUALITY integerMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.27  SINGLE-VALUE)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.51.1 NAME 'krbExtraData' EQUALITY octetStringMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.40)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.52.1 NAME 'krbObjectReferences' EQUALITY distinguishedNameMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.12)",  # noqa: E501
            "( 2.16.840.1.113719.1.301.4.53.1 NAME 'krbPrincContainerRef' EQUALITY distinguishedNameMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.12)",  # noqa: E501
            "( 2.16.840.1.113730.3.8.15.2.1 NAME 'krbPrincipalAuthInd' EQUALITY caseExactMatch SYNTAX 1 3.6.1.4.1.1466.115.121.1.15)",  # noqa: E501
            "( 1.3.6.1.4.1.5322.21.2.4 NAME 'krbAllowedToDelegateTo' EQUALITY caseExactIA5Match SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26)",  # noqa: E501
        ]
    )
    at_raw_definitions_filtered = [
        definition
        for definition in at_raw_definitions
        if "name 'ms" not in definition.lower()
    ]
    for at_raw_definition in at_raw_definitions_filtered:
        attribute_type = RDParser.create_attribute_type_by_raw(
            raw_definition=at_raw_definition
        )
        session.add(attribute_type)
    session.commit()

    # NOTE: Load objectClasses into the database
    async def _create_object_classes(connection):
        session = AsyncSession(bind=connection)
        await session.begin()

        oc_already_created_oids = set()
        oc_first_priority_raw_definitions = (
            "( 2.5.6.0 NAME 'top'  ABSTRACT MUST (objectClass ) MAY (entityTypeName $ instanceType $ nTSecurityDescriptor $ objectCategory $ cn $ description $ distinguishedName $ whenCreated $ whenChanged $ subRefs $ displayName $ uSNCreated $ isDeleted $ dSASignature $ objectVersion $ repsTo $ repsFrom $ memberOf $ ownerBL $ uSNChanged $ uSNLastObjRem $ showInAdvancedViewOnly $ adminDisplayName $ proxyAddresses $ adminDescription $ extensionName $ uSNDSALastObjRemoved $ displayNamePrintable $ directReports $ wWWHomePage $ USNIntersite $ name $ objectGUID $ replPropertyMetaData $ replUpToDateVector $ flags $ revision $ wbemPath $ fSMORoleOwner $ systemFlags $ siteObjectBL $ serverReferenceBL $ nonSecurityMemberBL $ queryPolicyBL $ wellKnownObjects $ isPrivilegeHolder $ partialAttributeSet $ managedObjects $ partialAttributeDeletionList $ url $ lastKnownParent $ bridgeheadServerListBL $ netbootSCPBL $ isCriticalSystemObject $ frsComputerReferenceBL $ fRSMemberReferenceBL $ uSNSource $ fromEntry $ allowedChildClasses $ allowedChildClassesEffective $ allowedAttributes $ allowedAttributesEffective $ possibleInferiors $ canonicalName $ proxiedObjectName $ sDRightsEffective $ dSCorePropagationData $ otherWellKnownObjects $ mS-DS-ConsistencyGuid $ mS-DS-ConsistencyChildCount $ masteredBy $ msCOM-PartitionSetLink $ msCOM-UserLink $ msDS-Approx-Immed-Subordinates $ msDS-NCReplCursors $ msDS-NCReplInboundNeighbors $ msDS-NCReplOutboundNeighbors $ msDS-ReplAttributeMetaData $ msDS-ReplValueMetaData $ msDS-NonMembersBL $ msDS-MembersForAzRoleBL $ msDS-OperationsForAzTaskBL $ msDS-TasksForAzTaskBL $ msDS-OperationsForAzRoleBL $ msDS-TasksForAzRoleBL $ msDs-masteredBy $ msDS-ObjectReferenceBL $ msDS-PrincipalName $ msDS-RevealedDSAs $ msDS-KrbTgtLinkBl $ msDS-IsFullReplicaFor $ msDS-IsDomainFor $ msDS-IsPartialReplicaFor $ msDS-AuthenticatedToAccountlist $ msDS-NC-RO-Replica-Locations-BL $ msDS-RevealedListBL $ msDS-PSOApplied $ msDS-NcType $ msDS-OIDToGroupLinkBl $ msDS-HostServiceAccountBL $ isRecycled $ msDS-LocalEffectiveDeletionTime $ msDS-LocalEffectiveRecycleTime $ msDS-LastKnownRDN $ msDS-EnabledFeatureBL $ msDS-ClaimSharesPossibleValuesWithBL $ msDS-MembersOfResourcePropertyListBL $ msDS-IsPrimaryComputerFor $ msDS-ValueTypeReferenceBL $ msDS-TDOIngressBL $ msDS-TDOEgressBL $ msDS-parentdistname $ msDS-ReplValueMetaDataExt $ msds-memberOfTransitive $ msds-memberTransitive $ structuralObjectClass $ createTimeStamp $ modifyTimeStamp $ subSchemaSubEntry $ msSFU30PosixMemberOf $ msDFSR-MemberReferenceBL $ msDFSR-ComputerReferenceBL ) )",  # noqa: E501
            "( 1.2.840.113556.1.5.20 NAME 'leaf' SUP top ABSTRACT )",
            "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST (cn ) MAY (sn $ serialNumber $ telephoneNumber $ seeAlso $ userPassword $ attributeCertificateAttribute ) )",  # noqa: E501
            "( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY (c $ l $ st $ street $ o $ ou $ title $ postalAddress $ postalCode $ postOfficeBox $ physicalDeliveryOfficeName $ telexNumber $ teletexTerminalIdentifier $ facsimileTelephoneNumber $ x121Address $ internationalISDNNumber $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ givenName $ initials $ generationQualifier $ houseIdentifier $ otherTelephone $ otherPager $ co $ department $ company $ streetAddress $ otherHomePhone $ msExchHouseIdentifier $ personalTitle $ homePostalAddress $ countryCode $ employeeID $ comment $ division $ otherFacsimileTelephoneNumber $ otherMobile $ primaryTelexNumber $ primaryInternationalISDNNumber $ mhsORAddress $ otherMailbox $ assistant $ ipPhone $ otherIpPhone $ msDS-AllowedToDelegateTo $ msDS-PhoneticFirstName $ msDS-PhoneticLastName $ msDS-PhoneticDepartment $ msDS-PhoneticCompanyName $ msDS-PhoneticDisplayName $ msDS-HABSeniorityIndex $ msDS-AllowedToActOnBehalfOfOtherIdentity $ mail $ manager $ homePhone $ mobile $ pager $ middleName $ thumbnailPhoto $ thumbnailLogo ) )",  # noqa: E501
            "( 1.2.840.113556.1.5.9 NAME 'user' SUP organizationalPerson STRUCTURAL MAY (o $ businessCategory $ userCertificate $ givenName $ initials $ x500uniqueIdentifier $ displayName $ networkAddress $ employeeNumber $ employeeType $ homePostalAddress $ userAccountControl $ badPwdCount $ codePage $ homeDirectory $ homeDrive $ badPasswordTime $ lastLogoff $ lastLogon $ dBCSPwd $ localeID $ scriptPath $ logonHours $ logonWorkstation $ maxStorage $ userWorkstations $ unicodePwd $ otherLoginWorkstations $ ntPwdHistory $ pwdLastSet $ preferredOU $ primaryGroupID $ userParameters $ profilePath $ operatorCount $ adminCount $ accountExpires $ lmPwdHistory $ groupMembershipSAM $ logonCount $ controlAccessRights $ defaultClassStore $ groupsToIgnore $ groupPriority $ desktopProfile $ dynamicLDAPServer $ userPrincipalName $ lockoutTime $ userSharedFolder $ userSharedFolderOther $ servicePrincipalName $ aCSPolicyName $ terminalServer $ mSMQSignCertificates $ mSMQDigests $ mSMQDigestsMig $ mSMQSignCertificatesMig $ msNPAllowDialin $ msNPCallingStationID $ msNPSavedCallingStationID $ msRADIUSCallbackNumber $ msRADIUSFramedIPAddress $ msRADIUSFramedRoute $ msRADIUSServiceType $ msRASSavedCallbackNumber $ msRASSavedFramedIPAddress $ msRASSavedFramedRoute $ mS-DS-CreatorSID $ msCOM-UserPartitionSetLink $ msDS-Cached-Membership $ msDS-Cached-Membership-Time-Stamp $ msDS-Site-Affinity $ msDS-User-Account-Control-Computed $ lastLogonTimestamp $ msIIS-FTPRoot $ msIIS-FTPDir $ msDRM-IdentityCertificate $ msDS-SourceObjectDN $ msPKIRoamingTimeStamp $ msPKIDPAPIMasterKeys $ msPKIAccountCredentials $ msRADIUS-FramedInterfaceId $ msRADIUS-SavedFramedInterfaceId $ msRADIUS-FramedIpv6Prefix $ msRADIUS-SavedFramedIpv6Prefix $ msRADIUS-FramedIpv6Route $ msRADIUS-SavedFramedIpv6Route $ msDS-SecondaryKrbTgtNumber $ msDS-AuthenticatedAtDC $ msDS-SupportedEncryptionTypes $ msDS-LastSuccessfulInteractiveLogonTime $ msDS-LastFailedInteractiveLogonTime $ msDS-FailedInteractiveLogonCount $ msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon $ msTSProfilePath $ msTSHomeDirectory $ msTSHomeDrive $ msTSAllowLogon $ msTSRemoteControl $ msTSMaxDisconnectionTime $ msTSMaxConnectionTime $ msTSMaxIdleTime $ msTSReconnectionAction $ msTSBrokenConnectionAction $ msTSConnectClientDrives $ msTSConnectPrinterDrives $ msTSDefaultToMainPrinter $ msTSWorkDirectory $ msTSInitialProgram $ msTSProperty01 $ msTSProperty02 $ msTSExpireDate $ msTSLicenseVersion $ msTSManagingLS $ msDS-UserPasswordExpiryTimeComputed $ msTSExpireDate2 $ msTSLicenseVersion2 $ msTSManagingLS2 $ msTSExpireDate3 $ msTSLicenseVersion3 $ msTSManagingLS3 $ msTSExpireDate4 $ msTSLicenseVersion4 $ msTSManagingLS4 $ msTSLSProperty01 $ msTSLSProperty02 $ msDS-ResultantPSO $ msPKI-CredentialRoamingTokens $ msTSPrimaryDesktop $ msTSSecondaryDesktops $ msDS-PrimaryComputer $ msDS-SyncServerUrl $ msDS-AssignedAuthNPolicySilo $ msDS-AuthNPolicySiloMembersBL $ msDS-AssignedAuthNPolicy $ userSMIMECertificate $ uid $ mail $ roomNumber $ photo $ manager $ homePhone $ secretary $ mobile $ pager $ audio $ jpegPhoto $ carLicense $ departmentNumber $ preferredLanguage $ userPKCS12 $ labeledURI $ msSFU30Name $ msSFU30NisDomain ) )",  # noqa: E501
            "( 1.2.840.113556.1.5.1 NAME 'securityObject' SUP top ABSTRACT MUST (cn ) )",  # noqa: E501
            "( 1.2.840.113556.1.5.14 NAME 'connectionPoint' SUP leaf ABSTRACT MUST (cn ) MAY (keywords $ managedBy $ msDS-Settings ) )",  # noqa: E501
            "( 1.2.840.113556.1.5.126 NAME 'serviceConnectionPoint' SUP connectionPoint STRUCTURAL MAY (versionNumber $ vendor $ versionNumberHi $ versionNumberLo $ serviceClassName $ serviceBindingInformation $ serviceDNSName $ serviceDNSNameType $ appSchemaVersion ) )",  # noqa: E501
            "( 1.2.840.113556.1.5.94 NAME 'serviceAdministrationPoint' SUP serviceConnectionPoint STRUCTURAL )",  # noqa: E501
            "( 1.2.840.113556.1.5.7000.56 NAME 'ipsecBase' SUP top ABSTRACT MAY (ipsecName $ ipsecID $ ipsecDataType $ ipsecData $ ipsecOwnersReference ) )",  # noqa: E501
            "( 1.2.840.113556.1.5.66 NAME 'domain' SUP top ABSTRACT MUST (dc ) )",  # noqa: E501
            "( 1.2.840.113556.1.3.59 NAME 'displayTemplate' SUP top STRUCTURAL MUST (cn ) MAY (helpData32 $ originalDisplayTableMSDOS $ addressEntryDisplayTable $ helpFileName $ addressEntryDisplayTableMSDOS $ helpData16 $ originalDisplayTable ) )",  # noqa: E501
            "( 2.5.6.2 NAME 'country' SUP top STRUCTURAL MUST (c ) MAY (searchGuide $ co ) )",  # noqa: E501
            "( 1.2.840.113556.1.5.7000.49 NAME 'applicationSettings' SUP top ABSTRACT MAY (applicationName $ notificationList $ msDS-Settings ) )",  # noqa: E501
            #
            # Kerberos schema: https://github.com/krb5/krb5/blob/master/src/plugins/kdb/ldap/libkdb_ldap/kerberos.schema
            "( 2.16.840.1.113719.1.301.6.1.1 NAME 'krbContainer' SUP top STRUCTURAL MUST (cn ) )",  # noqa: E501
            "( 2.16.840.1.113719.1.301.6.2.1 NAME 'krbRealmContainer' SUP top STRUCTURAL MUST (cn ) MAY (krbMKey $ krbUPEnabled $ krbSubTrees $ krbSearchScope $ krbLdapServers $ krbSupportedEncSaltTypes $ krbDefaultEncSaltTypes $ krbTicketPolicyReference $ krbKdcServers $ krbPwdServers $ krbAdmServers $ krbPrincNamingAttr $ krbPwdPolicyReference $ krbPrincContainerRef ) )",  # noqa: E501
            "( 2.16.840.1.113719.1.301.6.3.1 NAME 'krbService' SUP top ABSTRACT MUST (cn ) MAY (krbHostServer $ krbRealmReferences ) )",  # noqa: E501
            "( 2.16.840.1.113719.1.301.6.4.1 NAME 'krbKdcService' SUP krbService STRUCTURAL )",  # noqa: E501
            "( 2.16.840.1.113719.1.301.6.5.1 NAME 'krbPwdService' SUP krbService STRUCTURAL )",  # noqa: E501
            "( 2.16.840.1.113719.1.301.6.8.1 NAME 'krbPrincipalAux' SUP top AUXILIARY MAY (krbPrincipalName $ krbCanonicalName $ krbUPEnabled $ krbPrincipalKey $ krbTicketPolicyReference $ krbPrincipalExpiration $ krbPasswordExpiration $ krbPwdPolicyReference $ krbPrincipalType $ krbPwdHistory $ krbLastPwdChange $ krbLastAdminUnlock $ krbPrincipalAliases $ krbLastSuccessfulAuth $ krbLastFailedAuth $ krbLoginFailedCount $ krbExtraData $ krbAllowedToDelegateTo $ krbPrincipalAuthInd ) )",  # noqa: E501
            "( 2.16.840.1.113719.1.301.6.9.1 NAME 'krbPrincipal' SUP top STRUCTURAL MUST (krbPrincipalName ) MAY (krbObjectReferences ) )",  # noqa: E501
            "( 2.16.840.1.113719.1.301.6.11.1 NAME 'krbPrincRefAux' SUP top AUXILIARY MAY (krbPrincipalReferences ) )",  # noqa: E501
            "( 2.16.840.1.113719.1.301.6.13.1 NAME 'krbAdmService' SUP krbService STRUCTURAL )",  # noqa: E501
            "( 2.16.840.1.113719.1.301.6.14.1 NAME 'krbPwdPolicy' SUP top STRUCTURAL MUST (cn ) MAY (krbMaxPwdLife $ krbMinPwdLife $ krbPwdMinDiffChars $ krbPwdMinLength $ krbPwdHistoryLength $ krbPwdMaxFailure $ krbPwdFailureCountInterval $ krbPwdLockoutDuration $ krbPwdAttributes $ krbPwdMaxLife $ krbPwdMaxRenewableLife $ krbPwdAllowedKeysalts ) )",  # noqa: E501
            "( 2.16.840.1.113719.1.301.6.16.1 NAME 'krbTicketPolicyAux' SUP top AUXILIARY MAY (krbTicketFlags $ krbMaxTicketLife $ krbMaxRenewableAge ) )",  # noqa: E501
            "( 2.16.840.1.113719.1.301.6.17.1 NAME 'krbTicketPolicy' SUP top STRUCTURAL MUST (cn ) )",  # noqa: E501
        )

        for oc_1priority_raw_definition in oc_first_priority_raw_definitions:
            object_class_info = RDParser.get_object_class_info(
                raw_definition=oc_1priority_raw_definition
            )
            oc_already_created_oids.add(object_class_info.oid)

            object_class = await RDParser.create_object_class_by_info(
                session=session,
                object_class_info=object_class_info,
            )
            session.add(object_class)

        oc_raw_definitions: list[str] = ad_2012_r2_schema_json["raw"][
            "objectClasses"
        ]
        oc_raw_definitions_filtered = [
            definition
            for definition in oc_raw_definitions
            if "name 'ms" not in definition.lower()
        ]

        for oc_raw_definition in oc_raw_definitions_filtered:
            object_class_info = RDParser.get_object_class_info(
                raw_definition=oc_raw_definition
            )
            if object_class_info.oid in oc_already_created_oids:
                continue

            object_class = await RDParser.create_object_class_by_info(
                session=session,
                object_class_info=object_class_info,
            )
            session.add(object_class)

        await session.commit()
        await session.close()

    op.run_async(_create_object_classes)

    async def _create_attribute_types(connection):
        session = AsyncSession(bind=connection)
        await session.begin()

        attribute_type_dao = AttributeTypeDAO(session)
        for oid, name in (
            ("2.16.840.1.113730.3.1.610", "nsAccountLock"),
            ("1.3.6.1.4.1.99999.1.1", "posixEmail"),
        ):
            await attribute_type_dao.create_one(
                oid=oid,
                name=name,
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                single_value=True,
                no_user_modification=False,
                is_system=True,
            )

        await session.commit()

    op.run_async(_create_attribute_types)

    async def _modify_object_classes(connection):
        session = AsyncSession(bind=connection)
        await session.begin()

        attribute_type_dao = AttributeTypeDAO(session)
        object_class_dao = ObjectClassDAO(
            session,
            attribute_type_dao=attribute_type_dao,
        )

        for object_class_name, attribute_type_may_names in (
            ("user", ("nsAccountLock", "shadowExpire")),
            ("computer", ("userAccountControl",)),
            ("posixAccount", ("posixEmail",)),
            ("organizationalUnit", ("title", "jpegPhoto")),
        ):
            object_class = await object_class_dao.get_one_by_name(
                object_class_name=object_class_name,
            )
            attribute_types_may = await attribute_type_dao.get_all_by_names(
                attribute_type_names=attribute_type_may_names
            )
            object_class.attribute_types_may.extend(attribute_types_may)

        await session.commit()

    op.run_async(_modify_object_classes)


def downgrade() -> None:
    """Downgrade."""
    op.drop_index(
        "idx_object_classes_name_gin_trgm",
        table_name="ObjectClasses",
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )
    op.drop_index(
        "idx_attribute_types_name_gin_trgm",
        table_name="AttributeTypes",
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )
    op.drop_constraint(
        "object_class_must_attribute_type_uc",
        "ObjectClassAttributeTypeMustMemberships",
        type_="unique",
    )
    op.drop_table("ObjectClassAttributeTypeMustMemberships")

    op.drop_constraint(
        "object_class_may_attribute_type_uc",
        "ObjectClassAttributeTypeMayMemberships",
        type_="unique",
    )
    op.drop_table("ObjectClassAttributeTypeMayMemberships")

    op.drop_index("ix_ObjectClasses_name", table_name="ObjectClasses")
    op.drop_index("ix_ObjectClasses_oid", table_name="ObjectClasses")
    op.drop_table("ObjectClasses")
    op.execute(sa.text("DROP TYPE objectclasskinds"))

    op.drop_index("ix_AttributeTypes_name", table_name="AttributeTypes")
    op.drop_index("ix_AttributeTypes_oid", table_name="AttributeTypes")
    op.drop_table("AttributeTypes")
    # ### end Alembic commands ###

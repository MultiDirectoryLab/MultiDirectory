"""Update status process events.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap_protocol.policies.audit.audit_use_case import AuditUseCase


async def update_status_process_events(audit_use_case: AuditUseCase) -> None:
    """Update the status of process events."""
    if (
        await audit_use_case.is_existing_active_policy()
        and await audit_use_case.is_existing_active_destination()
    ):
        await audit_use_case.enable_event_processing()
    else:
        await audit_use_case.disable_event_processing()

"""Update status process events.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap_protocol.policies.audit.audit_use_case import AuditUseCase


async def update_status_process_events(audit_use_case: AuditUseCase) -> None:
    """Update the status of process events."""
    await audit_use_case.update_status_process_events()

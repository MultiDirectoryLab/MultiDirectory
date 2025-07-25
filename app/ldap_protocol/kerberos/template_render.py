"""Kerberos configuration template renderer.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import jinja2

from .schemas import KDCContext


class KRBTemplateRenderer:
    """Renderer for Kerberos configuration templates.

    Handles asynchronous rendering of krb5 and kdc configuration files
    using provided Jinja2 templates and context data.
    """

    def __init__(self, templates: jinja2.Environment) -> None:
        """Initialize KRBTemplateRenderer with Jinja2 templates.

        :param templates: Jinja2 environment or template loader.
        """
        self._templates = templates

    async def render_krb5(self, context: KDCContext) -> str:
        """Render the krb5.conf configuration file using the provided context.

        :param context:
            KDCContext dataclass with Kerberos configuration parameters.
        :return: Rendered krb5.conf as a string.
        """
        krb5_template = self._templates.get_template("krb5.conf")
        return await krb5_template.render_async(
            domain=context.domain,
            krbadmin=context.krbadmin,
            services_container=context.services_container,
            ldap_uri=context.ldap_uri,
        )

    async def render_kdc(self, context: KDCContext) -> str:
        """Render the kdc.conf configuration file using the provided context.

        :param context:
            KDCContext dataclass with Kerberos configuration parameters.
        :return: Rendered kdc.conf as a string.
        """
        kdc_template = self._templates.get_template("kdc.conf")
        return await kdc_template.render_async(domain=context.domain)

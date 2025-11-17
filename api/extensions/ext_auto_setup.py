"""
Extension for automatic admin account initialization on first startup.
"""

import logging

from flask import Flask

from configs import dify_config
from dify_app import DifyApp

logger = logging.getLogger(__name__)


def init_app(app: Flask | DifyApp):
    """
    Initialize automatic setup if configured.
    This runs after database initialization.
    """
    if dify_config.EDITION != "SELF_HOSTED":
        return

    # Only attempt auto-setup if all required config is present
    if not all(
        [
            dify_config.INIT_ADMIN_EMAIL,
            dify_config.INIT_ADMIN_PASSWORD,
            dify_config.INIT_ADMIN_NAME,
        ]
    ):
        logger.debug("Auto-setup skipped: configuration not complete")
        return

    # Type narrowing: at this point we know these are not None
    admin_email: str = dify_config.INIT_ADMIN_EMAIL  # type: ignore[assignment]
    admin_password: str = dify_config.INIT_ADMIN_PASSWORD  # type: ignore[assignment]
    admin_name: str = dify_config.INIT_ADMIN_NAME  # type: ignore[assignment]

    # Import here to avoid circular dependencies
    from controllers.console.setup import get_setup_status
    from libs.password import valid_password
    from services.account_service import RegisterService

    # All database operations must be within app context
    with app.app_context():
        # Check if already setup
        if get_setup_status():
            logger.debug("Auto-setup skipped: system already initialized")
            return

        try:
            # Validate password format
            try:
                valid_password(admin_password)
            except Exception:
                logger.exception("Auto-setup failed: invalid password format")
                return

            # Perform setup
            logger.info("Initializing default admin account: %s", admin_email)

            RegisterService.setup(
                email=admin_email,
                name=admin_name,
                password=admin_password,
                ip_address="127.0.0.1",  # Internal initialization
                language=dify_config.INIT_ADMIN_LANGUAGE,
            )

            logger.info("Default admin account initialized successfully")

        except Exception:
            logger.exception("Auto-setup failed")
            # Don't raise - allow app to continue starting

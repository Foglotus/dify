from pydantic import Field
from pydantic_settings import BaseSettings


class DeploymentConfig(BaseSettings):
    """
    Configuration settings for application deployment
    """

    APPLICATION_NAME: str = Field(
        description="Name of the application, used for identification and logging purposes",
        default="langgenius/dify",
    )

    DEBUG: bool = Field(
        description="Enable debug mode for additional logging and development features",
        default=False,
    )

    # Request logging configuration
    ENABLE_REQUEST_LOGGING: bool = Field(
        description="Enable request and response body logging",
        default=False,
    )

    EDITION: str = Field(
        description="Deployment edition of the application (e.g., 'SELF_HOSTED', 'CLOUD')",
        default="SELF_HOSTED",
    )

    DEPLOY_ENV: str = Field(
        description="Deployment environment (e.g., 'PRODUCTION', 'DEVELOPMENT'), default to PRODUCTION",
        default="PRODUCTION",
    )

    # Default admin account configuration
    INIT_ADMIN_EMAIL: str | None = Field(
        description="Default admin email address for automatic initialization",
        default=None,
    )

    INIT_ADMIN_PASSWORD: str | None = Field(
        description="Default admin password for automatic initialization",
        default=None,
    )

    INIT_ADMIN_NAME: str | None = Field(
        description="Default admin name for automatic initialization",
        default=None,
    )

    INIT_ADMIN_LANGUAGE: str = Field(
        description="Default admin language for automatic initialization",
        default="en-US",
    )

"""
RSA key management for password encryption/decryption.

This module provides unified RSA key pair generation and storage using Redis
to ensure all gunicorn worker processes use the same key pair.
"""

import base64
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from extensions.ext_redis import redis_client

logger = logging.getLogger(__name__)

# Redis keys for storing RSA key pair
RSA_PRIVATE_KEY_REDIS_KEY = "system:rsa_private_key"
RSA_PUBLIC_KEY_REDIS_KEY = "system:rsa_public_key"

# Key expiration: 30 days
RSA_KEY_EXPIRATION = 30 * 24 * 3600


class RSAPasswordEncryption:
    """Manage RSA keys for password encryption/decryption."""

    @classmethod
    def get_or_generate_rsa_keys(cls) -> tuple[str, str]:
        """
        Get or generate RSA key pair from Redis.

        Ensures all gunicorn worker processes use the same key pair.

        Returns:
            tuple[str, str]: (private_key_pem, public_key_pem)
        """
        try:
            private_key_pem = redis_client.get(RSA_PRIVATE_KEY_REDIS_KEY)
            public_key_pem = redis_client.get(RSA_PUBLIC_KEY_REDIS_KEY)

            if private_key_pem and public_key_pem:
                # Keys exist, decode from bytes to string
                if isinstance(private_key_pem, bytes):
                    private_key_pem = private_key_pem.decode("utf-8")
                if isinstance(public_key_pem, bytes):
                    public_key_pem = public_key_pem.decode("utf-8")
                logger.info("Retrieved existing RSA keys from Redis")
                return private_key_pem, public_key_pem

            # Generate new RSA key pair
            logger.info("Generating new RSA key pair")
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )

            # Serialize private key
            private_key_pem_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Serialize public key
            public_key = private_key.public_key()
            public_key_pem_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Store to Redis with expiration
            redis_client.setex(RSA_PRIVATE_KEY_REDIS_KEY, RSA_KEY_EXPIRATION, private_key_pem_bytes)
            redis_client.setex(RSA_PUBLIC_KEY_REDIS_KEY, RSA_KEY_EXPIRATION, public_key_pem_bytes)

            private_key_pem_str = private_key_pem_bytes.decode("utf-8")
            public_key_pem_str = public_key_pem_bytes.decode("utf-8")

            logger.info("Generated and stored new RSA keys in Redis")
            return private_key_pem_str, public_key_pem_str

        except Exception:
            logger.exception("Failed to get or generate RSA keys")
            raise

    @classmethod
    def decrypt_password(cls, encrypted_password: str) -> str:
        """
        Decrypt password encrypted by frontend.

        Args:
            encrypted_password: Base64-encoded encrypted password from frontend

        Returns:
            str: Decrypted password

        Raises:
            ValueError: If decryption fails
        """
        try:
            # Get private key
            private_key_pem, _ = cls.get_or_generate_rsa_keys()

            # Load private key
            loaded_key = serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"), password=None, backend=default_backend()
            )

            # Ensure it's an RSA private key
            if not isinstance(loaded_key, rsa.RSAPrivateKey):
                raise ValueError("Loaded key is not an RSA private key")

            # Decode base64 encrypted password
            encrypted_password_bytes = base64.b64decode(encrypted_password)

            # Decrypt using RSA PKCS1v15 padding
            decrypted_password_bytes = loaded_key.decrypt(encrypted_password_bytes, padding.PKCS1v15())

            return decrypted_password_bytes.decode("utf-8")

        except Exception as e:
            logger.exception("Failed to decrypt password")
            raise ValueError("Password decryption failed") from e

    @classmethod
    def get_public_key(cls) -> str:
        """
        Get the public key for frontend encryption.

        Returns:
            str: PEM-encoded public key
        """
        _, public_key_pem = cls.get_or_generate_rsa_keys()
        return public_key_pem


class RSAPasswordEncryptionError(Exception):
    """Exception raised for RSA password encryption/decryption errors."""

    pass

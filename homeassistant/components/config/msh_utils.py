"""MSH patch funcs firebase funcs and small utils funcs."""

import base64
from http import HTTPStatus
from typing import Any

import aiohttp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import config_core_secrets as ccs


async def verify_secret_key(
    secret_key: str, name: str, email: str, password: str, internal_url: str
) -> Any:
    """Verify the secret key with the cloud function."""
    cloud_function_url = "https://registernewuserandserver-jrskleaqea-uc.a.run.app"
    payload = {
        "secretKey": secret_key,
        "name": name,
        "email": email,
        "pass": password,
        "internalUrl": internal_url,
    }

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(cloud_function_url, json=payload) as response:
                if response.status != HTTPStatus.OK:
                    if response.json() is None:
                        return {
                            "success": False,
                            "message": f"Unexpected status code: {response.status}",
                        }
                    return await response.json()
                return await response.json()
        except aiohttp.ClientError as e:
            return {
                "success": False,
                "message": f"Failed to connect to cloud function: {e!s}",
            }


async def sync_password_with_firebase(
    email: str, current_password: str, new_password: str
) -> None:
    """Sync password change with Firebase asynchronously."""

    key = ccs.AES_ENC_KEY
    iv = ccs.AES_ENC_IV

    # Check lengths (for verification purposes)
    assert len(key) == 32, "Key must be 32 bytes for AES-256."
    assert len(iv) == 16, "IV must be 16 bytes for AES-CBC."

    # Data to encrypt
    data = new_password.encode("utf-8")

    # Pad data to AES block size (128 bits for AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt with AES-256-CBC using constant key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Encode the encrypted data to Base64
    encrypted_base64 = base64.b64encode(encrypted_data).decode("utf-8")

    url = "https://updateuserpassword-jrskleaqea-uc.a.run.app"
    headers = {"Content-Type": "application/json"}
    payload = {
        "email": email,
        "currentPassword": current_password,
        "newPassword": encrypted_base64,
    }

    async with (
        aiohttp.ClientSession() as session,
        session.post(url, headers=headers, json=payload) as response,
    ):
        if response.status != 200:
            pass
        else:
            pass

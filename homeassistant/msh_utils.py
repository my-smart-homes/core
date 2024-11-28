"""MSH patch funcs firebase funcs and small utils funcs."""

import base64
from http import HTTPStatus
import os
from typing import Any

import aiohttp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import config_core_secrets as ccs

SERVER_ID = "server_id"


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

    new_pass_padder = padding.PKCS7(128).padder()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Encrypt new password
    new_pass_data = new_password.encode("utf-8")
    new_pass_padded_data = (
        new_pass_padder.update(new_pass_data) + new_pass_padder.finalize()
    )
    new_pass_encryptor = cipher.encryptor()
    encrypted_new_pass = (
        new_pass_encryptor.update(new_pass_padded_data) + new_pass_encryptor.finalize()
    )
    encrypted_b64_new_pass = base64.b64encode(encrypted_new_pass).decode("utf-8")

    # Encrypt current password
    current_pass_encryptor = cipher.encryptor()
    current_pass_padder = padding.PKCS7(128).padder()
    current_pass_data = current_password.encode("utf-8")
    current_pass_padded_data = (
        current_pass_padder.update(current_pass_data) + current_pass_padder.finalize()
    )
    encrypted_current_pass = (
        current_pass_encryptor.update(current_pass_padded_data)
        + current_pass_encryptor.finalize()
    )
    encrypted_b64_current_pass = base64.b64encode(encrypted_current_pass).decode(
        "utf-8"
    )

    # Build payload
    url = "https://updateuserpassword-jrskleaqea-uc.a.run.app"
    headers = {"Content-Type": "application/json"}
    serverId = retrieve_value_from_config_file(SERVER_ID)
    payload = {
        "email": email,
        "currentPassword": encrypted_b64_current_pass,
        "newPassword": encrypted_b64_new_pass,
        "serverId": serverId,
    }

    async with (
        aiohttp.ClientSession() as session,
        session.post(url, headers=headers, json=payload) as response,
    ):
        if response.status != 200:
            response_data = await response.text()
            raise aiohttp.ClientError(
                f"Failed to sync with Firebase. Status: {response.status}, "
                f"Response: {response_data}"
            )


async def verify_user_subscription_for_this_server(username: str) -> Any:
    """Verify user's subscription status for a specific server."""
    from .auth.providers.homeassistant import (  # pylint: disable=import-outside-toplevel
        InternalServerError,
        NoInternetError,
        ServerDeniedError,
        SubscriptionOverError,
    )

    server_id = retrieve_value_from_config_file(SERVER_ID)

    cloud_function_url = "https://checkSubscriptionByServer-jrskleaqea-uc.a.run.app"
    payload = {"email": username, "serverId": server_id}

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(cloud_function_url, json=payload) as response:
                if response.status != HTTPStatus.OK:
                    response_data = await response.json()
                    error_key = response_data.get("error_key")

                    # Handle specific error scenarios
                    if error_key == "subscription_over":
                        raise SubscriptionOverError("Subscription has expired.")
                    if error_key == "server_denied":
                        raise ServerDeniedError(
                            "Server denied access or missing information."
                        )
                    if error_key == "server_crash":
                        raise InternalServerError("Internal server error occurred.")
                    raise ServerDeniedError(
                        f"Unexpected error: {response_data.get('message', 'Unknown error')}"
                    )

                response_data = await response.json()
                if response_data.get("success") is True:
                    return response_data.get("subscriptionEndDate")
                raise SubscriptionOverError("Success false")

        except aiohttp.ClientError as e:
            raise NoInternetError(f"Failed to connect to cloud function: {e!s}") from e


def write_key_value_to_config_file(key: str, value: str) -> None:
    """Write a value to a file based on the key in the relative config directory.

    Args:
        key (str): Logical name of the file (e.g., 'server_id' becomes 'data_server_id.txt').
        value (str): The value to write into the file.

    Raises:
        ValueError: If the key is invalid or empty.
        Exception: For any other file writing errors.

    """
    if not key.strip():
        raise ValueError("Key cannot be empty.")

    # Convert key to filename
    filename = f"data_{key.strip()}.txt"

    # Dynamically calculate the base path relative to this script
    base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config"))
    file_path = os.path.join(base_path, filename)

    try:
        # Ensure the base directory exists
        os.makedirs(base_path, exist_ok=True)

        # Write the value to the file
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(value.strip())
    except OSError:
        pass


def retrieve_value_from_config_file(key: str) -> str:
    """Retrieve a value from a file based on the key in the relative config directory.

    Args:
        key (str): Logical name of the file (e.g., 'server_id' for 'data_server_id.txt').

    Returns:
        str: The content of the file, or an empty string if the file doesn't exist or an error occurs.

    """
    if not key.strip():
        raise ValueError("Key cannot be empty.")

    # Convert key to filename
    filename = f"data_{key.strip()}.txt"

    # Dynamically calculate the base path relative to this script
    base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config"))
    file_path = os.path.join(base_path, filename)

    try:
        # Read and return the value from the file
        with open(file_path, encoding="utf-8") as file:
            return file.read().strip()
    except FileNotFoundError:
        return ""

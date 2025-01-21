"""MSH patch funcs firebase funcs and small utils funcs."""

import asyncio
import base64
from http import HTTPStatus
import os
from typing import Any

import aiofiles.os
import aiohttp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import config_core_secrets as ccs

SERVER_ID = "server_id"
SYS_DLIM = "SYS_DLIM"
EXTERNAL_URL = "EXTERNAL_URL"


async def verify_secret_key(
    secret_key: str,
    home_name: str,
    name: str,
    email: str,
    password: str,
    internal_url: str,
) -> Any:
    """Verify the secret key with the cloud function."""
    cloud_function_url = "https://registernewuserandserver-jrskleaqea-uc.a.run.app"
    # cloud_function_url = "https://heroic.requestcatcher.com/"
    payload = {
        "secretKey": secret_key,
        "homeName": home_name,
        "name": name,
        "email": email,
        "pass": password,
        "internalUrl": internal_url,
    }

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(cloud_function_url, json=payload) as response:
                if response.status != HTTPStatus.OK:
                    if await response.json() is None:
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

    encrypted_b64_new_pass = encrypt(new_password)

    encrypted_b64_current_pass = encrypt(current_password)

    # Build payload
    url = "https://updateuserpassword-jrskleaqea-uc.a.run.app"
    headers = {"Content-Type": "application/json"}
    serverId = await retrieve_value_from_config_file(SERVER_ID)
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

    server_id = await retrieve_value_from_config_file(SERVER_ID)

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


async def fetch_and_save_device_limit(email: str, server_id: str) -> None:
    """Fetch the device limit for a user and save it in a configuration file.

    Args:
        email (str): The user's email.
        server_id (str): The server ID.

    """

    cloud_function_url = "https://checkDeviceLimit-jrskleaqea-uc.a.run.app"
    payload = {"email": email, "serverId": server_id}

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(cloud_function_url, json=payload) as response:
                if response.status == HTTPStatus.OK:
                    response_data = await response.json()
                    if response_data.get("success"):
                        device_limit = response_data.get("devicesLimit", 0)
                        encryptedBase64DevLimit = encrypt(str(device_limit))
                        await write_key_value_to_config_file(
                            SYS_DLIM, encryptedBase64DevLimit
                        )
        except aiohttp.ClientError:
            pass


async def write_key_value_to_config_file(key: str, value: str) -> None:
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
    base_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../config/.storage/")
    )
    file_path = os.path.join(base_path, filename)

    try:
        # Ensure the base directory exists
        os.makedirs(base_path, exist_ok=True)

        # Write the value to the file
        async with aiofiles.open(file_path, "w", encoding="utf-8") as file:
            await file.write(value.strip())
    except OSError:
        pass


async def retrieve_value_from_config_file(key: str) -> str:
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
    base_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../config/.storage/")
    )
    file_path = os.path.join(base_path, filename)

    try:
        # Read and return the value from the file
        async with aiofiles.open(file_path, encoding="utf-8") as file:
            content = await file.read()
        return content.strip()
    except FileNotFoundError:
        return ""


def encrypt(data: str) -> str:
    """Encrypts a string using AES-CBC with PKCS7 padding and returns a base64-encoded string.

    Args:
        data (str): The plaintext data to encrypt.

    Returns:
        str: The base64-encoded encrypted string.

    """
    key = ccs.AES_ENC_KEY
    iv = ccs.AES_ENC_IV

    assert len(key) == 32, "Key must be 32 bytes for AES-256."
    assert len(iv) == 16, "IV must be 16 bytes for AES-CBC."

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(128).padder()

    data_bytes = data.encode("utf-8")
    padded_data = padder.update(data_bytes) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(encrypted_data).decode("utf-8")


def decrypt(encrypted_data: str) -> str:
    """Decrypts a base64-encoded string encrypted using AES-CBC with PKCS7 padding.

    Args:
        encrypted_data (str): The base64-encoded encrypted string.

    Returns:
        str: The decrypted plaintext string.

    """
    key = ccs.AES_ENC_KEY
    iv = ccs.AES_ENC_IV

    assert len(key) == 32, "Key must be 32 bytes for AES-256."
    assert len(iv) == 16, "IV must be 16 bytes for AES-CBC."

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    unpadder = padding.PKCS7(128).unpadder()

    encrypted_bytes = base64.b64decode(encrypted_data)
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_bytes) + decryptor.finalize()

    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode("utf-8")


async def add_external_url_into_confi_cors(external_url: str, config_path: str) -> None:
    """Add external URL to the CORS configuration file.

    Args:
        external_url (str): The external URL to add to the configuration.
        config_path (str): Path to the configuration file.

    """
    search_text = "http:\n  use_x_forwarded_for: true"
    replace_text = f"""http:
  cors_allowed_origins:
    - {external_url}
  use_x_forwarded_for: true"""

    try:
        async with aiofiles.open(config_path, encoding="utf-8") as file:
            content = await file.read()
        updated_content = content.replace(search_text, replace_text)
        async with aiofiles.open(config_path, mode="w", encoding="utf-8") as file:
            await file.write(updated_content)

    except FileNotFoundError:
        pass


async def reverse_proxy_client() -> None:
    """Run the bore client."""
    while True:
        try:
            # Read URL and port from the respective files
            external_url = await retrieve_value_from_config_file(EXTERNAL_URL)

            # Ensure both URL and port are available
            if external_url:
                # Construct the command
                # frpc http -s home1.msh.srvmysmarthomes.us -P 8002 -p websocket -n external_url -l 8123 -d external_url
                command = [
                    "frpc",
                    "http",
                    "-s",
                    "home1.msh.srvmysmarthomes.us",  # Updated server address
                    "-P",
                    "8002",  # Updated server port
                    "-p",
                    "websocket",  # Updated transport protocol
                    "-n",
                    external_url,  # Proxy name
                    "-l",
                    "8123",  # Local port
                    "-d",
                    external_url,  # Custom domain
                ]

                # Run the command asynchronously
                print("Starting connection...")  # noqa: T201
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                # Wait for the process to complete
                stdout, stderr = await process.communicate()

                if process.returncode != 0:
                    print(f"Command failed with return code {process.returncode}")  # noqa: T201
                    print(f"stderr: {stderr.decode()}")  # noqa: T201
            else:
                print("URL or port information is missing. Please check the files.")  # noqa: T201
        except asyncio.CancelledError:
            print("Terminating the process...")  # noqa: T201
            break

        # Delay before retrying
        print("Rechecking in 8 seconds...")  # noqa: T201
        await asyncio.sleep(8)  # Adjust delay as necessary

import base64
import os
import threading

import traceback
import shutil
import secrets

from typing import Callable, Any
import cryptography
from cryptography.hazmat.primitives.ciphers.aead import (
    ChaCha20Poly1305, AESGCM
)

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import (
    hashes, serialization
)

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# Static methods
def _prepare_types(
        prepare_type: str = '',
        **kwargs
):
    rsa_dict = {
        'message': {
            'original': (message := kwargs.get('message')),

            'is_bytes': isinstance(message, bytes),
            'is_str': isinstance(message, str),

            'error_msg': TypeError('message must be bytes or str')
        },
        'label': {
            'original': (label := kwargs.get('label')),

            'is_bytes': isinstance(label, bytes),
            'is_str': isinstance(label, str),

            'error_msg': TypeError('label must be bytes or str')
        },

        'rsa_key': {
            'original': (rsa_key := kwargs.get('rsa_key')),
            'is_bytes': isinstance(rsa_key, bytes),

            'error_msg': TypeError('RSA key must be bytes')
        }
    }
    aes_dict = {
        'aes_data': {
            'original': (aes_data := kwargs.get('aes_data')),
            'is_bytes': isinstance(aes_data, bytes),

            'is_str': isinstance(aes_data, str),
            'error_msg': TypeError('data must be bytes or str')
        },
        'associated_data': {
            'original': (associated_data := kwargs.get('associated_data')),
            'is_bytes': isinstance(associated_data, bytes),

            'is_str': isinstance(associated_data, str),
            'error_msg': TypeError('associated data must be bytes or str')
        },

        'aes_key': {
            'original': (aes_key := kwargs.get('aes_key')),
            'is_bytes': isinstance(aes_key, bytes),

            'error_msg': TypeError('AES key must be bytes')
        },
        'nonce': {
            'original': (nonce := kwargs.get('nonce')),
            'is_bytes': isinstance(nonce, bytes),

            'error_msg': TypeError('Nonce must be bytes')
        }
    }
    
    pepper_dict = {
        'hash_pepper': {
            'original': (hash_pepper := kwargs.get('hash_pepper')),

            'is_bytes': isinstance(hash_pepper, bytes),
            'is_str': isinstance(hash_pepper, str),

            'error_msg': TypeError('hash pepper must be bytes or str')
        },
        'password_pepper': {
            'original': (password_pepper := kwargs.get('password_pepper')),

            'is_bytes': isinstance(password_pepper, bytes),
            'is_str': isinstance(password_pepper, str),

            'error_msg': TypeError('password pepper must be bytes or str')
        }
    }
    
    prep_dicts = {
        'rsa': rsa_dict,
        'pepper': pepper_dict,

        'aes': aes_dict
    }

    prep_dict = prep_dicts.get(prepare_type, None)

    if prep_dict is None:
        raise ValueError('Invalid type to prepare')

    check_types = []

    for _, cdict in prep_dict.items():
        original_data = cdict['original']

        if original_data is None:
            continue

        is_bytes = cdict.get('is_bytes')

        is_str = cdict.get('is_str')
        error_msg = cdict.get('error_msg')

        if is_bytes:
            check_types.append(original_data)
        elif is_str:
            # NOQA: Script will skip this if not bytes or str
            check_types.append(original_data.encode('utf-8'))  # NOQA
        else:
            raise error_msg

    return tuple(check_types)


def _fernet_file_encrypt(
        input_file: str, salt: bytes = b"",
        key: bytes = b"", keep_copy: bool = False,

        is_precomputed: bool = False
) -> None:
    if len(key) < 32:
        raise ValueError("Key length is invalid for fernet.")

    with open(input_file, "rb+") as file:
        if is_precomputed:
            salt = b""

        fernet_key = base64.urlsafe_b64encode(key)

        file.seek(0, os.SEEK_SET)
        chunk = file.read(50 * 1024 * 1024)

        file.seek(0, os.SEEK_SET)
        file.write(salt)

        if keep_copy:
            file_name, file_ext = os.path.splitext(input_file)
            shutil.copy2(input_file, f"{file_name}_decrypted-copy{file_ext}")

        while chunk:
            chunk_encrypted = Fernet(fernet_key).encrypt(chunk)
            file.write(chunk_encrypted)

            chunk = file.read(50 * 1024 * 1024)  # Read 50MB at a time
        return


def _fernet_file_decrypt(
        input_file: str, key: bytes = b"",
        keep_copy: bool = False,

        is_precomputed: bool = False
) -> None:
    if len(key) < 32:
        raise ValueError("Key length is invalid for fernet.")

    with open(input_file, "rb+") as file:
        fernet_key = base64.urlsafe_b64encode(key)

        # If a precomputed key was used, no salt should be available
        if not is_precomputed:
            file.seek(32, os.SEEK_SET)

        chunk = file.read(50 * 1024 * 1024)
        decrypt_successful = False

        try:
            Fernet(fernet_key).decrypt(chunk)
            decrypt_successful = True
        except cryptography.fernet.InvalidToken as error:
            raise error
        finally:
            file.close() if not decrypt_successful else None

        # Erase/keep the file
        if keep_copy:
            file_name, file_ext = os.path.splitext(input_file)
            shutil.copy2(input_file, f"{file_name}_encrypted-copy{file_ext}")

        plaintext_end = 0

        while chunk:
            chunk_decrypted = Fernet(fernet_key).decrypt(chunk)
            plaintext_end += len(chunk_decrypted)

            cursor_position = file.tell()

            file.seek(0, os.SEEK_SET)
            file.write(chunk_decrypted)

            file.seek(cursor_position, os.SEEK_SET)
            chunk = file.read(50 * 1024 * 1024)

        file.truncate(plaintext_end)
    return


def _fernet_data_encrypt(
        data: [bytes, str], salt: bytes = b"",
        key: bytes = b"",

        is_precomputed: bool = False
) -> bytes:
    if len(key) < 32:
        raise ValueError("Key length is invalid for fernet.")

    if is_precomputed:
        salt = b""

    if not isinstance(data, bytes):
        data = data.encode("utf-8")

    fernet_key = base64.urlsafe_b64encode(key)
    encrypted_data = salt + Fernet(fernet_key).encrypt(data)

    return encrypted_data


def _fernet_data_decrypt(
        data: [bytes, str], key: bytes = b"",
        is_precomputed: bool = False
) -> bytes:
    if len(key) < 32:
        raise ValueError("Key length is invalid for fernet.")

    if not is_precomputed:
        data = data[32:]

    fernet_key = base64.urlsafe_b64encode(key)
    decrypted_data = Fernet(fernet_key).decrypt(data)

    return decrypted_data


# Classes
def generate_peppers(
        env_path: str = "pepper.env",
        skip_prompt: bool = False
) -> None:
    """
    Generate peppers to use for PBKDF2HMAC.

    Quick help:
        This function is a simple and easy way to generate peppers,
        but make sure to keep the peppers hidden and safe.

        You can optionally provide a name, or let it default to pepper.env

    Parameters:
        self [class parameter]
        env_path [defaults to pepper.env]

        skip_prompt [defaults to False]

    How to use:
        Call the function.
            # >>> generate_peppers()
            Wrote peppers to pepper.env, please make sure to keep the peppers in a safe area.

        -- You can check pepper.env, then use load_dotenv("pepper.env") and os.environ[]

        Call the function with an optional name:
            # >>> generate_peppers("some_peppers.env")
            Wrote peppers to pepper.env, please make sure to keep the peppers in a safe area.

        -- Same thing above, but now it's named "some_peppers.env"

        If the pepper already exists:
            # >>> generate_peppers()
            Warning: pepper.env already exists, overwrite? [Y/N]:
            -- You can choose to overwrite it, or return.

        Optionally, skip the prompt:
            # >>> generate_peppers(skip_prompt=True)
            Wrote peppers to pepper.env, please make sure to keep the peppers in a safe area.
    """

    if os.path.isdir(env_path):
        raise IsADirectoryError(f"Is a directory: {env_path}")

    if os.path.isfile(env_path) and not skip_prompt:
        confirm = input(f"Warning: {env_path} already exists, overwrite? [Y/N]: ")

        if confirm.lower() == "y":
            pass
        else:
            return

    with open(env_path, "w") as file:
        hash_pepper = secrets.token_bytes(32)
        password_pepper = secrets.token_bytes(32)

        file.write(f"hash_pepper={str(hash_pepper)}\n")
        file.write(f"password_pepper={str(password_pepper)}")

        print(f"Wrote peppers to {env_path}, please make sure to keep the peppers in a safe area.")
    return


def compare_hash(
        hash_1: str,
        hash_2: str
) -> bool:
    """
    Compare a hash using secrets.compare_digest.

    Quick help:
        Comparing hashes using "==" is a bad idea,
        Using a digest comparison function is better.

        The reason being is that "==" is susceptible to
        timing attacks. Which is a method of side-channel
        attacks which gets the time it takes to
        compare a string, the more time it takes
        to compare, the closer you are cracking the password.


        This simply compares the hash digest
        [The hex, which looks like 223d3c2cdafefk . . .]

        Note: This also works with strings like "digest1"

    Parameters:
        self [class parameter]

        hash_1 [first hash]
        hash_2 [second hash]

    How to use:
        Pass two hashes as parameters.
            # >>> hash_1 = "d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa"
            # >>> hash_2 = "d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa"
            -- Both hashes are the same, also the input string was "hash"

            # >>> compare_hash(hash_1, hash_2)
            True

        This is useful for checking if the hash matches an input:
            # >>> expected_hash = "d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa"
            # >>> input_hash = hash_string(input("Enter the string: "))

            -- The value of "falsehash" is: "45b7033e65585da8eda3fe91064a091b7321643078c569ef3d694a0c29f864fb"
            # >>> compare_hash(expected_hash, input_hash)
            False
    """

    compare_output = secrets.compare_digest(hash_1, hash_2)
    return compare_output


class ThreadManager:
    def __init__(self):
        self.error_list = []

        self.threads_set = set()
        self.semaphore = threading.Semaphore(5)

    def _guard_clauses(
            self,
            threads_set: [list, set] = None,

            error_list: list = None,
            semaphore: threading.Semaphore = None,

            callback_function: Callable = None
    ) -> tuple:
        if threads_set is None:
            threads_set = self.threads_set
        elif not isinstance(threads_set, set):
            raise TypeError(f"threads_set expected set, got {type(threads_set)}")

        if error_list is None:
            error_list = self.error_list
        elif not isinstance(error_list, list):
            raise TypeError(f"error_list expected list, got {type(error_list)}")

        # Semaphore guard clause
        if not hasattr(semaphore, 'acquire'):
            if semaphore is None:
                semaphore = self.semaphore
            else:
                raise TypeError(f"expected a semaphore/lock, got {type(semaphore)}")

        if not isinstance(threads_set, (list, set)):
            raise TypeError(f"threads_set expected a list/set, got {type(threads_set)}")

        if not callable(callback_function):
            raise TypeError("object passed is not callable")

        return threads_set, error_list, semaphore

    def set_thread_count(self, num: int) -> None:
        if not isinstance(num, int):
            raise TypeError(f"num expected int, got type '{type(num).__name__}'")

        if num < 1:
            num = 1
        self.semaphore = threading.Semaphore(num)

        return

    # thread worker
    def worker(
            self, callback_function: Callable,
            semaphore: threading.Semaphore = None,
            threads_set: set = None,

            error_list: list = None,
            *args, **kwargs
    ) -> Any:
        threads_set, error_list, semaphore = self._guard_clauses(
            semaphore=semaphore,
            threads_set=threads_set,

            error_list=error_list,
            callback_function=callback_function
        )
        result = None

        current_thread = threading.current_thread()
        type_name = type(callback_function).__name__

        if type_name == "function":
            func_name = callback_function.__name__
        else:
            func_name = type(callback_function).__name__

        with semaphore:  # acquire and release the semaphore
            try:
                result = callback_function(*args, **kwargs)
            except Exception as err:
                if error_list is not None:
                    # tb means traceback
                    tb_dict = {}
                    tb_msg = traceback.format_exc()

                    tb_dict["name"] = type(err).__name__
                    tb_dict["caller"] = func_name

                    tb_dict["traceback"] = tb_msg

                    error_list.append(tb_dict)
                else:
                    tb_msg = traceback.format_exc()
                    print(tb_msg)
            finally:
                threads_set.remove(current_thread) if current_thread in threads_set else None

        return result

    # create a thread
    def thread_create(
            self, callback: Callable, *args,
            semaphore: threading.Semaphore = None,

            threads_set: set = None,
            thread_name: str = "",

            error_list: list = None,
            **kwargs
    ) -> threading.Thread:
        threads_set, error_list, semaphore = self._guard_clauses(
            semaphore=semaphore,
            threads_set=threads_set,

            error_list=error_list,
            callback_function=callback
        )

        thread = threading.Thread(
            target=self.worker,
            args=(callback, semaphore, threads_set, error_list, *args),
            kwargs=kwargs,
            name=thread_name
        )

        threads_set.add(thread)
        thread.start()

        return thread


class CipherManager:
    def __init__(self) -> None:
        self.hash_method = hashes.SHA256()

        self.fernet = _FernetMethods(self)
        self.rsa = _RSAMethods(self)

        # self.aes = _AESMethods(self)
        return

    def hash_string(
            self, input_string: str,
            hash_method: object = None
    ) -> str:
        """
        Hash a string with the provided hash method.

        Parameters:
            input_string: [required, can be str or bytes]
            hash_method: [hashes.SHA256()]

        How to use:
            [hashes is cryptography.hazmat.primitives.hashes]

            Call hash_string like so:

            # >>> hash_string("example")
            50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c

            ----------------------------------------------------------------

            Optionally, you can provide a hash object:

            # >>> hash_string("example", hash_method=hashes.SHA512())
            3bb12eda3c298db5de25597f54d924f2e17e78a26ad8953ed8218ee682f0bbbe
            9021e2f3009d152c911bf1f25ec683a902714166767afbd8e5bd0fb0124ecb8a

            (The hash was split into two separate lines for readability)
        """

        if hash_method is None:
            hash_method = self.hash_method

        if not isinstance(input_string, bytes):
            bytes_passed = input_string.encode('utf-8')
        else:
            bytes_passed = input_string

        digest = hashes.Hash(hash_method)

        digest.update(bytes_passed)
        hashed_bytes = digest.finalize()

        hashed_string = hashed_bytes.hex()
        return hashed_string

    def hash_key(
            self, input_key: [bytes, str],
            salt: bytes = b"", hash_pepper: bytes = b"",

            password_pepper: bytes = b"", hash_method: object = None
    ) -> bytes:
        """
        Create a kdf-derived key using PBKDF2HMAC.

        Quick help:
            [hashes is cryptography.hazmat.primitives.hashes]

            A salt is a random value that makes the output more random,

            A pepper is a random secret value that only the program should know
            and must not be stored with the password.

            - hash_pepper is used during creating the PBKDF2HMAC object
            - password_pepper is used during key derivation

            You can pass a hash object to make the hash longer.
            - defaults to hashes.SHA256()

        Parameters:
            input_key: [required, can be str or bytes]
            salt: [defaults to b""]

            hash_pepper: [defaults to b""]
            password_pepper: [defaults to b""]

            hash_method: [defaults to hashes.SHA256()]
        """

        if hash_method is None:
            hash_method = self.hash_method

        kdf = PBKDF2HMAC(
            algorithm=hash_method,
            length=32,
            salt=salt + hash_pepper,
            iterations=100000
        )

        if isinstance(input_key, bytes):
            key = kdf.derive(input_key + password_pepper)
        else:
            key = kdf.derive(input_key.encode("utf-8") + password_pepper)

        return key


class _FernetMethods:
    def __init__(self, parent):
        self.hash_method = parent.hash_method

    def encrypt_file(
            self, input_file: str,
            kdf_key: bytes = b"", password: bytes = b"",

            keep_copy: bool = False, hash_pepper: bytes = b"",
            password_pepper: object = b""
    ) -> None:
        if keep_copy not in {True, False}:
            raise TypeError(f"keep_copy expected boolean, got '{keep_copy}'")

        # Check argument if it's a file
        if not os.path.isfile(input_file):
            if os.path.isdir(input_file):
                raise IsADirectoryError(f"Is a directory: {input_file}")
            else:
                raise FileNotFoundError(f"No such file: {input_file}")

        # If a precomputed key is passed, use it
        if kdf_key:
            if len(kdf_key) < 32:
                raise ValueError("Key length is invalid for fernet.")

            _fernet_file_encrypt(input_file, key=kdf_key, keep_copy=keep_copy, is_precomputed=True)
            return

        hash_pepper, password_pepper = _prepare_types(
            prepare_type='pepper', hash_pepper=hash_pepper,
            password_pepper=password_pepper
        )
        salt = secrets.token_bytes(32)

        # Construct the PBKDF2HMAC object
        kdf = PBKDF2HMAC(
            algorithm=self.hash_method,
            length=32,
            salt=salt + hash_pepper,
            iterations=100000
        )

        key = None

        if isinstance(password, bytes):
            key = kdf.derive(password + password_pepper)
        elif isinstance(password, str):
            key = kdf.derive(password.encode("utf-8") + password_pepper)

        _fernet_file_encrypt(input_file, salt=salt, key=key, keep_copy=keep_copy)
        return

    # decryption function
    def decrypt_file(
            self, input_file: str,
            kdf_key: bytes = b"", password: [bytes, str] = b"",

            keep_copy: bool = False, hash_pepper: bytes = b"",
            password_pepper: bytes = b""
    ) -> None:
        # Guard clauses
        if keep_copy not in [True, False]:
            raise TypeError(f"keep_copy expected boolean, got '{keep_copy}'")

        # Check argument if it's a file
        if not os.path.isfile(input_file):
            if os.path.isdir(input_file):
                raise IsADirectoryError(f"Is a directory: {input_file}")
            else:
                raise FileNotFoundError(f"No such file: {input_file}")

        # Decrypt the file in chunks
        if kdf_key:
            if len(kdf_key) < 32:
                raise ValueError("Key length is invalid for fernet.")

            _fernet_file_decrypt(input_file, key=kdf_key, keep_copy=keep_copy, is_precomputed=True)
            return

        hash_pepper, password_pepper = _prepare_types(
            prepare_type='pepper', hash_pepper=hash_pepper,
            password_pepper=password_pepper
        )

        with open(input_file, "rb+") as file:
            salt = file.read(32)

        kdf = PBKDF2HMAC(
            algorithm=self.hash_method,
            length=32,
            salt=salt + hash_pepper,
            iterations=100000
        )

        if isinstance(password, bytes):
            key = kdf.derive(password + password_pepper)
        else:
            key = kdf.derive(password.encode("utf-8") + password_pepper)

        _fernet_file_decrypt(input_file, key=key, keep_copy=keep_copy, is_precomputed=False)
        return

    # encryption function
    def encrypt_data(
            self, data: [bytes, str],
            kdf_key: bytes = b"",

            password: bytes = b"",
            hash_pepper: bytes = b"",

            password_pepper: bytes = b""
    ) -> bytes:
        if kdf_key:
            if len(kdf_key) < 32:
                raise ValueError("Key length is invalid for fernet.")

            return _fernet_data_encrypt(data=data, key=kdf_key, is_precomputed=True)

        hash_pepper, password_pepper = _prepare_types(
            prepare_type='pepper', hash_pepper=hash_pepper,
            password_pepper=password_pepper
        )

        salt = secrets.token_bytes(32)

        kdf = PBKDF2HMAC(
            algorithm=self.hash_method,
            length=32,
            salt=salt + hash_pepper,
            iterations=100000
        )

        if isinstance(password, bytes):
            key = kdf.derive(password + password_pepper)
        else:
            key = kdf.derive(password.encode("utf-8") + password_pepper)

        return _fernet_data_encrypt(data=data, salt=salt, key=key, is_precomputed=False)

    # decryption function
    def decrypt_data(
            self, data: [bytes, str],
            kdf_key: bytes = b"",

            password: bytes = b"",
            hash_pepper: bytes = b"",

            password_pepper: bytes = b""
    ) -> bytes:
        if kdf_key:
            if len(kdf_key) < 32:
                raise ValueError("Key length is invalid for fernet.")

            return _fernet_data_decrypt(data=data, key=kdf_key, is_precomputed=True)

        hash_pepper, password_pepper = _prepare_types(
            prepare_type='pepper', hash_pepper=hash_pepper,
            password_pepper=password_pepper
        )

        salt = data[:32]

        kdf = PBKDF2HMAC(
            algorithm=self.hash_method,
            length=32,
            salt=salt + hash_pepper,
            iterations=100000
        )

        if isinstance(password, bytes):
            key = kdf.derive(password + password_pepper)
        else:
            key = kdf.derive(password.encode("utf-8") + password_pepper)

        return _fernet_data_decrypt(data=data, key=key, is_precomputed=False)


class _RSAMethods:
    def __init__(self, parent):
        self.hash_method = parent.hash_method

        self.private_key = None
        self.public_key = None

    # noinspection PyMethodMayBeStatic
    def generate_keys(
            self, key_length: int = 2048,
            public_exponent: int = 65537,

            password: bytes = b"", output_to: str = "file"
    ) -> (tuple, None):
        """
        Generate an RSA public and private key.

        Quick help:
            This function outputs the key to either a tuple, or file.

            Tuple format:
            (b"public-key", b"private-key")


            File format:

            - public_key-{number}.pem
            - private_key-{number}.pem

            Number refers to a random number between 1 and 65537.

        :param key_length: [integer, default: 2048]
        :param public_exponent: [integer, default: 65537]
        :param password: [bytes, defaults to b"" or empty byte string]
        :param output_to: [str, must be "file" or "caller", defaults to "file"]
        :return: (b"public-key", b"private-key") | None
        """

        def key_creator():
            # Create the private key then derive the public key
            private_key = rsa.generate_private_key(
                public_exponent=public_exponent,
                key_size=key_length
            )
            public_key = private_key.public_key()

            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password)
            else:
                encryption_algorithm = serialization.NoEncryption()

            # Create the public and private key bytes
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,

                encryption_algorithm=encryption_algorithm
            )
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            number = secrets.randbelow(65537)

            # Write the key bytes to a file
            if output_to == "file":
                with open(f"public_key-{number}.pem", "wb") as file:
                    file.write(public_key_bytes)
                with open(f"private_key-{number}.pem", "wb") as file:
                    file.write(private_key_bytes)
            elif output_to == "caller":
                return public_key_bytes, private_key_bytes

            return

        error_dict = {
            'key_length': (
                isinstance(key_length, int),
                TypeError(
                    "key_length must be an integer"
                )
            ),

            'public_exponent': (
                isinstance(public_exponent, int),
                TypeError(
                    "public_exponent must be an integer"
                )
            ),

            'output_to': (
                output_to in {"file", "caller"},
                ValueError(
                    "output method must be file/caller"
                )
            )
        }

        for check_type, error_tuple in error_dict.items():
            check_result = error_tuple[0]
            error_type = error_tuple[1]

            if not check_result:
                raise error_type

        # Return statements
        return key_creator()

    def load_keys(
            self,
            public_key: bytes, private_key: bytes,

            key_password: [bytes, None] = None
    ) -> None:
        """
        Load RSA PEM keys into the class.

        Quick help:
            This simply loads the RSA keys into the class,
            allowing you to utilize the non-manual RSA
            methods.

            The manual RSA methods take a key as part
            of their arguments, the non-manual RSA
            methods use the loaded keys.

            The parameter key_password is used when
            the RSA key bytes were encrypted.

        :param public_key: [bytes, required]
        :param private_key: [bytes, required]
        :param key_password: [bool, optional, defaults to None]
        :return: None
        """
        self.public_key = serialization.load_pem_public_key(
            public_key
        )
        self.private_key = serialization.load_pem_private_key(
            private_key,
            key_password
        )
        return

    def encrypt(
            self, message: [bytes, str],
            label: [bytes, str] = b""
    ) -> bytes:
        """
        Encrypt data using the loaded RSA keys.

        Quick help:
         - Uses the RSA keys loaded in the class.
         - Automatically encodes the message in utf-8 if it's a string.
         - Raises an error if the public key is missing or not set.

        :param message: [Required, can be bytes or str]
        :param label: [Optional, can be bytes or str]
        :return: Encrypted message in bytes
        """

        if self.public_key is None:
            raise ValueError("Public key is missing or unset.")

        message, label = _prepare_types(
            prepare_type='rsa',
            message=message, label=label
        )

        encrypted_message = self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.hash_method),
                algorithm=self.hash_method,

                label=label
            )
        )

        return encrypted_message

    def decrypt(
            self, message: [bytes, str],
            label: [bytes, str] = b""
    ) -> bytes:
        """
        Decrypt data using the loaded RSA keys.

        Quick help:
         - Uses the RSA keys loaded in the class.
         - Automatically encodes the message in utf-8 if it's a string.
         - Raises an error if the private key is missing or not set.

        :param message: [Required, can be bytes or str]
        :param label: [Optional, can be bytes or str]
        :return: Decrypted message in bytes
        """

        if self.private_key is None:
            raise ValueError("Private key is missing or unset.")

        message, label = _prepare_types(
            prepare_type='rsa',
            message=message, label=label
        )

        decrypted_message = self.private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.hash_method),
                algorithm=self.hash_method,

                label=label
            )
        )

        return decrypted_message

    def sign(
            self, message: [bytes, str]
    ) -> bytes:
        """
        Get the signature of a certain message.

        Quick help:
         - Uses the RSA keys loaded in the class.
         - Automatically encodes the message in utf-8 if it's a string.
         - Raises an error if the private key is missing or not set.

        :param message: [Required, can be bytes or str]
        :return: Signature of message
        """
        if self.private_key is None:
            raise ValueError("Private key is missing or unset.")

        message = _prepare_types(
            prepare_type='rsa', message=message
        )[0]

        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(algorithm=self.hash_method),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            self.hash_method
        )

        return signature

    def verify(
            self, signature: bytes,
            message: [bytes, str]
    ) -> bool:
        """
        Verify the signature of a certain message.

        Quick help:
         - Uses the RSA keys loaded in the class.
         - Automatically encodes the message in utf-8 if it's a string.
         - Raises an error if the public key is missing or not set.

        :param signature: [Required, must be bytes]
        :param message: [Required, can be bytes or str]
        :return: True if the signatures match, False if not
        """

        if self.public_key is None:
            raise ValueError("Public key is missing or unset.")

        message = _prepare_types(
            prepare_type='rsa', message=message,
        )[0]

        if not isinstance(signature, bytes):
            raise TypeError("Signature passed must be bytes")

        try:
            self.public_key.verify(
                signature,
                message,

                padding.PSS(
                    mgf=padding.MGF1(algorithm=self.hash_method),
                    salt_length=padding.PSS.MAX_LENGTH
                ),

                self.hash_method
            )
        except cryptography.exceptions.InvalidSignature:  # NOQA: ct.exceptions exists
            return False

        return True

    def manual_encrypt(
            self, message: [bytes, str],
            key: bytes = b"",

            label: [bytes, str] = b""
    ) -> bytes:
        """
        Encrypt data using the provided RSA key.

        Quick help:
        - Uses the RSA keys provided in the arguments.
        - Automatically encodes the message in utf-8 if it's a string.
        - Raises an error if the public key is not provided.

        :param key: [Required, must be bytes]
        :param message: [Required, can be bytes or str]
        :param label: [Optional, can be bytes or str]
        :return: Encrypted message in bytes
        """
        if not key:
            raise ValueError("No RSA public key was passed.")

        message, label, key = _prepare_types(
            prepare_type='rsa', message=message,
            label=label, key=key
        )

        # Main code
        rsa_key = serialization.load_pem_public_key(
            key
        )

        encrypted_message = rsa_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.hash_method),
                algorithm=self.hash_method,

                label=label
            )
        )

        return encrypted_message

    def manual_decrypt(
            self, message: [bytes, str],
            key: bytes = b"",

            label: [bytes, str] = b"",
            key_password: [bytes, str] = None
    ) -> bytes:
        """
        Decrypt data using the provided RSA key.

        Quick help:
        - Uses the RSA keys provided in the arguments.
        - Automatically encodes the message in utf-8 if it's a string.
        - Raises an error if the private key is not provided.

        :param key_password: [Optional, used to decrypt private key]
        :param key: [Required, must be bytes]
        :param message: [Required, can be bytes or str]
        :param label: [Optional, can be bytes or str]
        :return: Decrypted message in bytes
        """

        if not key:
            raise ValueError("No RSA private key was passed.")

        message, label, key = _prepare_types(
            prepare_type='rsa', message=message,
            label=label, key=key
        )

        # Main code
        rsa_key = serialization.load_pem_private_key(
            key,
            key_password
        )

        parsed_message = rsa_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.hash_method),
                algorithm=self.hash_method,

                label=label
            )
        )

        return parsed_message

    def manual_sign(
            self, message: [bytes, str],
            key: bytes = b"",

            key_password: [bytes, str] = None
    ) -> bytes:
        """
        Get the signature of a certain message.

        Quick help:
        - Uses the RSA keys provided in the arguments.
        - Automatically encodes the message in utf-8 if it's a string.
        - Raises an error if the private key is not provided.

        :param key_password: [Optional, used to decrypt private key]
        :param key: [Required, must be bytes]
        :param message: [Required, can be bytes or str]
        :return: Signature of message
        """

        if not key:
            raise ValueError("No RSA private key was passed.")

        message, key = _prepare_types(
            prepare_type='rsa', message=message,
            key=key
        )

        rsa_key = serialization.load_pem_private_key(
            key,
            key_password
        )

        signed_message = rsa_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(algorithm=self.hash_method),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            self.hash_method
        )

        return signed_message

    def manual_verify(
            self, signature: bytes,
            message: [bytes, str],

            key: bytes = b""
    ) -> bool:
        """
        Verify the signature of a certain message.

        Quick help:
        - Uses the RSA keys provided in the arguments.
        - Automatically encodes the message in utf-8 if it's a string.
        - Raises an error if the public key is not provided.

        :param signature: [Required, must be bytes]
        :param message: [Required, can be bytes or str]
        :param key: [Required, must be bytes]
        :return: True if the signatures match, False if not
        """

        if not key:
            raise ValueError("Public key is missing or unset.")

        message, key = _prepare_types(
            prepare_type='rsa', message=message,
            key=key
        )

        # Run code depending on signature type (bytes)
        if not isinstance(signature, bytes):
            raise TypeError("Signature passed must be bytes")

        rsa_key = serialization.load_pem_public_key(
            key
        )

        try:
            rsa_key.verify(
                signature,
                message,

                padding.PSS(
                    mgf=padding.MGF1(algorithm=self.hash_method),
                    salt_length=padding.PSS.MAX_LENGTH
                ),

                self.hash_method
            )
        except cryptography.exceptions.InvalidSignature:  # NOQA: Exceptions exists
            return False

        return True


class _AESMethods:
    def __init__(self, parent):
        self.hash_method = parent.hash_method

        self.chacha20 = _ChaCha20Methods(self)
        self.gcm = _GCMMethods(self)


class _ChaCha20Methods:
    def __init__(self, parent):
        self.hash_method = parent.hash_method

    # Method is supposed to be public
    # noinspection PyMethodMayBeStatic
    def encrypt(
            self, data: [bytes, str],
            key: bytes = b"",

            nonce: bytes = b"",
            associated_data: [bytes, str] = None
    ) -> bytes:
        """
        Public method to encrypt with ChaCha20Poly1305.
        This requires you to provide the nonce and key directly.

        Quick help:

        - _prepare_types simply prepares the data to become bytes.

        :param data: [Required, can be bytes or str]
        :param key: [Required, must be bytes]
        :param nonce: [Required, must be bytes]
        :param associated_data: [Optional, can be bytes or str]
        :return: Encrypted data in bytes
        """
        data, associated_data, key, nonce = _prepare_types(
            aes_data=data,
            associated_data=associated_data,

            aes_key=key, nonce=nonce
        )

        chacha20 = ChaCha20Poly1305(key)
        encrypted_data = chacha20.encrypt(nonce, data, associated_data)

        return encrypted_data

    # Method is supposed to be public
    # noinspection PyMethodMayBeStatic
    def decrypt(
            self, data: [bytes, str],
            key: bytes = b"",

            nonce: bytes = b"",
            associated_data: [bytes, str] = None
    ) -> bytes:
        """
        Public method to decrypt with ChaCha20Poly1305.
        This requires you to provide the nonce and key directly.

        Quick help:

        - _prepare_types simply prepares the data to become bytes.

        :param data: [Required, can be bytes or str]
        :param key: [Required, must be bytes]
        :param nonce: [Required, must be bytes]
        :param associated_data: [Optional, can be bytes or str]
        :return: Decrypted data in bytes
        """
        data, associated_data, key, nonce = _prepare_types(
            aes_data=data,
            associated_data=associated_data,

            aes_key=key, nonce=nonce
        )
        chacha20 = ChaCha20Poly1305(key)
        plaintext = chacha20.decrypt(nonce, data, associated_data)

        return plaintext


class _GCMMethods:
    def __init__(self, parent):
        self.hash_method = parent.hash_method

    # Method is supposed to be public
    # noinspection PyMethodMayBeStatic
    def encrypt(
            self, data: [bytes, str],
            key: bytes = b"",

            nonce: bytes = b"",
            associated_data: [bytes, str] = None
    ) -> bytes:
        """
        Public method to encrypt with AES-GCM.
        This requires you to provide the nonce and key directly.

        Quick help:

        - _prepare_types simply prepares the data to become bytes.

        :param data: [Required, can be bytes or str]
        :param key: [Required, must be bytes]
        :param nonce: [Required, must be bytes]
        :param associated_data: [Optional, can be bytes or str]
        :return: Encrypted data in bytes
        """
        data, associated_data, key, nonce = _prepare_types(
            aes_data=data,
            associated_data=associated_data,

            aes_key=key, nonce=nonce
        )

        gcm = AESGCM(key)
        encrypted_data = gcm.encrypt(nonce, data, associated_data)

        return encrypted_data

    # Method is supposed to be public
    # noinspection PyMethodMayBeStatic
    def decrypt(
            self, data: [bytes, str],
            key: bytes = b"",

            nonce: bytes = b"",
            associated_data: [bytes, str] = None
    ) -> bytes:
        """
        Public method to decrypt with AES-GCM.
        This requires you to provide the nonce and key directly.

        Quick help:

        - _prepare_types simply prepares the data to become bytes.

        :param data: [Required, can be bytes or str]
        :param key: [Required, must be bytes]
        :param nonce: [Required, must be bytes]
        :param associated_data: [Optional, can be bytes or str]
        :return: Decrypted data in bytes
        """
        data, associated_data, key, nonce = _prepare_types(
            aes_data=data,
            associated_data=associated_data,

            aes_key=key, nonce=nonce
        )
        gcm = AESGCM(key)
        plaintext = gcm.decrypt(nonce, data, associated_data)

        return plaintext


if __name__ == '__main__':
    raise RuntimeError('This script must be imported as a module')

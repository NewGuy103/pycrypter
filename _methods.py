import base64
import os
import threading

import sys
import traceback
import shutil

import secrets
from typing import (
    Callable, Any, Literal,
    Iterable
)

import cryptography

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import (
    hashes, serialization
)

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def progress_bar(
        iteration: int, total: int,
        prefix: str = '',

        suffix: str = '',
        decimals: int = 1,

        length: int = 50,
        fill: str = '='
) -> None:
    """
    Call sys.stdout.write() to write a progress bar to the terminal

    Parameters:
        iteration (int): current iteration (required)
            The current iteration of the loop.

        total (int): total iterations (required)
            The total number of iterations for the loop

        prefix (str): prefix string (optional, defaults to "")
            A string that appears before the progress bar.

        suffix (str): suffix string (optional, defaults to "")
            A string that appears after the progress bar.

        decimals (int): positive number of decimals in percent complete (optional, defaults to 1)
            The number of decimal places to show in the percentage.

        length (int): character length of bar (optional, defaults to 50)
            The length of the progress bar.

        fill (str): bar fill character (optional, defaults to "=")
            The character used to fill the progress bar.

    Returns:
        None

    Example usage:
        progress_bar(10, 100, prefix='Progress:', suffix='Complete', decimals=1, length=50, fill='=')

        Output:
            Progress: |=====---------------------------------------------| 10.0% Complete
    """

    if not isinstance(iteration, int):
        raise TypeError(f"total expected an integer, got {type(iteration).__name__}")

    if not isinstance(total, int):
        raise TypeError(f"total expected an integer, got {type(total).__name__}")

    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)

    sys.stdout.write('\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix))
    sys.stdout.flush()


def iterate_dir(
        directory: str,
        iterate_tree: bool = True,

        skip_dirs: Iterable = None
) -> tuple[set, set]:
    """
    Retrieves file paths within a directory and tracks failed paths due to permission issues.

    Parameters:
        directory (str): The directory path to iterate through.
        iterate_tree (bool, optional): If True, iterates through subdirectories recursively. Default is True.
        skip_dirs (set, optional): A set of directory paths to skip during iteration. Default is None.

    Returns:
        tuple: A tuple containing:
            - set: File paths within the specified directory.
            - set: Paths that failed to access due to permission issues.

    Raises:
        NotADirectoryError: If the 'directory' argument is not a valid directory.

    Note:
        - The 'iterate_tree' parameter, when set to True, enables recursive iteration through subdirectories.
        - The 'skip_dirs' parameter allows skipping specific directories during the iteration process.
    """

    if not skip_dirs:
        skip_dirs = set()

    if iterate_tree not in (True, False):
        raise TypeError(
            f"'iterate_tree' expected boolean, got '{type(iterate_tree).__name__}'"
        )

    file_paths = set()
    failed_paths = set()

    if not os.path.isdir(directory):
        raise NotADirectoryError(f'Not a directory: {directory}')

    for filename in os.listdir(directory):
        path = None
        try:
            path = os.path.join(directory, filename)

            if path in skip_dirs:
                continue

            if os.path.isfile(path):
                file_paths.add(path)

            elif os.path.isdir(path) and iterate_tree:
                result = iterate_dir(path)

                file_paths.update(result[0])
                failed_paths.update(result[1])
        except PermissionError:
            failed_paths.add(path)

    return file_paths, failed_paths


class ThreadManager:
    """
    Manages a pool of threads, allowing the execution of callback functions with thread and error handling.

    Attributes:
        error_list (list): A list to store error information from threads.
        result_list (list): A list to store results from threads.
        threads_set (set): A set to keep track of active threads.
        semaphore (threading.Semaphore): A semaphore to control the number of concurrent threads.
    """

    def __init__(self):
        self.error_list = []
        self.result_list = []

        self.threads_set = set()
        self.semaphore = threading.Semaphore(5)

    def set_thread_count(self, num: int) -> None:
        """
        Sets the number of threads that can run concurrently.

        Parameters:
            num (int): The number of threads.

        Raises:
            TypeError: If num is not an integer.
        """

        if not isinstance(num, int):
            raise TypeError(f"num expected int, got type '{type(num).__name__}'")

        if num < 1:
            num = 1

        self.semaphore = threading.Semaphore(num)
        return

    def worker(
            self, callback_function: Callable,
            *args,

            semaphore: threading.Semaphore = None,

            threads_set: set = None,
            error_list: list = None,

            result_list: list = None,
            **kwargs
    ) -> Any:
        """
        Executes a callback function with thread and error handling.

        Parameters:
            callback_function (Callable): The callback function to execute.
            semaphore (threading.Semaphore): A semaphore for thread synchronization.
            threads_set (set): A set to keep track of active threads.
            error_list (list): A list to store error information.
            result_list (list): A list to store results.
            *args: Positional arguments to pass to the callback function.
            **kwargs: Keyword arguments to pass to the callback function.

        Returns:
            Any: The result of the callback function.

        Raises:
            TypeError: If input parameters have unexpected types.
        """

        match threads_set:
            case set():
                pass
            case None:
                threads_set = self.threads_set
            case _:
                raise TypeError(
                    f"threads_set expected set, got '{type(threads_set).__name__}'"
                )

        match error_list:
            case list():
                pass
            case None:
                error_list = self.error_list
            case _:
                raise TypeError(
                    f"error_list expected list, got '{type(error_list).__name__}'"
                )

        match result_list:
            case list():
                pass
            case None:
                result_list = self.result_list
            case _:
                raise TypeError(
                    f"result_list expected list, got '{type(result_list).__name__}'"
                )

        lock_types = (
            type(threading.Lock()),
            type(threading.Semaphore())
        )

        if not isinstance(semaphore, lock_types) and semaphore is not None:
            raise TypeError(
                "expected a semaphore/lock, got "
                f"'{type(semaphore).__name__}'"
            )
        elif semaphore is None:
            semaphore = self.semaphore

        if not callable(callback_function):
            raise TypeError("callback function passed is not callable")

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
                    tb_dict = {}
                    tb_msg = traceback.format_exc()

                    tb_dict["name"] = type(err).__name__
                    tb_dict["caller"] = func_name

                    tb_dict["traceback"] = tb_msg

                    error_list.append(tb_dict)
                else:
                    tb_msg = traceback.format_exc()
                    print(tb_msg)
            else:
                if result_list is not None:
                    rl_dict = {
                        'callback_name': func_name,
                        'result': result
                    }
                    result_list.append(rl_dict)
            finally:
                (threads_set.remove(current_thread)
                 if current_thread in threads_set else None)

        return result

    def thread_create(
            self,
            callback: Callable,
            *args,

            semaphore: threading.Semaphore = None,
            threads_set: set = None,

            thread_name: str = "",
            error_list: list = None,

            result_list: list = None,
            **kwargs
    ) -> threading.Thread:
        """
        Creates a thread to execute a callback function.

        Parameters:
            callback (Callable): The callback function to execute in a thread.
            *args: Positional arguments to pass to the callback function.
            semaphore (threading.Semaphore): A semaphore for thread synchronization.
            threads_set (set): A set to keep track of active threads.
            thread_name (str): The name to assign to the created thread.
            error_list (list): A list to store error information.
            result_list (list): A list to store results.
            **kwargs: Keyword arguments to pass to the callback function.

        Returns:
            threading.Thread: The created thread.
        """

        match threads_set:
            case set():
                pass
            case None:
                threads_set = self.threads_set
            case _:
                raise TypeError(
                    f"threads_set expected set, got '{type(threads_set).__name__}'"
                )

        worker_kwargs = {
            'semaphore': semaphore,
            'threads_set': threads_set,

            'error_list': error_list,
            'result_list': result_list
        }
        worker_kwargs.update(kwargs)

        thread = threading.Thread(
            target=self.worker,
            args=(callback, *args),
            kwargs=worker_kwargs,
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

        return

    @staticmethod
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

    @staticmethod
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

    def hash_string(
            self, input_string: str | bytes,
            hash_method: Any = None
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

        match input_string:
            case str():
                bytes_passed = input_string.encode('utf-8')
            case bytes():
                bytes_passed = input_string
            case _:
                raise TypeError("'input_string' can only be bytes or str")

        digest = hashes.Hash(hash_method)

        digest.update(bytes_passed)
        hashed_bytes = digest.finalize()

        hashed_string = hashed_bytes.hex()
        return hashed_string

    def hash_key(
            self, input_key: bytes | str,
            salt: bytes = b"",

            hash_pepper: bytes | str = b"",
            password_pepper: bytes | str = b"",

            hash_method: Any = None
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

        match input_key:
            case bytes():
                key = kdf.derive(input_key + password_pepper)
            case str():
                input_key = input_key.encode('utf-8')
                key = kdf.derive(input_key + password_pepper)
            case _:
                raise TypeError("'input_key' can only be bytes or str")

        return key


class _FernetMethods:
    """
    Provides methods for file and data encryption/decryption using Fernet encryption.

    This class encapsulates functionalities similar to Fernet encryption for symmetric key-based encryption.
    It includes methods to encrypt and decrypt files or data, supporting key derivation, password-based
    encryption, hashing, and various encryption schemes.

    Methods:
        encrypt_file(input_file, kdf_key, password, keep_copy, hash_pepper, password_pepper):
            Encrypts a file using Fernet encryption with key derivation.

        decrypt_file(input_file, kdf_key, password, keep_copy, hash_pepper, password_pepper):
            Decrypts a file encrypted using Fernet encryption with key derivation.

        encrypt_data(data, kdf_key, password, hash_pepper, password_pepper):
            Encrypts data using Fernet encryption with key derivation.

        decrypt_data(data, kdf_key, password, hash_pepper, password_pepper):
            Decrypts data encrypted using Fernet encryption with key derivation.
    """

    def __init__(self, parent):
        self.hash_method = parent.hash_method

    @staticmethod
    def _file_encrypt(
            input_file: str,
            key: bytes = b"",

            salt: bytes = b"",
            keep_copy: bool = False,

            is_precomputed: bool = False
    ):
        """
        Encrypts a file using Fernet encryption.

        Parameters:
            input_file (str): Path to the input file to be encrypted.
            key (bytes): Encryption key (default: b"").
            salt (bytes): Salt used in encryption (default: b"").
            keep_copy (bool): Indicates if a decrypted copy should be kept (default: False).
            is_precomputed (bool): Indicates if a precomputed key is used (default: False).
        """
        if is_precomputed:
            salt = b""

        with open(input_file, "rb+") as file:
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

                chunk = file.read(50 * 1024 * 1024)
            return

    @staticmethod
    def _file_decrypt(
            input_file: str, key: bytes = b"",
            keep_copy: bool = False,

            is_precomputed: bool = False
    ) -> None:
        """
        Decrypts a file encrypted using Fernet encryption.

        Parameters:
            input_file (str): Path to the input file to be decrypted.
            key (bytes): Decryption key (default: b"").
            keep_copy (bool): Indicates if an encrypted copy should be kept (default: False).
            is_precomputed (bool): Indicates if a precomputed key is used (default: False).
        """

        with open(input_file, "rb+") as file:
            fernet_key = base64.urlsafe_b64encode(key)

            # If a precomputed key was used, no salt should be available
            if not is_precomputed:
                file.seek(32, os.SEEK_SET)

            chunk = file.read(50 * 1024 * 1024)
            Fernet(fernet_key).decrypt(chunk)

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

    @staticmethod
    def _data_encrypt(
            data: bytes | str,
            salt: bytes = b"",

            key: bytes = b"",
            is_precomputed: bool = False
    ) -> bytes:
        """
        Encrypts data using Fernet encryption.

        Parameters:
            data (bytes | str): Data to be encrypted.
            salt (bytes): Salt used in encryption (default: b"").
            key (bytes): Encryption key (default: b"").
            is_precomputed (bool): Indicates if a precomputed key is used (default: False).

        Raises:
            ValueError: If key length is invalid for Fernet.
        """

        if len(key) != 32:
            raise ValueError("Key length is invalid for fernet.")

        if is_precomputed:
            salt = b""

        if not isinstance(data, bytes):
            data = data.encode("utf-8")

        fernet_key = base64.urlsafe_b64encode(key)
        encrypted_data = salt + Fernet(fernet_key).encrypt(data)

        return encrypted_data

    @staticmethod
    def _data_decrypt(
            data: bytes | str,
            key: bytes = b"",

            is_precomputed: bool = False
    ) -> bytes:
        """
        Decrypts data encrypted using Fernet encryption.

        Parameters:
            data (bytes | str): Data to be decrypted.
            key (bytes): Decryption key (default: b"").
            is_precomputed (bool): Indicates if a precomputed key is used (default: False).

        Raises:
            ValueError: If key length is invalid for Fernet.
        """

        if len(key) != 32:
            raise ValueError("Key length is invalid for fernet.")

        if not is_precomputed:
            data = data[32:]

        fernet_key = base64.urlsafe_b64encode(key)
        decrypted_data = Fernet(fernet_key).decrypt(data)

        return decrypted_data

    def encrypt_file(
            self, input_file: str,
            kdf_key: bytes = b"",

            password: bytes | str = b"",
            keep_copy: bool = False,

            hash_pepper: bytes | str = b"",
            password_pepper: bytes | str = b""
    ) -> None:
        """
        Encrypts a file using Fernet encryption with key derivation.

        Parameters:
            input_file (str): Path to the input file to be encrypted.
            kdf_key (bytes): Key used in key derivation (default: b"").
            password (bytes | str): Password for encryption (default: b"").
            keep_copy (bool): Indicates if a decrypted copy should be kept (default: False).
            hash_pepper (bytes | str): Pepper for hashing (default: b"").
            password_pepper (bytes | str): Pepper for password (default: b"").

        Raises:
            TypeError [1]: If 'keep_copy' is not a boolean.
            FileNotFoundError: If the input file does not exist.
            IsADirectoryError: If the input file is a directory.
            ValueError: If key length is invalid for Fernet.
            TypeError [2]: If 'hash_pepper' or 'password_pepper' are not bytes or strings.
            TypeError [3]: If 'password' is not bytes or a string.
        """

        if keep_copy not in (True, False):
            raise TypeError(f"'keep_copy' can only be bool, but got '{keep_copy}'")

        # Check argument if it's a file
        if not os.path.isfile(input_file):
            raise FileNotFoundError(f"No such file: {input_file}")
        elif os.path.isdir(input_file):
            raise IsADirectoryError(f"Is a directory: {input_file}")

        if kdf_key:
            if len(kdf_key) < 32:
                raise ValueError("Key length is invalid for fernet.")

            self._file_encrypt(
                input_file,
                key=kdf_key,

                keep_copy=keep_copy,
                is_precomputed=True
            )
            return

        match hash_pepper:
            case bytes():
                pass
            case str():
                hash_pepper = hash_pepper.encode('utf-8')
            case _:
                raise TypeError("'hash_pepper' can only be bytes or str")

        match password_pepper:
            case bytes():
                pass
            case str():
                password_pepper = password_pepper.encode('utf-8')
            case _:
                raise TypeError("'password_pepper' can only be bytes or str")

        salt = secrets.token_bytes(32)

        # Construct the PBKDF2HMAC object
        kdf = PBKDF2HMAC(
            algorithm=self.hash_method,
            length=32,
            salt=salt + hash_pepper,
            iterations=100000
        )

        match password:
            case bytes():
                key = kdf.derive(password + password_pepper)
            case str():
                input_key = password.encode('utf-8')
                key = kdf.derive(input_key + password_pepper)
            case _:
                raise TypeError("'password' can only be bytes or str")

        self._file_encrypt(
            input_file,
            salt=salt,

            key=key,
            keep_copy=keep_copy
        )
        return

    # decryption function
    def decrypt_file(
            self, input_file: str,
            kdf_key: bytes = b"",

            password: bytes | str = b"",
            keep_copy: bool = False,

            hash_pepper: bytes | str = b"",
            password_pepper: bytes | str = b""
    ) -> None:
        """
        Decrypts a file encrypted using Fernet encryption with key derivation.

        Parameters:
            input_file (str): Path to the input file to be decrypted.
            kdf_key (bytes): Key used in key derivation (default: b"").
            password (bytes | str): Password for decryption (default: b"").
            keep_copy (bool): Indicates if an encrypted copy should be kept (default: False).
            hash_pepper (bytes | str): Pepper for hashing (default: b"").
            password_pepper (bytes | str): Pepper for password (default: b"").

        Raises:
            TypeError [1]: If 'keep_copy' is not a boolean.
            FileNotFoundError: If the input file does not exist.
            IsADirectoryError: If the input file is a directory.
            ValueError: If key length is invalid for Fernet.
            TypeError [2]: If 'hash_pepper' or 'password_pepper' are not bytes or strings.
            TypeError [3]: If 'password' is not bytes or a string.
        """

        if keep_copy not in (True, False):
            raise TypeError(f"'keep_copy' can only be bool, but got '{keep_copy}'")

        # Check argument if it's a file
        if not os.path.isfile(input_file):
            raise FileNotFoundError(f"No such file: {input_file}")
        elif os.path.isdir(input_file):
            raise IsADirectoryError(f"Is a directory: {input_file}")

        # Decrypt the file in chunks
        if kdf_key:
            if len(kdf_key) < 32:
                raise ValueError("Key length is invalid for fernet.")

            self._file_decrypt(input_file, key=kdf_key, keep_copy=keep_copy, is_precomputed=True)
            return

        match hash_pepper:
            case bytes():
                pass
            case str():
                hash_pepper = hash_pepper.encode('utf-8')
            case _:
                raise TypeError("'hash_pepper' can only be bytes or str")

        match password_pepper:
            case bytes():
                pass
            case str():
                password_pepper = password_pepper.encode('utf-8')
            case _:
                raise TypeError("'password_pepper' can only be bytes or str")

        with open(input_file, "rb+") as file:
            salt = file.read(32)

        kdf = PBKDF2HMAC(
            algorithm=self.hash_method,
            length=32,
            salt=salt + hash_pepper,
            iterations=100000
        )

        match password:
            case bytes():
                key = kdf.derive(password + password_pepper)
            case str():
                input_key = password.encode('utf-8')
                key = kdf.derive(input_key + password_pepper)
            case _:
                raise TypeError("'password' can only be bytes or str")

        self._file_decrypt(input_file, key=key, keep_copy=keep_copy, is_precomputed=False)
        return

    # encryption function
    def encrypt_data(
            self, data: bytes | str,
            kdf_key: bytes = b"",

            password: bytes | str = b"",
            hash_pepper: bytes | str = b"",

            password_pepper: bytes | str = b""
    ) -> bytes:
        """
        Encrypts data using Fernet encryption with key derivation.

        Parameters:
            data (bytes | str): Data to be encrypted.
            kdf_key (bytes): Key used in key derivation (default: b"").
            password (bytes | str): Password for encryption (default: b"").
            hash_pepper (bytes | str): Pepper for hashing (default: b"").
            password_pepper (bytes | str): Pepper for password (default: b"").

        Raises:
            ValueError: If key length is invalid for Fernet.
            TypeError [1]: If 'hash_pepper' or 'password_pepper' are not bytes or strings.
            TypeError [2]: If 'password' is not bytes or a string.
        """

        if kdf_key:
            if len(kdf_key) < 32:
                raise ValueError("Key length is invalid for fernet.")

            return self._data_encrypt(data=data, key=kdf_key, is_precomputed=True)

        match hash_pepper:
            case bytes():
                pass
            case str():
                hash_pepper = hash_pepper.encode('utf-8')
            case _:
                raise TypeError("'hash_pepper' can only be bytes or str")

        match password_pepper:
            case bytes():
                pass
            case str():
                password_pepper = password_pepper.encode('utf-8')
            case _:
                raise TypeError("'password_pepper' can only be bytes or str")

        salt = secrets.token_bytes(32)

        kdf = PBKDF2HMAC(
            algorithm=self.hash_method,
            length=32,
            salt=salt + hash_pepper,
            iterations=100000
        )

        match password:
            case bytes():
                key = kdf.derive(password + password_pepper)
            case str():
                input_key = password.encode('utf-8')
                key = kdf.derive(input_key + password_pepper)
            case _:
                raise TypeError("'password' can only be bytes or str")

        return self._data_encrypt(data=data, salt=salt, key=key, is_precomputed=False)

    # decryption function
    def decrypt_data(
            self, data: bytes | str,
            kdf_key: bytes = b"",

            password: bytes | str = b"",
            hash_pepper: bytes | str = b"",

            password_pepper: bytes | str = b""
    ) -> bytes:
        """
        Decrypts data encrypted using Fernet encryption with key derivation.

        Parameters:
            data (bytes | str): Data to be decrypted.
            kdf_key (bytes): Key used in key derivation (default: b"").
            password (bytes | str): Password for decryption (default: b"").
            hash_pepper (bytes | str): Pepper for hashing (default: b"").
            password_pepper (bytes | str): Pepper for password (default: b"").

        Raises:
            ValueError: If key length is invalid for Fernet.
            TypeError [1]: If 'hash_pepper' or 'password_pepper' are not bytes or strings.
            TypeError [2]: If 'password' is not bytes or a string.
        """

        if kdf_key:
            if len(kdf_key) < 32:
                raise ValueError("Key length is invalid for fernet.")

            return self._data_decrypt(data=data, key=kdf_key, is_precomputed=True)

        match hash_pepper:
            case bytes():
                pass
            case str():
                hash_pepper = hash_pepper.encode('utf-8')
            case _:
                raise TypeError("'hash_pepper' can only be bytes or str")

        match password_pepper:
            case bytes():
                pass
            case str():
                password_pepper = password_pepper.encode('utf-8')
            case _:
                raise TypeError("'password_pepper' can only be bytes or str")

        salt = data[:32]

        if not isinstance(salt, bytes):
            salt = salt.encode('utf-8')

        kdf = PBKDF2HMAC(
            algorithm=self.hash_method,
            length=32,
            salt=salt + hash_pepper,
            iterations=100000
        )

        match password:
            case bytes():
                key = kdf.derive(password + password_pepper)
            case str():
                input_key = password.encode('utf-8')
                key = kdf.derive(input_key + password_pepper)
            case _:
                raise TypeError("'password' can only be bytes or str")

        return self._data_decrypt(data=data, key=key, is_precomputed=False)


class _RSAMethods:
    """
    Helper class implementing RSA encryption, decryption, signing, and verification methods.

    This class provides functionality to generate RSA keys, load keys into the class,
    encrypt and decrypt data, sign and verify signatures, as well as perform these operations
    using manually provided keys.

    Attributes:
        hash_method (str): The hash method used for encryption and decryption.

    Methods:
        generate_keys(key_length, public_exponent, password, output_to, key_names):
            Generates RSA public and private keys and saves them to files or returns them as bytes.

        load_keys(public_key, private_key, key_password):
            Load RSA PEM keys into the class.

        encrypt(message, label, public_key):
            Encrypts data using the loaded RSA keys.

        decrypt(message, label, private_key, key_password):
            Decrypts data using the loaded RSA keys.

        sign(message, private_key, key_password):
            Get the signature of a certain message.

        verify(signature, message, public_key):
            Verify the signature of a certain message.

    Raises:
        TypeError: If incorrect data types are provided for various parameters.
        ValueError: If keys are missing or not provided.
    """

    def __init__(self, parent):
        self.hash_method = parent.hash_method

        self.private_key = None
        self.public_key = None

    @staticmethod
    def generate_keys(
            key_length: int = 2048,
            public_exponent: int = 65537,

            password: bytes = b"",
            output_to: str = "file",

            key_names: list | set | tuple | None = None
    ) -> tuple | None:
        """
        Generates RSA public and private keys and saves them to files or returns them as bytes.

        Parameters:
            key_length (int): Length of the key to be generated (default: 2048).
            public_exponent (int): Public exponent for key generation (default: 65537).
            password (bytes): Password to encrypt the private key (default: b"").
            output_to (str): Specifies where to output the keys ("file", "caller", "file-caller") (default: "file").
            key_names (list | set | tuple | None): Names for public and private key files (default: None).

        Returns:
            tuple | None: If output_to is "caller" or "file-caller", returns public
              and private key bytes. Otherwise, returns None.

        Raises:
            TypeError: If incorrect data types are provided for key_length, public_exponent, password, or key_names.
            ValueError: If key_names does not contain exactly two items.
        """

        key_names = [
            "public_key.pem",
            "private_key.pem"
        ] if key_names is None else key_names

        if not isinstance(key_length, int):
            raise TypeError("Key length must be an integer")

        if not isinstance(public_exponent, int):
            raise TypeError("Public exponent must be an integer")

        if not isinstance(password, bytes):
            raise TypeError("Password must be bytes")

        if not isinstance(key_names, (list, set, tuple)):
            raise TypeError("Key names must be an iterable")

        if len(key_names) != 2:
            raise ValueError("Key names must explicitly have 2 items")

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

        if output_to == "caller":
            return public_key_bytes, private_key_bytes

        # Write the key bytes to a file
        with (
            open(f"{key_names[0]}", "wb") as pb_key,
            open(f"{key_names[1]}", "wb") as pv_key
        ):
            pb_key.write(public_key_bytes)
            pv_key.write(private_key_bytes)

        if output_to == "file-caller":
            return public_key_bytes, private_key_bytes

        return

    def load_keys(
            self, public_key: bytes,
            private_key: bytes,

            key_source: str | Literal['file', 'caller'] = "caller",
            key_password: bytes | None = None
    ) -> None:
        """
        Load RSA PEM keys from file paths or arguments into instance.

        Parameters:
            key_source (str): Source of where to get the keys. (file for paths, caller for passing to arguments)
            public_key (bytes): Public key bytes in PEM format.
            private_key (bytes): Private key bytes in PEM format.
            key_password (bytes | None): Password for the private key (default: None).

        Returns:
            None

        Raises:
            ValueError [1]: If the key_source is not file or caller.
            ValueError [2]: If public_key or private_key is missing or not provided.
            FileNotFoundError: If public_key or private_key paths do not exist.
        """

        if key_source not in ('file', 'caller'):
            raise ValueError("Key sources can only be 'file' or 'caller'")

        if key_source == 'file':
            if not os.path.isfile(public_key):
                raise FileNotFoundError(f"Key path '{public_key}' does not exist")
            elif not os.path.isfile(private_key):
                raise FileNotFoundError(f"Key path '{private_key}' does not exist")

            with open(public_key, 'rb') as public_keyfile, open(private_key, 'rb') as private_keyfile:
                public_key = public_keyfile.read()
                private_key = private_keyfile.read()

        self.public_key = serialization.load_pem_public_key(
            public_key
        )
        self.private_key = serialization.load_pem_private_key(
            private_key,
            key_password
        )
        return

    def encrypt(
            self, message: bytes | str,
            label: bytes | str = b"",

            public_key: bytes = None
    ) -> bytes:
        """
        Encrypt data using a provided key or the loaded RSA keys.

        Parameters:
            message (bytes | str): Data to be encrypted.
            label (bytes | str): Label to include in the encryption (default: b"").
            public_key (bytes): Public key bytes to use. (defaults to self.public_key)

        Returns:
            bytes: Encrypted message.

        Raises:
            ValueError: If the public key is missing or not provided.
            TypeError: If message or label is not bytes or str.
        """

        if public_key:
            rsa_key = serialization.load_pem_public_key(
                public_key
            )
        elif not public_key and self.public_key:
            rsa_key = self.public_key
        else:
            raise ValueError("Public key is missing or not provided.")

        match message:
            case str():
                message = message.encode('utf-8')
            case bytes():
                pass
            case _:
                raise TypeError("'message' can only be bytes or str")

        match label:
            case str():
                label = label.encode('utf-8')
            case bytes():
                pass
            case _:
                raise TypeError("'label' can only be bytes or str")

        encrypted_message = rsa_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.hash_method),
                algorithm=self.hash_method,

                label=label
            )
        )

        return encrypted_message

    def decrypt(
            self, message: bytes | str,
            label: bytes | str = b"",

            private_key: bytes = None,
            key_password: bytes = None
    ) -> bytes:
        """
        Decrypt data using a provided key or the loaded RSA keys.

        Parameters:
            message (bytes | str): Data to be decrypted.
            label (bytes | str): Label used in encryption (default: b"").
            private_key (bytes): Private key bytes to use. (defaults to self.private_key)
            key_password (bytes): Private key password.

        Returns:
            bytes: Decrypted message.

        Raises:
            ValueError: If the private key is missing or not provided.
            TypeError: If message or label is not bytes or str.
        """

        if private_key:
            rsa_key = serialization.load_pem_private_key(
                private_key,
                key_password
            )
        elif not private_key and self.private_key:
            rsa_key = self.private_key
        else:
            raise ValueError("Private key is missing or not provided.")

        match message:
            case str():
                message = message.encode('utf-8')
            case bytes():
                pass
            case _:
                raise TypeError("'message' can only be bytes or str")

        match label:
            case str():
                label = label.encode('utf-8')
            case bytes():
                pass
            case _:
                raise TypeError("'label' can only be bytes or str")

        decrypted_message = rsa_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.hash_method),
                algorithm=self.hash_method,

                label=label
            )
        )

        return decrypted_message

    def sign(
            self, message: bytes | str,
            private_key: bytes = None,

            key_password: bytes = None
    ) -> bytes:
        """
        Get the signature of a certain message.

        Parameters:
            message (bytes | str): Data to be signed.
            private_key (bytes): Private key bytes to use. (defaults to self.private_key)
            key_password (bytes): Password for private key.

        Returns:
            bytes: Signature of the message.

        Raises:
            ValueError: If the private key is missing or not provided.
            TypeError: If message is not bytes or str.
        """

        if private_key:
            rsa_key = serialization.load_pem_private_key(
                private_key,
                key_password
            )
        elif not private_key and self.private_key:
            rsa_key = self.private_key
        else:
            raise ValueError("Private key is missing or not provided.")

        match message:
            case str():
                message = message.encode('utf-8')
            case bytes():
                pass
            case _:
                raise TypeError("'message' can only be bytes or str")

        signature = rsa_key.sign(
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
            message: bytes | str,

            public_key: bytes = None
    ) -> bool:
        """
        Verify the signature of a certain message.

        Parameters:
            signature (bytes): Signature to be verified.
            message (bytes | str): Data whose signature needs verification.
            public_key (bytes): Public key bytes to use. (defaults to self.public_key

        Returns:
            bool: True if the signatures match, False if not.

        Raises:
            ValueError: If the public key is missing or not provided.
            TypeError: If message is not bytes or str.
        """

        if public_key:
            rsa_key = serialization.load_pem_public_key(
                public_key
            )
        elif not public_key and self.public_key:
            rsa_key = self.public_key
        else:
            raise ValueError("Public key is missing or not provided.")

        match message:
            case str():
                message = message.encode('utf-8')
            case bytes():
                pass
            case _:
                raise TypeError("'message' can only be bytes or str")

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
        except cryptography.exceptions.InvalidSignature:  # NOQA: ct.exceptions exists
            return False

        return True


if __name__ == '__main__':
    raise RuntimeError('This script must be imported as a module')

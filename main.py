# Required Modules
import platform
import os
import argparse

import getpass
import signal
import ctypes

import sys

from dotenv import load_dotenv
from typing import Final

from _methods import (
    CipherManager, ThreadManager,
    progress_bar, iterate_dir
)

__all__ = [
    "CipherManager", "ThreadManager",
    "progress_bar", "iterate_dir",
    "PYCRYPTER_VERSION"
]

PYCRYPTER_VERSION: Final = "1.4.2"


class _InteractiveCLI:
    def __init__(self, parent):
        self.password = None
        self.recovery_key = None
        self.thread_mgr = parent.thread_mgr
        self.cleanup = parent.cleanup

        self.cipher_file = parent.cipher_file
        self.cipher_directory = parent.cipher_directory

        self._load_messages()

    def _load_messages(self):
        self.messages = {}

    @staticmethod
    def _return_error(error_type, **kwargs):
        cmd_name = kwargs.get("cmd_name")
        message = kwargs.get("message")

        match error_type:
            case 'invalid_command':
                err_type = (
                    f"Error: Command '{cmd_name}' is not "
                    "a recognized command!"
                )
            case 'not_integer':
                err_type = (
                    f"Error: '{message}' is not an integer!"
                )
            case 'missing_arg':
                err_type = (
                    f"Error: Missing argument: '{message}'"
                )
            case _:
                print(f"Could not get error message for error type '{error_type}'")
                return

        print(err_type)
        return

    @staticmethod
    def _parse_str(input_string):
        tokens = []
        current_token = ""
        in_quotes = False

        for char in input_string:
            if char == '"':
                if in_quotes:
                    tokens.append(current_token)
                    current_token = ""
                in_quotes = not in_quotes
            elif char == ' ' and not in_quotes:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
            else:
                current_token += char

        if current_token:
            tokens.append(current_token)

        return tokens

    def mainloop(self):
        while not self.cleanup:
            user_input = input("pycrypter> ")
            args = self._parse_str(user_input)

            self.thread_mgr.error_list = []

            if len(args) == 0:
                continue

            if user_input == "exit":
                break

            cipher_switches = {
                'keep_copy': (
                        "-c" in args
                        or
                        "--keep-copy" in args
                ),
                'verbose': (
                        '-v' in args
                        or
                        '--verbose' in args
                ),

                'directory': (
                        '-dr' in args
                        or
                        '--directory' in args
                )
            }

            match args[0]:
                case "password":
                    try:
                        key = args[1]
                    except IndexError:
                        self._return_error(
                            "missing_arg",
                            message="password"
                        )
                        continue

                    self.password = key
                case "recovery-key":
                    try:
                        key = args[1]
                    except IndexError:
                        self._return_error(
                            "missing_arg",
                            message="recovery_key"
                        )
                        continue

                    self.recovery_key = key
                case "thread-count":
                    try:
                        num = int(args[1])
                    except ValueError:
                        self._return_error(
                            "not_integer",
                            message=args[1]
                        )
                        continue
                    except IndexError:
                        self._return_error(
                            "missing_arg",
                            message="thread_count"
                        )
                        continue

                    self.thread_mgr.set_thread_count(num)
                case "encrypt":
                    switches = cipher_switches
                    dirs = None
                    files = None

                    if switches['directory']:
                        filenames = input("Enter directories here: ")
                        dirs = set(self._parse_str(filenames))
                    else:
                        filenames = input("Enter filenames here: ")
                        files = set(self._parse_str(filenames))

                    if self.password is None:
                        password = getpass.getpass("Enter password: ")
                    else:
                        password = self.password

                    if switches['directory']:
                        self.cipher_directory(
                            dirs,
                            verbose=switches['verbose'],

                            password=password,
                            keep_copy=switches['keep_copy'],

                            cipher_method='encrypt'
                        )
                    else:
                        self.cipher_file(
                            files,
                            verbose=switches['verbose'],

                            password=password,
                            keep_copy=switches['keep_copy'],

                            cipher_method='encrypt'
                        )
                case "decrypt":
                    switches = cipher_switches
                    dirs = None
                    files = None

                    if switches['directory']:
                        filenames = input("Enter directories here: ")
                        dirs = set(self._parse_str(filenames))
                    else:
                        filenames = input("Enter filenames here: ")
                        files = set(self._parse_str(filenames))

                    if self.password is None:
                        password = getpass.getpass("Enter password: ")
                    else:
                        password = self.password

                    if switches['directory']:
                        self.cipher_directory(
                            dirs,
                            verbose=switches['verbose'],

                            password=password,
                            keep_copy=switches['keep_copy'],

                            cipher_method='decrypt'
                        )
                    else:
                        self.cipher_file(
                            files,
                            verbose=switches['verbose'],

                            password=password,
                            keep_copy=switches['keep_copy'],

                            cipher_method='decrypt'
                        )
                case _:
                    self._return_error(
                        "invalid_command",
                        cmd_name=args[0]
                    )


class Main:
    def __init__(self):
        if __name__ != "__main__":
            raise RuntimeError("class Main must be called from __main__")

        # pepper | DO NOT LEAK THIS!
        load_dotenv("pepper.env")

        self.hash_pepper = os.environ.get("hash_pepper", b"")
        self.password_pepper = os.environ.get("password_pepper", b"")

        # cleanup variables
        self.cleanup = False

        # misc
        self.thread_mgr = ThreadManager()
        self.thread_create = self.thread_mgr.thread_create

        self.cipher_mgr = CipherManager()

        self.encrypt_file = self.cipher_mgr.fernet.encrypt_file
        self.decrypt_file = self.cipher_mgr.fernet.decrypt_file

        # self.parser objects
        self.args = None
        self._add_args()

        self.cli = _InteractiveCLI(self)

    def _add_args(self) -> None:
        self.parser = argparse.ArgumentParser(description=f'Pycrypter CLI by NewGuy103. v{PYCRYPTER_VERSION}')

        self.parser.add_argument(
            '-i', '--interactive',
            action="store_true",
            help="Script interactive mode."
        )
        self.parser.add_argument(
            '-e', '--encrypt',
            action="store_true",
            help='Encryption switch.'
        )

        self.parser.add_argument(
            '-d', '--decrypt',
            action="store_true",
            help='Decryption switch.'
        )

        self.parser.add_argument(
            '-ds', "--deep-search",
            action="store_true",
            help='If specified, search the sub-folders of the directory specified.'
        )

        self.parser.add_argument(
            '-c', "--keep-copy",
            action="store_true",
            help='If specified, keep a copy of the encrypted/decrypted file.'
        )

        self.parser.add_argument(
            '-v', "--verbose",
            action="store_true",
            help='Show detailed output to the command-line.'
        )

        self.parser.add_argument(
            '-t', '--threads',
            metavar='int',
            nargs="?",
            type=int,
            help="Sets the maximum amount of files to process in memory."
        )

        self.parser.add_argument(
            '-f', "--file",
            metavar='input_file',
            type=str,
            nargs="+",
            help='File path(s) to specify.'
        )

        self.parser.add_argument(
            '-dr', "--directory",
            metavar='input_dir',
            type=str,
            nargs="+",
            help='Directory path(s) to specify.'
        )
        return

    def parse_args(self) -> None:
        self.args = self.parser.parse_args()

        if self.args.interactive:
            self.cli.mainloop()
            sys.exit()

        # Guard clauses
        if self.args.threads:
            self.thread_mgr.set_thread_count(self.args.threads)

        if self.args.encrypt and self.args.decrypt:
            raise argparse.ArgumentError(
                None,
                "expected 1 required argument, got two: -e/--encrypt and -d/--decrypt"
            )

        if not self.args.encrypt and not self.args.decrypt:
            raise argparse.ArgumentError(
                None,
                "missing required argument: -e/--encrypt or -d/--decrypt"
            )

        cipher_method = "encrypt" if self.args.encrypt else "decrypt"
        password = getpass.getpass("Enter password: ")

        separator = f"|{'-' * 61}|"
        print(f"{separator}\n", end="")

        if self.args.file:
            self.cipher_file(
                self.args.file,
                verbose=self.args.verbose,
                password=password,
                keep_copy=self.args.keep_copy,
                cipher_method=cipher_method
            )

        if self.args.directory:
            self.cipher_directory(
                self.args.directory,
                verbose=self.args.verbose,
                password=password,
                keep_copy=self.args.keep_copy,
                cipher_method=cipher_method
            )

        return

    def cipher_file(
            self, file_list: [list, set, tuple],
            verbose: bool = True,

            password: [bytes, str] = b"",
            keep_copy: bool = False,

            cipher_method: str = "encrypt"
    ) -> None:
        """
        Cipher a set of file(s) with extra parameters.

        :param file_list: A list/set/tuple including the file paths.
        :param verbose: Verbose output or no output.
        :param password: The key for ciphering the file.
        :param keep_copy: Keep a copy of the file
        :param cipher_method: "encrypt" or "decrypt"
        :return: None
        """
        if cipher_method not in {"encrypt", "decrypt"}:
            raise TypeError('cipher_method must be encrypt/decrypt')

        files = set()
        files_dict = {'count': 0, 'finished': 0, 'exception_thrown': 0}

        thread = None

        if cipher_method == 'encrypt':
            cipher_callback = self.encrypt_file
        elif cipher_method == 'decrypt':
            cipher_callback = self.decrypt_file

        for file in file_list:
            if os.path.isfile(file):
                files.add(file)
                files_dict['count'] += 1
                continue

            if len(files) > 1:
                if os.path.isdir(file):
                    print(f"IsADirectoryError: Is a directory: {file}")
                else:
                    print(f"FileNotFoundError: No such file: {file}")
            else:
                if os.path.isdir(file):
                    raise IsADirectoryError(f"Is a directory: {file}")
                else:
                    raise FileNotFoundError(f"No such file: {file}")

        for current_iteration, file in enumerate(files):
            if self.cleanup:
                break

            iter_var = current_iteration
            if current_iteration + 1 == files_dict['count']:
                iter_var = files_dict['count']

            progress_bar(
                iter_var,
                files_dict['count'],

                prefix='Progress: ',
                suffix='Complete',

                decimals=1,
                length=50,

                fill='='
            )

            thread = self.thread_create(
                # NOQA: cipher_callback is defined at the top
                callback=cipher_callback,  # NOQA

                input_file=file,
                password=password,
                keep_copy=keep_copy,

                hash_pepper=self.hash_pepper,
                password_pepper=self.password_pepper
            )

        if thread is not None:
            thread.join()

        files_dict['exception_thrown'] = len(self.thread_mgr.error_list)
        files_dict['finished'] = files_dict['count']

        files_dict['finished'] -= len(self.thread_mgr.error_list)

        if verbose:
            separator = f"|{'-' * 61}|"
            msg1 = (
                f"\n{separator}"
                "\n\n"

                "Total files parsed: "
                f"{files_dict['count']}\n"

                "Files parsed successfully: "
                f"{files_dict['finished']}\n"

                "Files not parsed: "
                f"{files_dict['exception_thrown']}"
            )

            msg2 = (
                f"\n{separator}"
                "\n\n"

                f"ThreadManager error list:\n"
            )

            print("\nVerbose logging information: ")

            print(msg1)
            print(msg2)

            err_list = list(self.thread_mgr.error_list)
            for err_dict in err_list:
                err_data = (
                    f"Error name: {err_dict['name']}\n"
                    f"Caller function: {err_dict['caller']}\n"

                    f"Error traceback: \n{err_dict['traceback']}"
                )

                print(err_data)

            return

    def cipher_directory(
            self, dirs: [list, set, tuple],
            verbose: bool = True,

            password: [bytes, str] = b"",
            keep_copy: bool = False,

            cipher_method: str = "encrypt"
    ) -> None:
        """
        Cipher a set of file(s) inside directories with extra parameters.

        :param dirs: A list/set/tuple including the directory paths.
        :param verbose: Verbose output or no output.
        :param password: The key for ciphering the file.
        :param keep_copy: Keep a copy of the file
        :param cipher_method: "encrypt" or "decrypt"
        :return: None
        """
        if cipher_method not in {"encrypt", "decrypt"}:
            raise TypeError('cipher_method must be encrypt/decrypt')

        files = set()
        folders = set()

        files_dict = {'count': 0, 'finished': 0, 'exception_thrown': 0}
        thread = None

        if cipher_method == 'encrypt':
            cipher_callback = self.encrypt_file
        elif cipher_method == 'decrypt':
            cipher_callback = self.decrypt_file

        for folder in dirs:
            if os.path.isdir(folder):
                folders.add(folder)
                continue

            if len(dirs) > 1:
                if os.path.isdir(folder):
                    print(f"NotADirectoryError: Is a directory: {folder}")
                else:
                    print(f"FileNotFoundError: No such file: {folder}")
            else:
                if os.path.isdir(folder):
                    raise NotADirectoryError(f"Is a directory: {folder}")
                else:
                    raise FileNotFoundError(f"No such directory: {folder}")

        for i, folder in enumerate(folders):
            returned_files = iterate_dir(folder, iterate_tree=True)

            for file in returned_files:
                files.add(file)

                if file in files:
                    files_dict['count'] += 1

        for current_iteration, file in enumerate(files):
            if self.cleanup:
                break

            iter_var = current_iteration
            if current_iteration + 1 == files_dict['count']:
                iter_var = files_dict['count']

            progress_bar(
                iter_var,
                files_dict['count'],

                prefix='Progress: ',
                suffix='Complete',

                decimals=1,
                length=50,

                fill='='
            )

            thread = self.thread_create(
                # NOQA: cipher_callback is defined at the top
                callback=cipher_callback,  # NOQA

                input_file=file,
                password=password,
                keep_copy=keep_copy,

                hash_pepper=self.hash_pepper,
                password_pepper=self.password_pepper
            )

        if thread is not None:
            thread.join()

        files_dict['exception_thrown'] = len(self.thread_mgr.error_list)
        files_dict['finished'] = files_dict['count']

        files_dict['finished'] -= len(self.thread_mgr.error_list)

        if verbose:
            separator = f"|{'-' * 61}|"
            msg1 = (
                f"\n{separator}"
                "\n\n"

                "Total files parsed: "
                f"{files_dict['count']}\n"

                "Files parsed successfully: "
                f"{files_dict['finished']}\n"

                "Files not parsed: "
                f"{files_dict['exception_thrown']}"
            )

            msg2 = (
                f"\n{separator}"
                "\n\n"

                f"ThreadManager error list:\n"
            )

            print("\nVerbose logging information: ")

            print(msg1)
            print(msg2)

            err_list = list(self.thread_mgr.error_list)
            for err_dict in err_list:
                err_data = (
                    f"Error name: {err_dict['name']}\n"
                    f"Caller function: {err_dict['caller']}\n"

                    f"Error traceback: \n{err_dict['traceback']}"
                )

                print(err_data)

            return


if __name__ == "__main__":
    if platform.system() == "Windows":
        # NOQA: Conditional import if the platform is Windows
        import win32api  # NOQA
        import win32con  # NOQA

        import win32file  # NOQA
        from winnt import MAXDWORD  # NOQA

        import pywintypes  # NOQA

    main = Main()


    def script_cleanup(*_, **__):
        main.cleanup = True


    # NOQA: PyCharm shows a warning when
    # passing script_cleanup directly to signal.signal()
    exit_call = lambda *_: script_cleanup()  # NOQA

    if platform.system() == "Windows":
        # kernel32 signal handler
        kernel32 = ctypes.windll.kernel32
        handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)

        handler_func = handler_type(script_cleanup)
        kernel32.SetConsoleCtrlHandler(handler_func, True)

        signal.signal(
            signal.SIGINT,
            exit_call
        )
        signal.signal(
            signal.SIGTERM,
            exit_call
        )
    else:
        signal.signal(
            signal.SIGINT,
            exit_call
        )
        signal.signal(
            signal.SIGTERM,
            exit_call
        )

    main.parse_args()

# Required Modules
import platform

import os
import sys
import argparse

import getpass
import signal
import ctypes

from dotenv import load_dotenv

from typing import Final
from typing import Iterable

from methods import CipherManager, ThreadManager

PYCRYPTER_VERSION: Final = "1.4.1"


def progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='='):
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


# iterate through a directory and optionally a subdirectory
def iterate_dir(directory, iterate_tree=True, skip_dirs=None):
    """
    Iterate through a directory while optionally iterating through the subdirectories

    Parameters:
        directory (str): directory to iterate (required)
            The directory passed to iterate through.

        iterate_tree (bool): iterate through subdirectories (optional, defaults to True)
            Defines whether the script iterates through subdirectories or not.

        skip_dirs (list): list of directories to skip (optional, defaults to []/empty list)
            Defines the subdirectories to exclude from the search.

        Returns:
            set: file_paths
            - Returns absolute paths

        Example usage:
            Passing a non-boolean [True, False] to
            the iterate_tree argument will result in a ValueError:

            Traceback (most recent call last):
              File "C:\\MyPython\\pycrypter.py", line 1, in <module>
                raise ValueError("iterate_tree must be a valid boolean")
            ValueError: iterate_tree must be a valid boolean

            [Passing True, False, 1, 0 is a valid boolean]

            =========================================================
            Passing a non-existent directory/a file will not raise
            an exception, but instead return a string value, signaling
            an error:

            Example 1:
                files = iterate_dir("C:\\MyFakeDirectory", iterate_tree=True, skip_dirs=[])

                print(files)

                [Output]
                NotADirectoryError

            Example 2:
                files = iterate_dir("C:\\MyPython\\myfile.txt", iterate_tree=True, skip_dirs=[])

                print(files)

                [Output]
                NotADirectoryError

            =========================================================
            A PermissionError exception will be caught, and added to
            an exception list:

            import win32api
            import win32con

            # Set the system attribute for the MyPython folder
            win32api.SetFileAttributes("C:\\MyPython\\", win32con.FILE_ATTRIBUTE_SYSTEM)

            permission_errors = []

            # Assume this code has two files, the script and "sys.txt"
            files = iterate_dir("C:\\MyPython\\", iterate_tree=True, skip_dirs=[])

            print(files)
            print(permission_errors)

            [Output]
            []
            ['iterate_dir | A PermissionError occured! Path: "C:\\MyPython"']

            ---------------------------------------------------------
            How to call:

            files = iterate_dir(".", iterate_tree=True, skip_dirs=[])

            print(files)

            ---------------------------------------------------------
            We can assume that the files in the current working directory
            is the current script file and a.txt, so this will be the output:

            ['.\\pycrypter.py', '.\\a.txt']
            ---------------------------------------------------------

            If you use "." or ".." as the directory argument, any added to
            the list will be formatted as so:

            ['.\\example.txt', '..\\myfile.txt']

            However, using the absolute path like so:
            iterate_dir("C:\\MyPython\\", iterate_tree=True, skip_dirs=[])

            Will return the absolute path, formatted like this:

            ['C:\\MyPython\\a.txt']
    """

    if not skip_dirs:
        skip_dirs = set()

    if iterate_tree not in [True, False]:
        raise TypeError(f"iterate_tree expected boolean, got {iterate_tree}")

    file_paths = set()

    # Check argument if it's a directory
    if not os.path.isdir(directory):
        if os.path.isfile(directory):
            raise NotADirectoryError(f'Not a directory: {directory}')
        else:
            raise FileNotFoundError(f'No such directory: {directory}')

    # Iterate through the directory, and catch PermissionErrors
    try:
        directory = os.path.abspath(directory)

        for filename in os.listdir(directory):
            path = os.path.join(directory, filename)

            if path in skip_dirs:
                continue

            if os.path.isfile(path):
                file_paths.add(path)

            elif os.path.isdir(path) and iterate_tree:
                file_paths.update(iterate_dir(path))
    except PermissionError as err:
        raise err
    finally:
        return file_paths


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

    def _add_args(self) -> None:
        self.parser = argparse.ArgumentParser(description=f'Pycrypter CLI by NewGuy103. v{PYCRYPTER_VERSION}')

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

        self.parser.add_argument(
            '-dt', '--data',
            metavar='passed_data',
            type=str,
            nargs="+",
            help="Data to encrypt."
        )
        return

    def parse_args(self) -> None:
        self.args = self.parser.parse_args()

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
        password = getpass.getpass("Enter password: ").encode('utf-8')

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
                callback=cipher_callback, # NOQA

                input_file=file,
                password=password,
                keep_copy=keep_copy,

                hash_pepper=self.hash_pepper,
                password_pepper=self.password_pepper
            )

        if thread is not None:
            thread.join()

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
    exit_call = lambda *_: script_cleanup() # NOQA

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

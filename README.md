# newguy103-pycrypter

The `newguy103-pycrypter` module is a comprehensive Python toolkit designed to facilitate various cryptographic operations, progress tracking, directory management, thread handling, and advanced encryption techniques.

## Features Overview

### Progress Tracking

The `progress_bar` function enables the generation of customized progress bars within the terminal, allowing precise tracking of iterative processes. This function is highly configurable, offering options for iteration count, prefix/suffix strings, bar length, and fill characters.

Example Usage:

```python
from pycrypter import progress_bar

# Track progress for an iterative process
progress_bar(10, 100, prefix='Progress:', suffix='Complete', decimals=1, length=50, fill='-')

# Output:
# Progress: |=====---------------------------------------------| 10.0% Complete
```

### Directory Iteration

The `iterate_dir` function simplifies directory traversal, efficiently retrieving file paths within a directory while managing permission-related path failures. It supports both recursive iteration through subdirectories and the exclusion of specific directories during traversal.

Example Usage:

```python
from pycrypter import iterate_dir

# Retrieve file paths within a directory
file_paths, failed_paths = iterate_dir(
    'path/to/directory', iterate_tree=True, 
    skip_dirs={'excluded_dir'}
)
```

### Thread Management

The `ThreadManager` class provides an intuitive interface to handle pools of threads, ensuring smooth execution of callback functions while efficiently managing errors and monitoring active threads.

Example Usage:

```python
from pycrypter import ThreadManager

# Create a ThreadManager instance
thread_manager = ThreadManager()

# Set the number of concurrent threads
thread_manager.set_thread_count(5)

# Create and execute a thread for a callback function
thread = thread_manager.thread_create(
    my_callback_function, 
    arg1, arg2,

    func_kwarg=42
)
thread.join()

# Get callback errors and callback results
print(thread_manager.error_list)
print(thread_manager.result_list)
```

### Encryption Techniques

The `CipherManager` class integrates two encryption methodologies, `_FernetMethods` and `_RSAMethods`, accessible as `self.fernet` and `self.rsa`, respectively. These classes offer versatile encryption and decryption functionalities using Fernet encryption and RSA algorithms.

#### Fernet Encryption

The `self.fernet` attribute, an instance of `_FernetMethods`, supports file and data encryption/decryption, symmetric key-based encryption, key derivation, password-based encryption, hashing, and various encryption schemes.

Example Usage:

```python
import secrets
from pycrypter import CipherManager

# Create a CipherManager instance
cipher_manager = CipherManager()

# Define peppers
hash_pepper = secrets.token_bytes(32)
password_pepper = secrets.token_bytes(32)

my_password = "..."

# Encrypt a file using Fernet encryption and a password
cipher_manager.fernet.encrypt_file(
    'file.txt', password=my_password,

    hash_pepper=hash_pepper,
    password_pepper=password_pepper
)

# Decrypt a previously encrypted file using Fernet encryption with the same password
cipher_manager.fernet.decrypt_file(
    'file.txt',
    password=my_password,
    hash_pepper=hash_pepper,
    password_pepper=password_pepper
)

# Print the file contents
with open('file.txt', 'r') as file:
    print("Decrypted File:", file.read())

# Encrypt data using Fernet encryption with a password and peppers
encrypted_data = cipher_manager.fernet.encrypt_data(
    b'Sensitive data to encrypt',
    password=my_password,

    hash_pepper=hash_pepper,
    password_pepper=password_pepper
)

# Decrypt previously encrypted data using Fernet encryption with the same password and peppers
decrypted_data = cipher_manager.fernet.decrypt_data(
    encrypted_data,
    password=my_password,
    hash_pepper=hash_pepper,
    password_pepper=password_pepper
)
print("Decrypted Data:", decrypted_data)
```

#### RSA Encryption and Decryption

The `self.rsa` attribute, an instance of `_RSAMethods`, offers RSA encryption, decryption, signing, and verification methods. It allows key generation, loading, encryption operations, and signature verification using the RSA algorithm.

Example Usage:

```python
from pycrypter import CipherManager

# Create a CipherManager instance
cipher_manager = CipherManager()

key_names = [
    'path/to/public_key.pem',
    'path/to/private_key.pem'
]

# Generate RSA keys to files
cipher_manager.rsa.generate_keys(
    key_length=2048,  public_exponent=65537, 
    password=b"", output_to="file", 

    key_names=key_names
)

# Load RSA keys from files
cipher_manager.rsa.load_keys(
    public_key='path/to/public_key.pem', 
    private_key='path/to/private_key.pem',

    key_source='file'
)

# Encrypt and Decrypt
message_to_encrypt = b"Your secret message"
encrypted_data = cipher_manager.rsa.encrypt(message_to_encrypt, label='optional_label')

decrypted_data = cipher_manager.rsa.decrypt(encrypted_data, label='optional_label')
print("Decrypted message:", decrypted_data.decode())

# Sign and Verify
message_to_sign = b"Your message to sign"
signature = cipher_manager.rsa.sign(message_to_sign)

is_verified = cipher_manager.rsa.verify(signature, message_to_sign)
print("Signature verified:", is_verified)
```

## Requirements

- `cryptography` library for cryptographic functionalities.
- `threading` module for managing threads.


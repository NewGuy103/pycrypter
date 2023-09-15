import methods
import cryptography

from cryptography.hazmat.primitives import hashes
import secrets

class CC:
    hash_method = hashes.SHA256()


tep = CC()
rsa = methods._RSAMethods(tep)

pb_k, pv_k = rsa.generate_keys(output_to='caller')
rsa.load_keys(pb_k, pv_k)

ct = rsa.encrypt('Dust')
print(ct)

dc = rsa.decrypt(ct)
print(dc)

exit()


aes = methods._AESMethods(tep)

ct = aes.chacha20.kdf_encrypt('Test', password='pepper', associated_data=b'nonce')
print(ct)

dc = aes.chacha20.kdf_decrypt(ct, password='pepper', associated_data=b'nonce')
print(dc)

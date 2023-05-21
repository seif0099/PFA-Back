from cryptography.fernet import Fernet
def encrypt_string(plaintext):
    key = b'NPLb3uBmXV4Tvr5u-Vg09iwGX_DLkHMozv1Q3NWUDR0=' 
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(plaintext.encode())
    return encrypted_text

def decrypt_string(ciphertext):
    key = b'NPLb3uBmXV4Tvr5u-Vg09iwGX_DLkHMozv1Q3NWUDR0='
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(ciphertext)
    return decrypted_text.decode()
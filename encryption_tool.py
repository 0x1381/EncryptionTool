#0x1381
import base64
import hashlib
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

class EncryptionTool:
    """
    Advanced encryption tool supporting multiple methods:
    - Caesar Cipher
    - Text reversal
    - Base64 encoding
    - MD5 hashing
    - SHA-256 hashing
    - Fernet encryption
    - XOR Cipher
    - AES Encryption
    - DES Encryption
    - ROT13
    - Binary Conversion
    - Hexadecimal Conversion
    """
    
    # Caesar Cipher
    @staticmethod
    def caesar_encrypt(text, shift):
        """Encrypt text using Caesar Cipher with given shift value"""
        result = ""
        for char in text:
            if char.isupper():
                result += chr((ord(char) + shift - 65) % 26 + 65)
            elif char.islower():
                result += chr((ord(char) + shift - 97) % 26 + 97)
            else:
                result += char
        return result

    @staticmethod
    def caesar_decrypt(text, shift):
        """Decrypt Caesar Cipher by shifting back"""
        return EncryptionTool.caesar_encrypt(text, -shift)

    # Text Reversal
    @staticmethod
    def reverse_text(text):
        """Reverse the input text"""
        return text[::-1]

    # Base64 Encoding
    @staticmethod
    def base64_encode(text):
        """Encode text to Base64"""
        return base64.b64encode(text.encode()).decode()

    @staticmethod
    def base64_decode(encoded_text):
        """Decode Base64 to original text"""
        return base64.b64decode(encoded_text.encode()).decode()

    # Hash Functions
    @staticmethod
    def md5_hash(text):
        """Generate MD5 hash of text"""
        return hashlib.md5(text.encode()).hexdigest()

    @staticmethod
    def sha256_hash(text):
        """Generate SHA-256 hash of text"""
        return hashlib.sha256(text.encode()).hexdigest()

    # Fernet Encryption
    @staticmethod
    def fernet_encrypt(text, key=None):
        """Encrypt using Fernet symmetric encryption"""
        if key is None:
            key = Fernet.generate_key()
        fernet = Fernet(key)
        return fernet.encrypt(text.encode()), key

    @staticmethod
    def fernet_decrypt(encrypted_text, key):
        """Decrypt Fernet encrypted text"""
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_text).decode()

    # XOR Cipher
    @staticmethod
    def xor_encrypt(text, key):
        """Basic XOR encryption"""
        return bytes([ord(text[i]) ^ ord(key[i % len(key)]) for i in range(len(text))])

    @staticmethod
    def xor_decrypt(encrypted_data, key):
        """XOR decryption (symmetric operation)"""
        return ''.join([chr(encrypted_data[i] ^ ord(key[i % len(key)])) for i in range(len(encrypted_data))])

    # AES Encryption
    @staticmethod
    def aes_encrypt(text, key=None):
        """Encrypt using AES-256 (CBC mode)"""
        if key is None:
            key = get_random_bytes(32)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_text = pad(text.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded_text)
        return iv + encrypted, key

    @staticmethod
    def aes_decrypt(encrypted_data, key):
        """Decrypt AES encrypted data"""
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        return unpad(decrypted, AES.block_size).decode()

    # DES Encryption
    @staticmethod
    def des_encrypt(text, key=None):
        """Encrypt using DES"""
        if key is None:
            key = get_random_bytes(8)
        iv = get_random_bytes(8)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_text = pad(text.encode(), DES.block_size)
        encrypted = cipher.encrypt(padded_text)
        return iv + encrypted, key

    @staticmethod
    def des_decrypt(encrypted_data, key):
        """Decrypt DES encrypted data"""
        iv = encrypted_data[:8]
        ciphertext = encrypted_data[8:]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        return unpad(decrypted, DES.block_size).decode()

    # ROT13
    @staticmethod
    def rot13(text):
        """ROT13 transformation"""
        return text.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))

    # Binary Conversion
    @staticmethod
    def text_to_binary(text):
        """Convert text to binary representation"""
        return ' '.join(format(ord(i), '08b') for i in text)

    @staticmethod
    def binary_to_text(binary_str):
        """Convert binary string back to text"""
        return ''.join([chr(int(b, 2)) for b in binary_str.split()])

    # Hexadecimal Conversion
    @staticmethod
    def text_to_hex(text):
        """Convert text to hexadecimal"""
        return binascii.hexlify(text.encode()).decode()

    @staticmethod
    def hex_to_text(hex_str):
        """Convert hexadecimal back to text"""
        return binascii.unhexlify(hex_str).decode()

def display_menu():
    """Display the main menu options"""
    print("\n🔐 \033[0;36m Advanced Encryption Tool 🔐\n")
    print("1. Encrypt/Encode/Hash text")
    print("2. Decrypt/Decode text")
    print("3. Exit\n")
    return input("Please choose an option (1-3): ")

def encryption_menu():
    """Display available encryption methods"""
    print("\n🔒\033[32;1m Available Methods:")
    print("1. Caesar Cipher")
    print("2. Reverse Text")
    print("3. Base64 Encoding")
    print("4. MD5 Hash")
    print("5. SHA-256 Hash")
    print("6. Fernet Encryption")
    print("7. XOR Cipher")
    print("8. AES Encryption")
    print("9. DES Encryption")
    print("10. ROT13")
    print("11. Binary Conversion")
    print("12. Hexadecimal Conversion\n")
    return input("\033[0;36m Select method (1-12): ")

def handle_encryption():
    """Handle the encryption process"""
    method = encryption_menu()
    text = input("Enter text to process: ")
    
    try:
        if method == "1":  # Caesar
            shift = int(input("Enter shift value: "))
            result = EncryptionTool.caesar_encrypt(text, shift)
            print(f"\n🔑 Shift: {shift}")
            print(f"🔒 Encrypted: {result}")
            
        elif method == "2":  # Reverse
            result = EncryptionTool.reverse_text(text)
            print(f"\n🔒 Reversed: {result}")
            
        elif method == "3":  # Base64
            result = EncryptionTool.base64_encode(text)
            print(f"\n🔒 Base64: {result}")
            
        elif method == "4":  # MD5
            result = EncryptionTool.md5_hash(text)
            print(f"\n🔒 MD5 Hash: {result}")
            
        elif method == "5":  # SHA-256
            result = EncryptionTool.sha256_hash(text)
            print(f"\n🔒 SHA-256 Hash: {result}")
            
        elif method == "6":  # Fernet
            encrypted, key = EncryptionTool.fernet_encrypt(text)
            print(f"\n🔑 Key: {key.decode()}")
            print(f"🔒 Encrypted: {encrypted.decode()}")
            
        elif method == "7":  # XOR
            key = input("Enter XOR key: ")
            result = EncryptionTool.xor_encrypt(text, key)
            print(f"\n🔑 Key: {key}")
            print(f"🔒 Encrypted (hex): {result.hex()}")
            
        elif method == "8":  # AES
            encrypted, key = EncryptionTool.aes_encrypt(text)
            print(f"\n🔑 Key (hex): {key.hex()}")
            print(f"🔒 Encrypted (base64): {base64.b64encode(encrypted).decode()}")
            
        elif method == "9":  # DES
            encrypted, key = EncryptionTool.des_encrypt(text)
            print(f"\n🔑 Key (hex): {key.hex()}")
            print(f"🔒 Encrypted (base64): {base64.b64encode(encrypted).decode()}")
            
        elif method == "10":  # ROT13
            result = EncryptionTool.rot13(text)
            print(f"\n🔒 ROT13: {result}")
            
        elif method == "11":  # Binary
            result = EncryptionTool.text_to_binary(text)
            print(f"\n🔒 Binary: {result}")
            
        elif method == "12":  # Hex
            result = EncryptionTool.text_to_hex(text)
            print(f"\n🔒 Hexadecimal: {result}")
            
        else:
            print("❌ Invalid method selection!")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

def handle_decryption():
    """Handle the decryption process"""
    method = encryption_menu()
    
    try:
        if method == "1":  # Caesar
            text = input("Enter text to decrypt: ")
            shift = int(input("Enter shift value: "))
            result = EncryptionTool.caesar_decrypt(text, shift)
            print(f"\n🔓 Decrypted: {result}")
            
        elif method == "2":  # Reverse
            text = input("Enter text to reverse back: ")
            result = EncryptionTool.reverse_text(text)
            print(f"\n🔓 Original: {result}")
            
        elif method == "3":  # Base64
            text = input("Enter Base64 to decode: ")
            result = EncryptionTool.base64_decode(text)
            print(f"\n🔓 Decoded: {result}")
            
        elif method in ["4", "5"]:  # Hashes
            print("⚠️ Note: Hash functions are one-way and cannot be decrypted!")
            print("They are used for digital fingerprints. To verify, you can:")
            
            if method == "4":
                sample = input("Enter text to generate MD5 hash: ")
                print(f"🖇️ MD5 Hash: {EncryptionTool.md5_hash(sample)}")
            else:
                sample = input("Enter text to generate SHA-256 hash: ")
                print(f"🖇️ SHA-256 Hash: {EncryptionTool.sha256_hash(sample)}")
            
        elif method == "6":  # Fernet
            text = input("Enter encrypted text: ").encode()
            key = input("Enter Fernet key: ").encode()
            result = EncryptionTool.fernet_decrypt(text, key)
            print(f"\n🔓 Decrypted: {result}")
            
        elif method == "7":  # XOR
            text_hex = input("Enter encrypted data (hex): ")
            key = input("Enter XOR key: ")
            encrypted = bytes.fromhex(text_hex)
            result = EncryptionTool.xor_decrypt(encrypted, key)
            print(f"\n🔓 Decrypted: {result}")
            
        elif method == "8":  # AES
            text_b64 = input("Enter base64 encrypted data: ")
            key_hex = input("Enter AES key (hex): ")
            encrypted = base64.b64decode(text_b64)
            key = bytes.fromhex(key_hex)
            result = EncryptionTool.aes_decrypt(encrypted, key)
            print(f"\n🔓 Decrypted: {result}")
            
        elif method == "9":  # DES
            text_b64 = input("Enter base64 encrypted data: ")
            key_hex = input("Enter DES key (hex): ")
            encrypted = base64.b64decode(text_b64)
            key = bytes.fromhex(key_hex)
            result = EncryptionTool.des_decrypt(encrypted, key)
            print(f"\n🔓 Decrypted: {result}")
            
        elif method == "10":  # ROT13
            text = input("Enter ROT13 text: ")
            result = EncryptionTool.rot13(text)
            print(f"\n🔓 Decrypted: {result}")
            
        elif method == "11":  # Binary
            text = input("Enter binary string (space separated bytes): ")
            result = EncryptionTool.binary_to_text(text)
            print(f"\n🔓 Decrypted: {result}")
            
        elif method == "12":  # Hex
            text = input("Enter hexadecimal string: ")
            result = EncryptionTool.hex_to_text(text)
            print(f"\n🔓 Decrypted: {result}")
            
        else:
            print("❌ Invalid method selection!")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

def main():
    """Main program execution"""
    # Check for required packages
    try:
        from cryptography.fernet import Fernet
        from Crypto.Cipher import AES, DES
    except ImportError:
        print("Installing required packages...")
        import subprocess
        subprocess.run(["pip", "install", "cryptography", "pycryptodome"])
    
    while True:
        choice = display_menu()
        
        if choice == "1":
            handle_encryption()
        elif choice == "2":
            handle_decryption()
        elif choice == "3":
            print("👋 Exiting...")
            break
        else:
            print("❌ Invalid choice!")
            
            
r='\033[1;31m'
g='\033[32;1m' 
y='\033[1;33m'
w='\033[1;37m'

if __name__ == "__main__":
    main()
    
#0x1381
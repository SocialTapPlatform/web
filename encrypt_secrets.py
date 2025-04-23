import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password, salt):
    """Generate an encryption key from a password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data, key):
    """Encrypt data using Fernet symmetric encryption"""
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, key):
    """Decrypt data using Fernet symmetric encryption"""
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()

def encrypt_env_vars(password, env_vars_to_encrypt):
    """Encrypt specific environment variables"""
    # Generate a random salt
    salt = os.urandom(16)
    salt_b64 = base64.b64encode(salt).decode()
    
    # Generate encryption key from password and salt
    key = generate_key(password, salt)
    
    # Store encrypted values
    encrypted_values = {}
    
    for var_name in env_vars_to_encrypt:
        value = os.environ.get(var_name)
        if value:
            encrypted_values[var_name] = encrypt_data(value, key)
    
    return {
        "salt": salt_b64,
        "encrypted": encrypted_values
    }

def create_encrypted_env_file(password, output_file=".env.encrypted"):
    """Create an encrypted environment file"""
    env_vars_to_encrypt = [
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_SECRET",
        "FLASK_SECRET_KEY",
        "ENCRYPTION_KEY"
    ]
    
    result = encrypt_env_vars(password, env_vars_to_encrypt)
    
    with open(output_file, "w") as f:
        f.write(f"SALT={result['salt']}\n\n")
        f.write("# Encrypted environment variables\n")
        for var_name, encrypted_value in result["encrypted"].items():
            f.write(f"{var_name}_ENCRYPTED={encrypted_value}\n")
    
    print(f"Created encrypted environment file: {output_file}")
    print("You can safely commit this file to your repository.")
    print("\nTo use these values, create a decrypt_secrets.py script to decrypt them.")

def main():
    password = input("Enter an encryption password: ")
    create_encrypted_env_file(password)

if __name__ == "__main__":
    main()
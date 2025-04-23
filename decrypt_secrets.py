import os
import base64
from dotenv import load_dotenv
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

def decrypt_data(encrypted_data, key):
    """Decrypt data using Fernet symmetric encryption"""
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()

def load_encrypted_env(password, encrypted_file=".env.encrypted", output_file=".env"):
    """Load and decrypt environment variables from an encrypted file"""
    if not os.path.exists(encrypted_file):
        print(f"Error: {encrypted_file} not found.")
        return False
    
    # Load encrypted values
    with open(encrypted_file, "r") as f:
        lines = f.readlines()
    
    encrypted_vars = {}
    salt_b64 = None
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        if "=" in line:
            key, value = line.split("=", 1)
            if key == "SALT":
                salt_b64 = value
            elif key.endswith("_ENCRYPTED"):
                var_name = key.replace("_ENCRYPTED", "")
                encrypted_vars[var_name] = value
    
    if not salt_b64:
        print("Error: No salt found in encrypted file.")
        return False
    
    # Decode salt
    salt = base64.b64decode(salt_b64)
    
    # Generate key from password and salt
    key = generate_key(password, salt)
    
    # Decrypt values
    decrypted_vars = {}
    for var_name, encrypted_value in encrypted_vars.items():
        try:
            decrypted_value = decrypt_data(encrypted_value, key)
            decrypted_vars[var_name] = decrypted_value
        except Exception as e:
            print(f"Error decrypting {var_name}: {e}")
            return False
    
    # Write decrypted values to .env file
    with open(output_file, "w") as f:
        for var_name, value in decrypted_vars.items():
            f.write(f"{var_name}={value}\n")
    
    print(f"Successfully decrypted environment variables to {output_file}")
    return True

def main():
    password = input("Enter the decryption password: ")
    if load_encrypted_env(password):
        print("You can now run your application with the decrypted environment variables.")

if __name__ == "__main__":
    main()
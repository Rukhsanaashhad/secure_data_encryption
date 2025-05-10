import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# ----------------- Configuration -----------------

DATA_FILE = "secure_data.json"
KEY_FILE = "fernet_key.key"
ADMIN_PASSWORD = "admin123"  # Should be stored encrypted or in env variables

# ----------------- Helper functions -----------------

# Load or create encryption key
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return key

cipher = Fernet(load_or_create_key())

# Load data from JSON
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save data to JSON
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Hash passkey (per user)
def hash_passkey(passkey, username):
    combined = f"{username}:{passkey}"
    return hashlib.sha256(combined.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

# ----------------- User Management -----------------

def register_user(username, passkey):
    data = load_data()
    user_hash = hash_passkey(passkey, username)
    if username in data:
        return False
    data[username] = {
        "passkey_hash": user_hash,
        "entries": {}  # Store encrypted data here
    }
    save_data(data)
    return True

def authenticate_user(username, passkey):
    data = load_data()
    if username not in data:
        return False
    user_hash = hash_passkey(passkey, username)
    return user_hash == data[username]["passkey_hash"]

# ----------------- Data Storage per User -----------------

def store_user_data(username, data_text, passkey):
    data = load_data()
    user = data.get(username)
    if not user:
        return False
    # Create a unique key for this data
    encrypted_text = encrypt_data(data_text)
    # Store encrypted data with a unique ID (e.g., timestamp)
    entry_id = hashlib.sha256(encrypted_text.encode()).hexdigest()
    user["entries"][entry_id] = encrypted_text
    save_data(data)
    return entry_id

def retrieve_user_data(username, entry_id, passkey):
    data = load_data()
    user = data.get(username)
    if not user:
        return None
    encrypted_text = user["entries"].get(entry_id)
    if not encrypted_text:
        return None
    decrypted_text = decrypt_data(encrypted_text)
    return decrypted_text

# ----------------- Streamlit UI -----------------

st.title("🔒 Advanced Secure Data System")

# Session State
if "user" not in st.session_state:
    st.session_state["user"] = None

menu = ["Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Register":
    st.subheader("Register New User")
    username = st.text_input("Username")
    passkey = st.text_input("Create Password", type="password")
    if st.button("Register"):
        if username and passkey:
            success = register_user(username, passkey)
            if success:
                st.success("Registration successful! Log in now.")
            else:
                st.error("Username already exists.")
        else:
            st.error("Please fill all fields.")

elif choice == "Login":
    st.subheader("Login")
    username = st.text_input("Username")
    passkey = st.text_input("Password", type="password")
    if st.button("Login"):
        if authenticate_user(username, passkey):
            st.session_state["user"] = username
            st.success(f"Welcome, {username}!")
        else:
            st.error("Invalid credentials.")

# Logged-in Actions
if st.session_state["user"]:
    user = st.session_state["user"]
    st.sidebar.write(f"Logged in as: **{user}**")
    
    if choice == "Store Data":
        st.subheader("🔐 Store Data")
        data_input = st.text_area("Enter Data to Secure")
        passkey_confirm = st.text_input("Enter your password to confirm", type="password")
        if st.button("Encrypt & Save"):
            if data_input and passkey_confirm:
                if authenticate_user(user, passkey_confirm):
                    entry_id = store_user_data(user, data_input, passkey_confirm)
                    st.success(f"Data stored! Entry ID: {entry_id}")
                else:
                    st.error("Password confirmation failed.")
            else:
                st.error("All fields are required.")

    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Data")
        entry_id_input = st.text_input("Enter Entry ID")
        passkey_confirm = st.text_input("Enter your password to confirm", type="password")
        if st.button("Retrieve Data"):
            if entry_id_input and passkey_confirm:
                if authenticate_user(user, passkey_confirm):
                    data = retrieve_user_data(user, entry_id_input, passkey_confirm)
                    if data:
                        st.success(f"Retrieved Data: {data}")
                    else:
                        st.error("Invalid Entry ID or no such data.")
                else:
                    st.error("Password confirmation failed.")
            else:
                st.error("All fields are required.")

    elif choice == "Logout":
        st.session_state["user"] = None
        st.sidebar.write("Logged out.")

else:
    st.info("Please log in or register to access data storage and retrieval.")

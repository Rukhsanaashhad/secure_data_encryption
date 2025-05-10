import streamlit as st
import hashlib
import json
import os
import re
from cryptography.fernet import Fernet

# ----------------- Configuration -----------------
DATA_FILE = "secure_data.json"
KEY_FILE = "fernet_key.key"

# ----------------- Helper functions -----------------
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

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def hash_passkey(passkey, username):
    combined = f"{username}:{passkey}"
    return hashlib.sha256(combined.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

# User management functions
def register_user(username, passkey):
    data = load_data()
    if username in data:
        return False
    user_hash = hash_passkey(passkey, username)
    data[username] = {
        "passkey_hash": user_hash,
        "entries": {}
    }
    save_data(data)
    return True

def authenticate_user(username, passkey):
    data = load_data()
    if username not in data:
        return False
    return hash_passkey(passkey, username) == data[username]["passkey_hash"]

def store_user_data(username, data_text):
    data = load_data()
    user = data.get(username)
    if not user:
        return False
    encrypted_text = encrypt_data(data_text)
    entry_id = hashlib.sha256(encrypted_text.encode()).hexdigest()
    user["entries"][entry_id] = encrypted_text
    save_data(data)
    return entry_id

def retrieve_user_data(username, entry_id):
    data = load_data()
    user = data.get(username)
    if not user:
        return None
    encrypted_text = user["entries"].get(entry_id)
    if not encrypted_text:
        return None
    return decrypt_data(encrypted_text)

# 1. Password strength check function
def check_password_strength(password):
    criteria = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digits": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    }
    strength_score = sum(criteria.values())
    if strength_score == 5:
        return "Strong"
    elif strength_score >= 3:
        return "Medium"
    else:
        return "Weak"

# ----------------- Streamlit UI -----------------
st.set_page_config(page_title="Secure Data System", page_icon="🔒")
st.title("🔒 Advanced Secure Data System")

# Initialize session state
if "user" not in st.session_state:
    st.session_state["user"] = None

menu = ["Register", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# Handle "Logout" 
if choice == "Logout":
    st.session_state["user"] = None
    st.success("Logged out successfully.")
    st.stop()

# Registration
if choice == "Register":
    st.subheader("Register New User")
    username = st.text_input("Username")
    passkey = st.text_input("Create Password", type="password")
    # Show password strength feedback
    if passkey:
        strength = check_password_strength(passkey)
        st.write(f"Password strength: **{strength}**")
    if st.button("Register"):
        if username and passkey:
            strength = check_password_strength(passkey)
            if strength == "Weak":
                st.error("Password is too weak. Please create a stronger password (at least 8 characters, including uppercase, lowercase, digit, and special character).")
            else:
                success = register_user(username, passkey)
                if success:
                    st.success("Registration successful! Log in now.")
                else:
                    st.error("Username already exists.")
        else:
            st.error("Please fill all fields.")

# Login
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

# Logged-in actions
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
                    entry_id = store_user_data(user, data_input)
                    if entry_id:
                        st.success(f"Data stored! Entry ID: {entry_id}")
                    else:
                        st.error("Failed to store data.")
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
                    data = retrieve_user_data(user, entry_id_input)
                    if data:
                        st.success(f"Retrieved Data: {data}")
                    else:
                        st.error("Invalid Entry ID or no such data.")
                else:
                    st.error("Password confirmation failed.")
            else:
                st.error("All fields are required.")

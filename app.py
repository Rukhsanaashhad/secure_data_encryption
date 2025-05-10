# pip install streamlit sqlalchemy bcrypt cryptography
import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt
from cryptography.fernet import Fernet
import os

# Setup Database
engine = create_engine('sqlite:///secure_data.db')
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

# Models
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password_hash = Column(LargeBinary)
    encryption_key = Column(LargeBinary)

class UserData(Base):
    __tablename__ = 'userdata'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    encrypted_data = Column(LargeBinary)

Base.metadata.create_all(engine)

# Hash password
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Verify password
def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# Generate encryption key
def generate_key():
    return Fernet.generate_key()

# Encrypt/Decrypt data
def encrypt_data(data, key):
    return Fernet(key).encrypt(data.encode())

def decrypt_data(token, key):
    return Fernet(key).decrypt(token).decode()

# Registration
def register():
    st.header("Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if session.query(User).filter_by(username=username).first():
            st.warning("Username exists.")
        else:
            password_hash = hash_password(password)
            key = generate_key()
            user = User(username=username, password_hash=password_hash, encryption_key=key)
            session.add(user)
            session.commit()
            st.success("Registered successfully!")

# Login
def login():
    st.header("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user = session.query(User).filter_by(username=username).first()
        if user and verify_password(password, user.password_hash):
            st.session_state["user_id"] = user.id
            st.session_state["encryption_key"] = user.encryption_key
            st.success("Logged in!")
        else:
            st.error("Invalid Credentials!")

# Secure Data Storage
def save_user_data(data, key, user_id):
    encrypted = encrypt_data(data, key)
    user_data = UserData(user_id=user_id, encrypted_data=encrypted)
    session.add(user_data)
    session.commit()

# Retrieve Data
def get_user_data(user_id, key):
    data_record = session.query(UserData).filter_by(user_id=user_id).order_by(UserData.id.desc()).first()
    if data_record:
        return decrypt_data(data_record.encrypted_data, key)
    return "No data found."

# Main App Logic
def main():
    if "user_id" not in st.session_state:
        choice = st.selectbox("Choose:", ["Login", "Register"])
        if choice == "Register":
            register()
        elif choice == "Login":
            login()
    else:
        user_id = st.session_state["user_id"]
        key = st.session_state["encryption_key"]
        st.title("Secure Data Dashboard")
        data = st.text_area("Enter Data")
        if st.button("Save Data"):
            save_user_data(data, key, user_id)
            st.success("Data encrypted and saved securely.")
        retrieved = get_user_data(user_id, key)
        st.subheader("Your Data")
        st.write(retrieved)

if __name__ == "__main__":
    main()
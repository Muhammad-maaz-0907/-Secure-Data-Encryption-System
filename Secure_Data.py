import streamlit as st
import hashlib
import time
import json
import os 
from cryptography.fernet import Fernet
from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import pbkdf2_hmac

DATA_FILE = "secure_Data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# section login 

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# if data is loaded
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}       

def save_data(data):
    with open(DATA_FILE, "w")as f:
        json.dump(data,f)

def generate_key(passkey):
    key = pbkdf2_hmac("sha256" , passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)  # ✅ ENCODE it so Fernet accepts it

def hash_password(password):
    key = pbkdf2_hmac("sha256", password.encode(), SALT, 100000)
    return urlsafe_b64encode(key).decode()
# cryptography.fernet used

def encrypt_data(data, key):
    chiper = Fernet(generate_key(key))
    return chiper.encrypt(data.encode()).decode()

def decrypt_text(encrypted_data, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_data.encode()).decode()
    except:
        return None
    
store_data = load_data()

# navigation bar (with gradient title)
st.markdown("""
    <h1 style='font-size: 3em; text-align: center; margin-bottom: 1rem;'>
        🛡️ <span style='
    background: linear-gradient(to right, #ff5e62, #ff9966);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: bold;
        '>Secure Data Encryption System</span>
    </h1>
""", unsafe_allow_html=True)

menu = ["Home", "Register", "Login", "Store Data", "Get Data"]
choice = st.sidebar.selectbox("Navigation", menu)


if choice == "Home":
    st.markdown("""
    <h2 style='text-align: center; font-size: 2em;'>
        🔐 <span style='
            background: linear-gradient(to right, #ff512f, #dd2476);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: bold;
        '>Welcome to Secure Data Encryption System</span>
    </h2>
""", unsafe_allow_html=True)
    st.markdown("""
## 🛡️  Secure your Data :

Your privacy matters — and we're here to protect it.

This application allows you to **securely store and retrieve sensitive information** using strong encryption. Powered by modern cryptographic techniques and built with a user-friendly interface, you can confidently:

- 🔐 **Encrypt** your private data with a personal passkey  
- 🔓 **Decrypt** only with the correct credentials  
- 🚫 Automatically **lock access** after multiple failed attempts  
- 💾 Keep your data safe and accessible without relying on external databases  

Whether you're saving passwords, personal notes, or confidential records, this system ensures that your data remains **private, protected, and in your control**.

> 🔒 Stay safe. Stay secure. Encrypt everything.
""")
elif choice == "Register":
    st.subheader("📝 Register new user")
    username = st.text_input(" Username")
    password = st.text_input(" Password",type="password")

    if st.button("Register"):
        if username and password:
            if username in store_data:
                st.warning("⚠️Username already exists")
            else:
                store_data[username] = {
                    "password" : hash_password(password),
                    "data" : []
                }  
                save_data(store_data)
                st.success("✅ Registration successful")
                
        else:
            st.error("both fields are required")

elif choice == "Login":
            st.subheader(" 🔑User Login")

            if time.time() < st.session_state.lockout_time:
                remaining = int(st.session_state.lockout_time - time.time())
                st.error("❌ You are locked out for 60 seconds")
                st.stop()

            username = st.text_input("Username")
            password = st.text_input("Password",type="password")

            if st.button("Login"):
                if username in store_data and store_data[username]["password"] == hash_password(password):
                        st.session_state.authenticated_user = username
                        st.session_state.failed_attempts = 0
                        st.success(f"✅ Welome,{username}!")
                else:
                        st.session_state.failed_attempts += 1
                        remaining = 3 - st.session_state.failed_attempts
                        st.error(f"❌ Incorrect password ⚠️Attempts remaining: {remaining}")
                    
                        if st.session_state.failed_attempts >= 3:
                            st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                            st.error(f"🛑 You are locked out for {LOCKOUT_DURATION} seconds")
                            st.stop()

# data stored section
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("📝 Please login first")
        st.stop()  # Prevents the rest from executing
    else:
        st.subheader("🗄️ Store Encrypted Data")
        data = st.text_area("Enter Data To Encrypt")
        passkey = st.text_input("Encryption Key (passkey)", type="password")

        if st.button("Encrypt And Store"):
            if data and passkey:
                encrypted_data = encrypt_data(data, passkey)
                store_data[st.session_state.authenticated_user]["data"].append(encrypted_data)
                save_data(store_data)
                st.success("✅ Data stored successfully")
            else:
                st.error("❌ Both fields are required")

elif choice == "Get Data":
    if not st.session_state.authenticated_user:  # ← Proper check for unauthenticated users
        st.warning("🔓 Please login first")
        st.stop()  # ← Important: Stop execution here
    
    st.subheader("🗄️ Get Decrypted Data")
    
    # Safer data retrieval with nested defaults
    user_data = store_data.get(st.session_state.authenticated_user, {}).get("data", [])
    
    if not user_data:
        st.info("📭 No encrypted data found for your account")
    else:
        st.write("🔒 Your Encrypted Entries:")
        for i, item in enumerate(user_data, 1):
            st.code(f"Entry {i}:\n{item}", language="text")
        
        st.markdown("---")
        encrypt_data = st.text_area("📝 Paste encrypted data to decrypt")
        passkey = st.text_input("🔑 Encryption Key (passkey)", type="password")
        
        if st.button("🔓 Decrypt"):
            if not encrypt_data or not passkey:
                st.error("❌ Both fields are required")
            else:
                result = decrypt_text(encrypt_data, passkey)
                if result:
                    st.success("✅ Decryption Successful")
                    st.text_area("Decrypted Data", value=result, height=200)
                else:
                    st.error("❌ Decryption failed - Wrong key or corrupted data")
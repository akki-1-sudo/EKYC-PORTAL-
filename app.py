import os
import logging
import streamlit as st
from preprocess import read_image, extract_id_card, save_image
from ocr_engine import extract_text
from postprocess import extract_information, extract_information1
from face_verification import detect_and_extract_face, deepface_face_comparison, get_face_embeddings
from sql_connection import insert_records, fetch_records, check_duplicacy, insert_records_aadhar, fetch_records_aadhar, check_duplicacy_aadhar
import toml
import hashlib
from random import randint
from twilio.rest import Client

# Twilio configuration (replace with your Twilio credentials)
TWILIO_ACCOUNT_SID = "your_account_sid"
TWILIO_AUTH_TOKEN = "your_auth_token"
TWILIO_PHONE_NUMBER = "your_twilio_phone_number"

logging_str = "[%(asctime)s: %(levelname)s: %(module)s]: %(message)s"
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(filename=os.path.join(log_dir, "ekyc_logs.log"), level=logging.INFO, format=logging_str, filemode="a")

config = toml.load("config.toml")
db_config = config.get("database", {})

db_user = db_config.get("user")
db_password = db_config.get("password")

# Hashing function for passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Dummy user credentials for demonstration
USER_CREDENTIALS = {
    "admin": hash_password("admin123"),
    "user": hash_password("user123")
}

# Function to send OTP
def send_otp(contact_number):
    if not contact_number.startswith("+"):
        raise ValueError("Phone number must include the country code and start with '+'.")
    otp = randint(100000, 999999)  # Generate a 6-digit OTP
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    try:
        message = client.messages.create(
            body=f"Your OTP for registration is {otp}",
            from_=TWILIO_PHONE_NUMBER,
            to=contact_number
        )
        logging.info(f"OTP sent to {contact_number}")
        return otp
    except Exception as e:
        logging.error(f"Failed to send OTP: {e}")
        st.error(f"Failed to send OTP. If you are using a trial account, ensure the number is verified in Twilio.")
        return None

# Registration page with OTP verification
def register_page():
    st.title("Register New User")
    new_username = st.text_input("Enter a new username")
    new_password = st.text_input("Enter a new password", type="password")
    confirm_password = st.text_input("Confirm your password", type="password")
    contact_number = st.text_input("Enter your contact number (with country code, e.g., +1234567890)")
    otp_sent = st.button("Send OTP")
    if otp_sent:
        if contact_number:
            try:
                otp = send_otp(contact_number)
                if otp:
                    st.session_state["otp"] = otp
                    st.session_state["contact_number"] = contact_number
                    st.success("OTP sent to your contact number.")
                else:
                    st.warning("OTP could not be sent. Please ensure the number is valid or verified in Twilio.")
            except ValueError as ve:
                st.error(str(ve))
        else:
            st.error("Please enter a valid contact number.")

    otp_input = st.text_input("Enter the OTP sent to your contact number")
    if st.button("Register"):
        if new_username in USER_CREDENTIALS:
            st.error("Username already exists. Please choose a different username.")
        elif new_password != confirm_password:
            st.error("Passwords do not match. Please try again.")
        elif "otp" not in st.session_state or otp_input != str(st.session_state.get("otp", "")):
            st.error("Invalid OTP. Please try again.")
        else:
            USER_CREDENTIALS[new_username] = hash_password(new_password)
            st.success("Registration successful! You can now log in.")
            logging.info(f"New user registered: {new_username}")
            if "otp" in st.session_state:
                del st.session_state["otp"]  # Clear OTP after successful registration
            if "contact_number" in st.session_state:
                del st.session_state["contact_number"]

# Login page
def login_page():
    st.title("E-KYC Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        hashed_password = hash_password(password)
        if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == hashed_password:
            st.success("Login successful!")
            st.session_state["logged_in"] = True
        else:
            st.error("Invalid username or password.")
    if st.button("Register"):
        st.session_state["register"] = True

# Set wider page layout
def wider_page():
    max_width_str = "max-width: 1200px;"
    st.markdown(
        f"""
        <style>
            .reportview-container .main .block-container{{ {max_width_str} }}
        </style>
        """,
        unsafe_allow_html=True,
    )
    logging.info("Page layout set to wider configuration.")

# Main function
def main():
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False
    if "register" not in st.session_state:
        st.session_state["register"] = False

    if st.session_state["register"]:
        register_page()
    elif not st.session_state["logged_in"]:
        login_page()
    else:
        wider_page()
        option = st.sidebar.selectbox("Select ID Card Type", ("PAN", "AADHAR"))
        st.title(f"Registration Using {option} Card")
        image_file = st.file_uploader("Upload ID Card")
        if image_file is not None:
            face_image_file = st.file_uploader("Upload Face Image")
            st.write("Processing your files...")

if __name__ == "__main__":
    main()
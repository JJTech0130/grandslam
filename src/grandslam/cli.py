# Try and get the username and password from environment variables
import os
from .gsa import authenticate, Anisette

def main():
    username = os.environ.get("APPLE_ID")
    password = os.environ.get("APPLE_ID_PASSWORD")
    # If they're not set, prompt the user
    if username is None:
        username = input("Apple ID: ")
    if password is None:
        import getpass

        password = getpass.getpass("Password: ")

    authenticate(username, password, Anisette())
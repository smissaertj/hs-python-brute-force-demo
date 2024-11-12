# Login and Password Finder

This Python script attempts to log into a server by brute-forcing both the login and password. It utilizes an exception-based vulnerability to find the correct credentials incrementally.

## How It Works

1. **Login Discovery**: The script iterates through a list of logins to find a valid one. If the server response indicates a password error or exception, the login is considered correct.
2. **Password Discovery**: Once the login is found, the script uses an incremental character-based approach to build the password. It takes advantage of an exception response from the server to confirm each character in the password until the full password is identified.

## Prerequisites

- Python 3.x
- A login dictionary file (default: `logins.txt`) with each login on a new line.

## Usage

1. Ensure you have a `logins.txt` file in the same directory, containing potential logins.
2. Run the script from the command line with the following command:

   ```bash
   python hack.py <host> <port>
Replace <host> and <port> with the target server's IP and port.

3. The script will output the found credentials in JSON format if successful.

## Logging

The script uses logging to provide information about its progress, including:

- Connection issues
- Login and password discovery steps
- Errors encountered

## Example
```bash
python3 hack.py 127.0.0.1 9090
{"login": "found_login", "password": "found_password"}
```

### Disclaimer
This script is intended for educational purposes only. Ensure you have permission before testing against any server.
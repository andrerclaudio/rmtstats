#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import subprocess
import sys
import paramiko

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_target_is_online(ip: str, timeout: int = 3, retries: int = 3) -> bool:
    """
    Check if the target is online by pinging it.

    Args:
        ip (str): IP address of the target machine.
        timeout (int, optional): Timeout in seconds. Defaults to 3.
        retries (int, optional): Number of retries before considering the target as offline. Defaults to 3.

    Returns:
        bool: True if the target is online, False otherwise.
    """

    logging.info(f'Checking if {ip} is online ...')

    # Initialise the returncode to False
    returncode = False

    # Linux-specific ping command
    cmd = ['ping', '-c', '1', '-w', str(timeout), ip]

    for i in range(1, retries + 1):
        logging.debug(f"Ping attempt {i} of {retries} to {ip}")

        try:
            with open('/dev/null', 'w') as devnull:
                returncode = subprocess.call(cmd, stdout=devnull, stderr=devnull) == 0

            if returncode:
                logging.info(f"Target {ip} is online on attempt {i}.")
                break

        except OSError as e:
            logging.error(f"An OS error occurred: {e}")
            return False

    if not returncode:
        logging.info(f"Couldn't reach target {ip} after {retries} attempts.")
        return False

    return True


def fetch_uname_info(ip: str, username: str, key_file: str = None) -> str:
    """
    Fetch the uname -a information from the target machine via SSH.

    Args:
        ip (str): IP address of the target machine.
        username (str): SSH username.
        key_file (str, optional): Path to the private key file. Defaults to None, using the default SSH key.

    Returns:
        str: The output of the uname -a command.
    """

    logging.info(f"Connecting to {ip} to retrieve uname information.")

    # Initialize the  client to None
    client = None

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Load SSH key from the keyring or a specified key file
        if key_file:
            private_key = paramiko.RSAKey.from_private_key_file(key_file)
        else:
            private_key = None  # Use the default key from SSH agent

        client.connect(ip, username=username, pkey=private_key)

        stdin, stdout, stderr = client.exec_command("uname -a")

        # Read the command output
        uname_output = stdout.read().decode()
        error_output = stderr.read().decode()

        if error_output:
            logging.error(f"Error fetching uname output: {error_output}")
            return None

        logging.info(f"Successfully fetched uname output from {ip}.")
        return uname_output

    except paramiko.SSHException as e:
        logging.error(f"SSH connection failed: {e}")
        return None

    finally:
        if client:
            # Don't forget to close the connection
            logging.debug(f'Closing SSH connection to {ip}.')
            client.close()


def main():
    """
    Main function that runs the script.
    """

    try:
        logging.info("rmtstats is running")
        
        # TODO: Add your IP address below, or pass it as a parameter in the command line when running from crontab
        if check_target_is_online(ip='100.96.1.50'):

            uname_info = fetch_uname_info(ip='100.96.1.50', username='root')

            if uname_info:
                print(uname_info)
            else:
                logging.error("Failed to retrieve uname information.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

    logging.info("rmtstats finished successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()

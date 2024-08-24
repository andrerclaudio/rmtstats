#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import subprocess
import os
import sys
import paramiko
from time import sleep

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


def fetch_top_info(ip: str, username: str, key_file: str = None) -> str:
    """
    Fetch the top information from a target machine via SSH.

    This function connects to a remote machine using SSH, executes the `top` command 
    in batch mode, retrieves the output, processes it to extract the header and 
    the top CPU-intensive processes, and returns this information as a formatted string.

    Args:
        ip (str): The IP address of the target machine.
        username (str): The username to use for the SSH connection.
        key_file (str, optional): The path to the private key file for SSH authentication. 
                                  If not provided, it will try to find the SSH keys in 
                                  the deafult folders.

    Returns:
        str: The formatted string containing the top command's header and the top CPU-intensive 
             processes. Returns `None` if there was an error during the connection or command execution.
    """

    TOP_PROCESS_LINES = 11  # Number of lines to retrieve from the top command
    TOP_HEADER_LINES = 7  # Header lenght of Top command

    logging.info(f"Connecting to {ip} to retrieve top information.")

    # Initialize the client to None
    client = None
    # Initialize the result to None
    result = None

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if key_file:
            private_key = paramiko.RSAKey.from_private_key_file(key_file)
        else:
            private_key = None

        client.connect(ip, username=username, pkey=private_key)

        # Run top command with batch mode
        command = "top -b -n 1"  # Use `-b` for batch mode and `-n 1` to limit to one iteration

        stdin, stdout, stderr = client.exec_command(command)

        # Read the command output
        top_output = stdout.read().decode()
        error_output = stderr.read().decode()

        if error_output:
            logging.error(f"Error fetching top output: {error_output}")

        logging.debug(f"Successfully fetched top output from {ip}.")

        # Process the output to get the TOP_PROCESS_LINES number of lines and most CPU-intensive processes
        lines = top_output.splitlines()        
        # Capture the top command header output
        top_header = "\n".join(lines[:TOP_HEADER_LINES])        
        # Get the CPU-intensive processes (after the header lines)
        process_lines = [line for line in lines[TOP_PROCESS_LINES:] if line and not line.startswith('top')]
        # Sort by CPU usage if needed (assuming CPU usage is in the 9th column)
        process_lines.sort(key=lambda x: float(x.split()[8]), reverse=True)
        # Join sorted lines to get the top CPU-intensive processes
        cpu_intense_processes = "\n".join(process_lines[:TOP_PROCESS_LINES])

        result = f"{top_header}\n\nTop CPU-intensive processes (by %CPU):\n{cpu_intense_processes}\n\n"

    except paramiko.SSHException as e:
        logging.error(f"SSH connection failed: {e}")

    finally:
        if client:
            # Don't forget to close the connection
            logging.info(f'Closing SSH connection to {ip}.')
            client.close()

        # Return the result (None if there was an error)
        return result


def main(ip: str, username: str) -> None:
    """
    Continuously monitor a remote machine's CPU usage via SSH and display the results.

    This function runs an infinite loop that checks if a target machine is online. 
    If the target is online, it fetches the `top` command output, displaying the 
    system's current state and the most CPU-intensive processes. The screen is 
    cleared before each new display. The function handles interruptions gracefully 
    and logs significant events.

    Args:
        ip (str): The IP address of the target machine to monitor.
        username (str): The username to use for the SSH connection.

    Raises:
        KeyboardInterrupt: If the script is interrupted by the user.
        Exception: If an unexpected error occurs during execution.

    Returns:
        None
    """

    try:
        logging.info("rmtstats is running")
        
        while True:

            # TODO: Add your IP address below, or pass it as a parameter in the command line when running from crontab
            if check_target_is_online(ip=ip):

                info = fetch_top_info(ip=ip, username=username)                

                if info:
                    # Clear the screen and print the new information
                    os.system('clear')
                    print(info)
                else:
                    logging.error("Failed to retrieve uname information.")

                logging.info('Target available, proceeding to next iteration.')
                #  Wait one second before acquiring the target again
                sleep(1)

            else:
                logging.info('Target unavailable, retrying in 2 seconds.')
                # Wait two seconds before retrying
                sleep(2)

    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
        sys.exit(0)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

    logging.info("rmtstats finished successfully.")
    sys.exit(0)


if __name__ == "__main__":
    """
    Command line arguments allow the script to be invoked from crontab on a specific IP address/username combination.
    """
    parser = argparse.ArgumentParser(description="Remote stats monitoring script.")
    parser.add_argument('--ip', required=True, help="[String] IP address of the target.")
    parser.add_argument('--user', required=True, help="[String] Username for authentication.")

    args = parser.parse_args()

    if not args.ip or not args.user:
        parser.error("Both --ip and --user are required.")
    
    main(args.ip, args.user)

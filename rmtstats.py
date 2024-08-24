#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import subprocess
import os
import sys
import paramiko
from time import sleep
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout
from PyQt5.QtCore import Qt, QTimer
import threading

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class BoxedLabel(QWidget):
    """

    """
    
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.label = QLabel(self)
        self.label.setStyleSheet("""
            border: 2px solid black;
            padding: 10px;
            background-color: black;
            color: white;
            qproperty-alignment: 'AlignLeft|AlignTop';  /* Align text to the left and top */
        """)
        self.label.setTextFormat(Qt.RichText)  # Set text format to HTML

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        self.setLayout(layout)

        self.setWindowTitle('--- Remote Stats ---')
        self.resize(480, 272)  # Adjust size as needed
        self.show()

    def update_text(self, text):
        # Use HTML to format the text
        formatted_text = f"<pre>{text}</pre>"  # Use <pre> tag to preserve whitespace and line breaks
        self.label.setText(formatted_text)


class FetchRemoteStats(threading.Thread):
    """

    """

    def __init__(self, ip: str, user: str) -> None:

        threading.Thread.__init__(self)
        
        self.ip = ip
        self.username = user
        self.__info = 'The screen will be update soon!'
        self.__lock = True
        self.thread = threading.Thread()
        self.thread.name = 'RmstStats'
        self.start()

    def run(self):
        """

        """

        try:

            logging.info('Start fetching ...')

            while self.__lock:

                if check_target_is_online(ip=self.ip):

                    logging.info('Target available, proceeding to next iteration.')
                    info = fetch_top_info(ip=self.ip, username=self.username)                

                    if info:
                        self.__info = info
                    else:
                        self.__info = 'Failed to retrieve information.'
                        logging.error(self.__info)
                    
                    #  Wait one second before acquiring the target again
                    sleep(1)

                else:
                    self.__info = 'Target unavailable, retrying ...'
                    logging.info(self.__info)
                    # Wait two seconds before retrying
                    sleep(2)

            logging.info('Stop fetching ...')

        except threading.ThreadError as e:
            logging.error(f"An error occurred: {e}")
            sys.exit(1)

    def get(self) -> str:
        """

        """
        return self.__info

    def unlock(self) -> None:
        """

        """
        self.__lock = False



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

    """

    try:
        logging.info("rmtstats is running")

        stats = FetchRemoteStats(ip=ip, user=username)
        app = QApplication(sys.argv)
        box = BoxedLabel()
        
        # Update every 1 second
        timer = QTimer()
        timer.timeout.connect(lambda: box.update_text(stats.get()))
        timer.start(1000)

        app.exec_()
        stats.unlock()

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

    logging.info("rmtstats finished successfully.")
    sys.exit(0)


if __name__ == "__main__":
    """

    """
    parser = argparse.ArgumentParser(description="Remote stats monitoring script.")
    parser.add_argument('--ip', required=True, help="[String] IP address of the target.")
    parser.add_argument('--user', required=True, help="[String] Username for authentication.")
 
    args = parser.parse_args()
 
    if not args.ip or not args.user:
        parser.error("Both --ip and --user are required.")
    
    main(args.ip, args.user)
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import subprocess
import os
import sys
import paramiko
from time import sleep
import threading
import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib, Gdk

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class BoxedLabel(Gtk.Window):
    """
    A GTK window to display remote statistics.
    """

    def __init__(self):
        super().__init__(title="--- Remote Stats ---")
        self.set_default_size(480, 183)  # Set the window size to 480x183

        # Create a label with custom formatting
        self.label = Gtk.Label()
        self.label.set_xalign(0)  # Align text to the left
        self.label.set_yalign(0)  # Align text to the top
        self.label.set_justify(Gtk.Justification.LEFT)
        self.label.set_line_wrap(True)
        self.label.set_name("label")  # Assign a name to the label for CSS

        # Create a container to hold the label
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.box.pack_start(self.label, True, True, 10)
        self.add(self.box)
        self.set_name("window")  # Assign a name to the window for CSS

        # Load and apply the CSS
        self.load_css()

        # Show all components
        self.show_all()
        self.fullscreen()  # Make the window full screen

    def load_css(self):
        """
        Load and apply CSS style from a file.
        """
        css_provider = Gtk.CssProvider()
        css_file = os.path.join(os.path.dirname(__file__), "style.css")
        if not os.path.exists(css_file):
            logging.error(f"CSS file not found: {css_file}")
            sys.exit(1)

        css_provider.load_from_path(css_file)
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(),
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )
        logging.info("CSS loaded and applied")

    def update_text(self, text):
        # Update the label text
        formatted_text = f"<span foreground='white' background='black'><tt>{GLib.markup_escape_text(text)}</tt></span>"
        self.label.set_markup(formatted_text)


class FetchRemoteStats(threading.Thread):
    """
    A thread that fetches remote statistics from a specified IP address.

    This class inherits from `threading.Thread` and runs in a separate thread to
    periodically fetch information from a remote server. It updates the stored
    information and handles errors during the fetching process.

    Attributes:
        ip (str): The IP address of the remote server to fetch information from.
        user (str): The username for authentication to the remote server.
        password (str): The password for authentication to the remote server.
        __info (str): The most recent information fetched from the remote server.
        __lock (bool): A flag to control the fetching loop.
    """

    def __init__(self, ip: str, user: str, password: str) -> None:
        """
        Initialize the FetchRemoteStats thread.

        Args:
            ip (str): The IP address of the remote server.
            user (str): The username for authentication.
        """
        super().__init__(name="RmstStats")

        self.ip = ip
        self.username = user
        self.password = password
        self.__info = "The screen will update soon!"
        self.__lock = True

        # Start the thread
        self.start()

    def run(self) -> None:
        """
        The method that runs in the thread. Continuously fetches information from the remote server
        as long as the __lock attribute is True. Logs status updates and handles errors.
        """
        try:
            logging.info("Start fetching ...")

            while self.__lock:

                if check_target_is_online(ip=self.ip):
                    logging.info("Target available, proceeding to fetch information.")
                    info = fetch_top_info(
                        ip=self.ip, username=self.username, password=self.password
                    )

                    if info:
                        self.__info = info
                    else:
                        self.__info = "Failed to retrieve information."
                        logging.error(self.__info)

                    # Wait one second before the next fetch attempt
                    sleep(1)

                else:
                    self.__info = "Target unavailable, retrying ..."
                    logging.info(self.__info)
                    # Wait two seconds before retrying
                    sleep(2)

            logging.info("Stop fetching ...")

        except threading.ThreadError as e:
            logging.error(f"An error occurred: {e}")
            sys.exit(1)

    def get(self) -> str:
        """
        Retrieve the most recent information fetched.

        Returns:
            str: The most recent information fetched from the remote server.
        """
        return self.__info

    def unlock(self) -> None:
        """
        Stop the fetching loop by setting the __lock attribute to False.
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

    logging.info(f"Checking if {ip} is online ...")

    # Initialise the returncode to False
    returncode = False

    # Linux-specific ping command
    cmd = ["ping", "-c", "1", "-w", str(timeout), ip]

    for i in range(1, retries + 1):
        logging.debug(f"Ping attempt {i} of {retries} to {ip}")

        try:
            with open("/dev/null", "w") as devnull:
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
            logging.debug(f"Closing SSH connection to {ip}.")
            client.close()


def fetch_top_info(ip: str, username: str, password: str) -> str:
    """
    Fetch the top information from a target machine via SSH.

    This function connects to a remote machine using SSH, executes the `top` command
    in batch mode, retrieves the output, processes it to extract the header and
    the top CPU-intensive processes, and returns this information as a formatted string.

    Args:
        ip (str): The IP address of the target machine.
        username (str): The username to use for the SSH connection.
        password (str): The password to use for the SSH connection.

    Returns:
        str: The formatted string containing the top command's header and the top CPU-intensive
             processes. Returns `None` if there was an error during the connection or command execution.
    """

    TOP_PROCESS_LINES = 11  # Number of lines to retrieve from the top command
    TOP_HEADER_LINES = 7  # Header length of Top command

    logging.info(f"Connecting to {ip} to retrieve top information.")

    client = None
    result = None

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect using the username and password
        client.connect(ip, username=username, password=password)

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
        top_header = "\n".join(lines[:TOP_HEADER_LINES])
        process_lines = [
            line
            for line in lines[TOP_PROCESS_LINES:]
            if line and not line.startswith("top")
        ]
        process_lines.sort(key=lambda x: float(x.split()[8]), reverse=True)
        cpu_intense_processes = "\n".join(process_lines[:TOP_PROCESS_LINES])

        result = f"{top_header}\n\nTop CPU-intensive processes (by %CPU):\n{cpu_intense_processes}\n\n"

    except paramiko.SSHException as e:
        logging.error(f"SSH connection failed: {e}")

    finally:
        if client:
            logging.info(f"Closing SSH connection to {ip}.")
            client.close()

        return result


def on_activate(application) -> None:
    """
    Signal handler for the 'activate' signal of the Gtk.Application.
    Initializes and shows the BoxedLabel window.
    """
    global window  # Declare window as global to be accessible in update_label
    window = BoxedLabel()
    window.set_application(application)
    window.present()


def update_label() -> bool:
    """
    Signal handler for the GLib timeout signal. Updates the text of the label window
    if it is open.

    Returns: True if the loop should continue, False to exit.
    """
    global stats
    if window:
        # Update the text of the window if it is open
        window.update_text(stats.get())
    return True  # Continue calling this function


def main(ip: str, username: str, password: str) -> None:
    """
    Main entry point for the application.

    Initializes the FetchRemoteStats thread to fetch remote statistics
    and sets up a Gtk application to display the information. The application
    updates the displayed information every second.

    Args:
        ip (str): The IP address of the remote server to fetch information from.
        username (str): The username for authentication to the remote server.
        password (str): The password for authentication to the remote server.

    Exits:
        sys.exit(0) if the application finishes successfully.
        sys.exit(1) if an error occurs.
    """

    global stats
    global window

    try:
        logging.info("rmtstats is running")

        # Initialize the FetchRemoteStats thread
        stats = FetchRemoteStats(ip=ip, user=username, password=password)
        # Create the GTK application
        app = Gtk.Application()
        # Connect the activate signal to the handler
        app.connect("activate", on_activate)
        # Create a GLib timeout to update the label every second
        GLib.timeout_add_seconds(1, update_label)
        # Run the GTK application
        app.run(None)
        # Stop the FetchRemoteStats thread after the application quits
        stats.unlock()

    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
        sys.exit(1)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

    logging.info("rmtstats finished successfully.")
    sys.exit(0)


if __name__ == "__main__":
    """
    Entry point for the script when executed directly.

    Parses command-line arguments for the IP address, username, and password,
    validates the arguments, and calls the main function to start
    the remote stats monitoring application.

    Command-line arguments:
        --ip (str): The IP address of the target server.
        --user (str): The username for authentication.
        --password (str): The password for authentication.

    Exits:
        sys.exit(1) if required arguments are missing or invalid.
    """
    parser = argparse.ArgumentParser(description="Remote stats monitoring script.")

    # Define command-line arguments
    parser.add_argument("--ip", required=True, help="IP address of the target server.")
    parser.add_argument("--user", required=True, help="Username for authentication.")
    parser.add_argument(
        "--password", required=True, help="Password for authentication."
    )

    # Parse arguments
    args = parser.parse_args()

    # Check if required arguments are present
    if not args.ip or not args.user or not args.password:
        parser.error("Both --ip, --user, and --password are required.")

    # Call the main function with parsed arguments
    main(args.ip, args.user, args.password)

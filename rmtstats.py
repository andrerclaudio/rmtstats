#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib

import argparse
from functools import partial
import logging
import subprocess
import sys
import paramiko
from time import sleep
import threading
import signal
import psutil
import socket

# Configure logging
logging.basicConfig(
    level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s"
)


class TopCommandError(Exception):
    """Exception raised for errors during the execution of the `top` command."""

    def __init__(self, message: str):
        super().__init__(message)


class BoxedLabel(Gtk.Window):
    """
    A GTK window to display remote statistics in a styled label.
    The window is customized with CSS and dynamically updates the label's content.
    """

    def __init__(self, app):
        """
        Initialize the BoxedLabel window.

        Args:
            app (Gtk.Application): The GTK application instance, used to quit the app when the window is closed.
        """
        super().__init__(title="--- Remote Stats ---")

        # Store the reference to the application for later use (quitting the app)
        self.app = app

        # Connect the "close-request" signal to handle window close events
        self.connect("close-request", self.on_close)

        # Create and configure the label to display the remote statistics
        self.label = Gtk.Label()
        self.label.set_xalign(0)  # Align text to the left
        self.label.set_yalign(0)  # Align text to the top
        self.label.set_wrap(True)  # Enable line wrapping for long text
        self.set_child(self.label)

        # Dynamic CSS string for window and label appearance
        self.css = """
        window {
            background-color: black;
        }

        label {
            color: white;
            font-size: 10px;
        }
        """

        # Load and apply the defined CSS
        self.load_css()
        # Remove title bar
        self.set_decorated(False)
        # Make the window full-screen
        self.fullscreen()

    def load_css(self):
        """
        Load CSS data and apply it to the window.
        """
        css_provider = Gtk.CssProvider()
        css_provider.load_from_data(
            self.css, -1
        )  # Pass CSS data and length (-1 for null-terminated)
        display = self.get_display()  # Get the display from the current window
        Gtk.StyleContext.add_provider_for_display(
            display,
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )
        logging.info("CSS loaded and applied successfully.")

    def update_text(self, text):
        """
        Update the label text with formatted content.
        Args:
            text (str): The text to display in the label. It will be formatted and safely escaped for markup.
        """
        formatted_text = f"<span foreground='white' background='black'><tt>{GLib.markup_escape_text(text)}</tt></span>"
        GLib.idle_add(self.label.set_markup, formatted_text)

    def on_close(self, widget) -> bool:
        """
        Handle the window close event and perform any necessary cleanup before exiting.

        Args:
            widget (Gtk.Widget): The widget triggering the event.

        Returns:
            bool: Return False to allow the window to close.
        """
        logging.info("Performing cleanup before exiting the application.")
        self.app.quit()  # Quit the GTK application
        return False  # Returning False allows the window to close


class CheckStatus(object):
    """
    A class to check the status of a network interface and ping a target machine.

    Attributes:
        ip (str): The IP address to ping.
        interface_name (str): The name of the network interface to check. Defaults to 'tun0'.
    """

    def __init__(self, ip: str, interface_name: str = "tun0") -> None:
        """
        Initialize the CheckStatus object.

        Args:
            ip (str): The IP address to check for connectivity.
            interface_name (str, optional): The name of the network interface to check. Defaults to 'tun0'.
        """
        self.ip = ip
        self.interface_name = interface_name

    def interface(self) -> bool:
        """
        Check the status of a network interface.

        This method verifies if the specified network interface is up and has an assigned IP address.

        Returns:
            bool: True if the interface is up and has an IP address assigned, False otherwise.
        """
        try:
            # Get all network interfaces and their addresses
            addrs = psutil.net_if_addrs()

            # Check if the interface exists
            if self.interface_name not in addrs:
                logging.debug(f"Interface {self.interface_name} not found.")
                return False

            # Get the addresses for the interface
            interface_addrs = addrs[self.interface_name]

            # Check for assigned IP address (IPv4)
            ip_assigned = False
            for addr in interface_addrs:
                if addr.family == socket.AF_INET:
                    logging.debug(
                        f"Interface {self.interface_name} has IP address: {addr.address}"
                    )
                    ip_assigned = True

            # If no IP is assigned, return False
            if not ip_assigned:
                logging.debug(
                    f"Interface {self.interface_name} does not have an IP address assigned."
                )
                return False

            # Check if the interface is up
            if psutil.net_if_stats()[self.interface_name].isup:
                logging.debug(f"Interface {self.interface_name} is up.")
                return True
            else:
                logging.debug(f"Interface {self.interface_name} is down.")
                return False

        # Handle key errors from the psutil library
        except KeyError as e:
            logging.error(f"KeyError occurred: {e}")
            return False
        # Handle general psutil errors
        except psutil.Error as e:
            logging.error(f"psutil.Error occurred: {e}")
            return False
        # Catch any other unexpected errors
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            return False

    def target(self, timeout: int = 3, retries: int = 3) -> bool:
        """
        Check if the target machine is online by sending a ping request.

        This method attempts to ping the target machine up to the specified number of retries.
        It returns True if the target responds within the timeout, and False otherwise.

        Args:
            timeout (int, optional): Timeout in seconds for each ping attempt. Defaults to 3 seconds.
            retries (int, optional): The number of retries to attempt before considering the target offline. Defaults to 3.

        Returns:
            bool: True if the target responds to ping, False if it does not after the retries.
        """
        logging.debug(f"Checking if {self.ip} is online...")

        # Default return value indicating the target is offline
        returncode = False

        # Linux-specific ping command with a single ping (-c 1) and a timeout (-w timeout)
        cmd = ["ping", "-c", "1", "-w", str(timeout), self.ip]

        # Attempt to ping the target machine up to the specified number of retries
        for i in range(1, retries + 1):
            logging.debug(f"Ping attempt {i} of {retries} to {self.ip}")

            try:
                # Suppress the output of the ping command by redirecting it to /dev/null
                with open("/dev/null", "w") as devnull:
                    returncode = (
                        subprocess.call(cmd, stdout=devnull, stderr=devnull) == 0
                    )

                # If the ping is successful, stop retrying
                if returncode:
                    logging.debug(f"Target {self.ip} is online on attempt {i}.")
                    break

            # Handle OS-level errors
            except OSError as e:
                logging.error(f"An OS error occurred while pinging: {e}")
                return False

        # Log and return False if the target did not respond after all retries
        if not returncode:
            logging.info(f"Couldn't reach target {self.ip} after {retries} attempts.")
            return False

        return True


class FetchRemoteStats(threading.Thread):
    """
    A thread that fetches remote statistics from a specified IP address.

    This class runs in a separate thread and periodically retrieves information
    from a remote server. It updates the stored information and handles errors
    during the fetching process.

    Attributes:
        ip (str): The IP address of the remote server.
        username (str): The username for SSH authentication to the remote server.
        password (str): The password for SSH authentication to the remote server.
        interface_name (str): The network interface to check before fetching stats.
        __info (str): The most recent information fetched from the remote server.
        __lock (bool): A flag to control the fetching loop (True to keep running).
    """

    def __init__(
        self, ip: str, user: str, password: str, interface_name: str = "tun0"
    ) -> None:
        """
        Initialize the FetchRemoteStats thread.

        Args:
            ip (str): The IP address of the remote server.
            user (str): The username for SSH authentication.
            password (str): The password for SSH authentication.
            interface_name (str, optional): The network interface to check before fetching stats. Defaults to 'tun0'.
        """
        super().__init__(name="RmstStats")

        self.ip = ip
        self.username = user
        self.password = password

        # Instantiate the CheckStatus object for checking network status
        self.check_status = CheckStatus(ip=ip, interface_name=interface_name)

        # Default message before fetching any data
        self.__info = "The screen will update soon!"

        # Control flag for the fetching loop
        self.__lock = True

        # Start the thread immediately after initialization
        self.start()

    def run(self) -> None:
        """
        Main method that runs in the thread. Fetches remote statistics continuously
        as long as __lock is True. Logs status updates and handles errors.
        """
        try:
            # Loop to check if the interface is operational before fetching data
            while self.__lock:
                if self.check_status.interface():
                    logging.info(
                        f"Interface {self.check_status.interface_name} is operational."
                    )
                    break
                else:
                    self.__info = f"Interface {self.check_status.interface_name} is not operational, retrying..."
                    logging.debug(self.__info)
                    sleep(2)

            # Fetch remote statistics while __lock is True
            while self.__lock:
                if self.check_status.target():
                    logging.debug("Target is online, proceeding to fetch information.")

                    # Fetch the top process info from the remote server
                    info = fetch_top_info(
                        ip=self.ip, username=self.username, password=self.password
                    )

                    # Update the stored information or log an error if fetching failed
                    if info:
                        self.__info = info
                    else:
                        self.__info = "Failed to retrieve information, retrying..."
                        logging.error(self.__info)

                    # Wait one second before fetching the next set of stats
                    sleep(1)

                else:
                    self.__info = "Target unavailable, retrying..."
                    logging.debug(self.__info)

                    sleep(2)

            logging.info("Stopped fetching remote stats.")

        except threading.ThreadError as e:
            logging.error(f"An error occurred during the thread operation: {e}")
            sys.exit(1)

    def get(self) -> str:
        """
        Retrieve the most recent information fetched from the remote server.

        Returns:
            str: The latest fetched information.
        """
        return self.__info

    def unlock(self) -> None:
        """
        Stop the fetching loop by setting the __lock attribute to False.
        """
        self.__lock = False


def fetch_top_info(ip: str, username: str, password: str) -> str:
    """
    Fetch the top process information from a target machine via SSH.

    This function connects to a remote machine using SSH, runs the `top` command in batch mode,
    and retrieves its output. It formats the output to include the top command header and limits
    the number of displayed process lines to a predefined quantity. The processes are listed
    in the order of memory usage.

    Args:
        ip (str): The IP address of the remote machine.
        username (str): The SSH username for authentication.
        password (str): The SSH password for authentication.

    Returns:
        str: A formatted string containing the top command's header and a limited number of process lines.

    Raises:
        TopCommandError: If there is an error during the execution of the `top` command.
    """

    TOP_PROCESS_QTY = 7  # Number of process lines to retrieve from the top command
    TOP_HEADER_LENGTH = 7  # Header length of top command output

    logging.debug(f"Connecting to {ip} to retrieve top command information.")

    client = None
    result = ""

    try:
        # Set up SSH client and configure to accept unknown host keys
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the remote machine using username and password
        client.connect(
            ip,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
        )

        # Command to run top in batch mode (-b), limit to one iteration (-n 1), and sort by memory usage (-o %MEM)
        command = "top -b -n 1 -o %MEM"

        stdin, stdout, stderr = client.exec_command(command)

        # Read the command output and error output
        top_output = stdout.read().decode()  # Read and decode the output of top command
        error_output = stderr.read().decode()

        # Raise an error if there is any stderr output from the command
        if error_output:
            raise TopCommandError(f"Error fetching top output: {error_output}")

        logging.debug(f"Successfully fetched top output from {ip}.")

        # Split the output into lines and extract the top header and process lines
        lines = top_output.splitlines()
        top_header = "\n".join(lines[:TOP_HEADER_LENGTH])  # Extract the header section

        # Extract process lines, filtering out empty lines and redundant header information
        process_lines = [
            line
            for line in lines[TOP_HEADER_LENGTH:]
            if line and not line.startswith("top")
        ][
            :TOP_PROCESS_QTY
        ]  # Limit the number of process lines

        # Join the processed lines into a formatted output
        process_lines_output = "\n".join(process_lines)

        result = (
            f"{top_header}\n\nProcesses (limited to {TOP_PROCESS_QTY} lines) by %MEM:\n"
            f"{process_lines_output}\n\n"
        )

    except paramiko.SSHException as e:
        # Log SSH connection failures
        logging.error(f"SSH connection failed: {e}")

    except TopCommandError as e:
        # Log top command errors and re-raise the exception
        logging.error(f"Top command error: {e}")
        raise e

    finally:
        # Close the SSH connection if it was opened
        if client:
            logging.debug(f"Closing SSH connection to {ip}.")
            client.close()

        return result


def on_activate(application, window: BoxedLabel) -> None:
    """
    Signal handler for the 'activate' signal of the Gtk.Application.

    This function is called when the application is started. It sets the application
    to the provided `BoxedLabel` window and presents the window to the user.

    Args:
        application (Gtk.Application): The main Gtk application instance.
        window (BoxedLabel): The window that displays the fetched remote statistics.
    """
    window.set_application(application)
    window.present()


def update_label(window: BoxedLabel, stats: FetchRemoteStats) -> bool:
    """
    Updates the text label with fetched remote statistics at regular intervals.

    This function is periodically called by GLib's timeout mechanism to update the
    label's content with the most recent remote statistics. It continues to be
    called while the window is open.

    Args:
        window (BoxedLabel): The window displaying the statistics.
        stats (FetchRemoteStats): The thread fetching remote statistics.

    Returns:
        bool: Always returns True to keep the timeout active.
    """
    if window:
        # Update the label text with the latest fetched statistics
        window.update_text(stats.get())
    return True  # Continue the periodic updates


def app_signal_handler(signum, frame, app: Gtk.Application) -> None:
    """
    Handle termination signals to gracefully stop the GTK application.

    This function is triggered when the process receives termination signals,
    such as SIGINT (Ctrl+C) or SIGTERM (default kill signal). It logs the
    shutdown event and gracefully terminates the Gtk application by calling `app.quit()`.

    Args:
        signum (int): The signal number (e.g., SIGINT, SIGTERM).
        frame: The current stack frame (not used, included for signal handling signature).
        app (Gtk.Application): The Gtk application instance to quit gracefully.
    """
    logging.info(f"Received signal {signum}. Initiating application shutdown.")
    app.quit()


def main(ip: str, username: str, password: str, interface: str = None) -> None:
    """
    Main function that initializes and runs the application.

    This function starts the `FetchRemoteStats` thread, sets up the Gtk application
    with a window to display the fetched data, and updates the display every second.
    It also captures keyboard interrupts (CTRL+C) to stop the application gracefully.
    If an interface is provided, the script checks the availability of the specified
    network interface before fetching the stats.

    Args:
        ip (str): The IP address of the remote server to monitor.
        username (str): Username for SSH authentication.
        password (str): Password for SSH authentication.
        interface (str, optional): The network interface to check before fetching stats.

    Exits:
        sys.exit(0): If the application completes successfully.
        sys.exit(1): If an error occurs during execution or the interface is not found.
    """
    try:
        logging.info("rmtstats is running")

        # Initialize the thread that fetches remote statistics
        stats = FetchRemoteStats(
            ip=ip, user=username, password=password, interface_name=interface
        )

        # Create a new Gtk application instance
        app = Gtk.Application()

        # Create the window for displaying statistics
        window = BoxedLabel(app)

        # Connect the Gtk application 'activate' signal to the on_activate handler
        app.connect("activate", partial(on_activate, window=window))

        # Set up a GLib timeout to periodically update the window's label every second
        GLib.timeout_add_seconds(1, lambda: update_label(window, stats))

        # Handle the SIGINT (CTRL+C) and SIGTERM signals to quit the application
        signal.signal(
            signal.SIGINT, lambda sig, frame: app_signal_handler(sig, frame, app)
        )
        signal.signal(
            signal.SIGTERM, lambda sig, frame: app_signal_handler(sig, frame, app)
        )

        # Run the Gtk application
        app.run(None)

        # Stop the FetchRemoteStats thread after the Gtk application quits
        stats.unlock()

    except Exception as e:
        # Log the exception and exit with an error code
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

    # Log successful completion of the application
    logging.info("rmtstats finished successfully.")
    sys.exit(0)


if __name__ == "__main__":
    """
    Entry point for the script when run as the main module.

    Parses the command-line arguments for the IP address, username, password,
    and an optional network interface, validates them, and then calls the
    main function to start the application.

    Command-line arguments:
        --ip (str): The IP address of the remote server to fetch statistics from.
        --user (str): The username for SSH authentication.
        --password (str): The password for SSH authentication.
        --interface (str, optional): The network interface to check before starting.

    Exits:
        sys.exit(1): If any required argument is missing or invalid.
    """
    parser = argparse.ArgumentParser(description="Remote stats monitoring script.")

    # Add required command-line arguments
    parser.add_argument("--ip", required=True, help="IP address of the target server.")
    parser.add_argument(
        "--user", required=True, help="Username for SSH authentication."
    )
    parser.add_argument(
        "--password", required=True, help="Password for SSH authentication."
    )
    parser.add_argument(
        "--interface",
        required=False,
        help="Network interface to check. E.g.: tun0 or wlo1.",
    )

    # Parse the arguments from the command line
    args = parser.parse_args()

    # Ensure all required arguments are provided
    if not args.ip or not args.user or not args.password:
        parser.error("The --ip, --user, and --password arguments are required.")

    # Start the main application with the parsed arguments
    main(args.ip, args.user, args.password, args.interface)

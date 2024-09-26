#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib

import argparse
from functools import partial
import logging
import sys
import signal
from widget import BoxedLabel, on_activate, update_label
from core import FetchRemoteStats

# Configure logging
logging.basicConfig(
    level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s"
)


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

        # Create the window for displaying statistics
        window = BoxedLabel()

        # Connect the Gtk application 'activate' signal to the on_activate handler
        window.app.connect("activate", partial(on_activate, window=window))

        # Set up a GLib timeout to periodically update the window's label every second
        GLib.timeout_add_seconds(1, lambda: update_label(window, stats))

        # Handle the SIGINT (CTRL+C) and SIGTERM signals to quit the application
        signal.signal(
            signal.SIGINT, lambda sig, frame: app_signal_handler(sig, frame, window.app)
        )
        signal.signal(
            signal.SIGTERM,
            lambda sig, frame: app_signal_handler(sig, frame, window.app),
        )

        # Run the Gtk application
        window.app.run(None)

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

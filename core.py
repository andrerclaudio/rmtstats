import logging
import subprocess
import sys
import psutil
from time import sleep
import threading
import socket
from commands import fetch_top_info


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

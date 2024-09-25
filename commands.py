import logging
import paramiko


class TopCommandError(Exception):
    """Exception raised for errors during the execution of the `top` command."""

    def __init__(self, message: str):
        super().__init__(message)


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

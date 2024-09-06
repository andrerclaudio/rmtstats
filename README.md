# rmtstats - Remote System Monitoring Tool

## Overview

rmtstats is a Python-based remote system monitoring tool that fetches and displays real-time system statistics from a remote server using SSH. It provides a simple graphical interface to view the top processes running on the remote machine, sorted by memory usage.

## Features

- Real-time monitoring of remote system statistics
- Secure connection via SSH
- Graphical display of top processes
- Automatic reconnection attempts if the target becomes unavailable
- Graceful handling of connection errors and interruptions

## Requirements

- Python 3.x
- GTK 3.0
- Required Python packages:
  - gi (PyGObject)
  - paramiko
  - argparse
  - logging

## Installation

1. Ensure you have Python 3.x installed on your system.
2. Install the required packages.

## How It Works

1. The script establishes an SSH connection to the specified remote server.
2. It runs the `top` command on the remote server to fetch system statistics.
3. The fetched data is displayed in a GTK window, which updates every second.
4. The display shows the top processes sorted by memory usage.
5. If the connection is lost, the script will attempt to reconnect automatically.

## Components

- `BoxedLabel`: A GTK window class for displaying the remote statistics.
- `FetchRemoteStats`: A thread class that continuously fetches remote stats.
- `check_target_is_online`: A function to check if the remote server is reachable.
- `fetch_top_info`: A function to retrieve and parse the `top` command output from the remote server.

## Error Handling

- The script logs various events and errors for debugging purposes.
- It handles SSH connection failures and retries connections when the target is unavailable.
- Graceful shutdown is implemented to handle keyboard interrupts (Ctrl+C).

## Customization

- You can adjust the `TOP_PROCESS_QTY` variable to change the number of processes displayed.
- The update interval can be modified by changing the argument in `GLib.timeout_add_seconds()`.

## Security Considerations

- The script uses password-based SSH authentication. For improved security, consider implementing key-based authentication.
- Ensure that you're using this tool on a secure network and with appropriate permissions.

## Limitations

- The current version is designed for Linux-based remote systems.
- The script does not support SSH key-based authentication in its current form.

## Contributing

Contributions to improve rmtstats are welcome. Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

MIT license

## Disclaimer

This tool is provided as-is, without any warranties. Use it at your own risk and ensure you have the necessary permissions to monitor the remote system.
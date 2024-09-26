import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib

import logging
from core import FetchRemoteStats


class BoxedLabel(Gtk.Window):
    """
    A GTK window to display remote statistics in a styled label.
    The window is customized with CSS and dynamically updates the label's content.
    """

    def __init__(self):
        """
        Initialize the BoxedLabel window.
        """
        super().__init__(title="--- Remote Stats ---")

        # Create a new Gtk application instance
        self.app = Gtk.Application()

        # Connect the "close-request" signal to handle window close events
        self.connect("close-request", self.on_close)

        # Create a box to hold the label
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.set_child(self.box)

        # Create and configure the label to display the remote statistics
        self.label = Gtk.Label()
        self.label.set_xalign(0)  # Align text to the left
        self.label.set_yalign(0)  # Align text to the top
        self.label.set_wrap(True)  # Enable line wrapping for long text

        # Add the label to the box
        self.box.append(self.label)

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
        Update the label's text content dynamically from a string.
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

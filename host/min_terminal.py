"""
Interactive terminal program for sending and receiving MIN frames.
Supports both hex and string input modes.
"""
import argparse
from struct import unpack
from time import sleep
import threading
import logging
import serial.tools.list_ports
from typing import List, Optional

from min import ThreadsafeTransportMINSerialHandler

# Set up logger for this module
logger = logging.getLogger(__name__)


def bytes_to_int32(data: bytes, big_endian=True) -> int:
    """Convert 4 bytes to a 32-bit integer."""
    if len(data) != 4:
        raise ValueError("int32 should be exactly 4 bytes")
    if big_endian:
        return unpack('>I', data)[0]
    else:
        return unpack('<I', data)[0]


def parse_hex_input(hex_str: str) -> bytes:
    """Convert a hex string to bytes, handling spaces and 0x prefixes."""
    # Remove spaces and 0x prefixes
    hex_str = hex_str.replace(' ', '').replace('0x', '')
    return bytes.fromhex(hex_str)


def log_and_print(message, level=logging.INFO, reprint_input_prompt=False, hex_mode=False):
    """Print message to console and log it."""
    print(("\n" if reprint_input_prompt else "") + message)
    logger.log(level, message)
    if reprint_input_prompt:
        if hex_mode:
            print("Enter hex payload: ", end='', flush=True)
        else:
            print("Enter string payload: ", end='', flush=True)



def receive_frames_thread(
    min_handler, hex_mode: bool, stop_event: threading.Event,
    callback=None, print_prompt=True
):
    """Thread function to continuously poll for and display received frames."""
    while not stop_event.is_set():
        frames = min_handler.poll()
        for frame in frames:
            # Run callback if provided before standard handling
            if callback and callback(frame):
                # Skip standard handling if callback returns True
                continue
                
            if hex_mode:
                data = frame.payload.hex()
            else:
                try:
                    data = frame.payload.decode('ascii')
                except UnicodeDecodeError:
                    data = frame.payload.hex()
            msg = "Frame received: min ID={0} {1}".format(frame.min_id, data)
            log_and_print(msg, reprint_input_prompt=True, hex_mode=hex_mode)

        sleep(0.05)  # Small delay to prevent CPU hogging


def parse_log_level(level_name):
    """Convert a log level name to the corresponding logging level."""
    levels = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    level_name = level_name.lower()
    if level_name not in levels:
        raise ValueError(f"Invalid log level: {level_name}")
    return levels[level_name]


def setup_min_handler(port, baudrate, loglevel=logging.ERROR):
    """Set up and return a MIN handler with the given parameters."""
    # Set up logging configuration
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=loglevel, format=log_format)
    
    min_handler = ThreadsafeTransportMINSerialHandler(
        port=port,
        baudrate=baudrate,
        loglevel=loglevel
    )
    return min_handler


def start_min_terminal(min_handler, hex_mode=False, min_id=0x00, frame_callback=None):
    """Start an interactive MIN terminal."""
    log_and_print(f"Mode: {'Hex' if hex_mode else 'String'}")
    log_and_print(f"Using MIN ID: 0x{min_id:02X}")
    log_and_print("Press Ctrl+C to exit")
    if hex_mode:
        log_and_print("Input format: '0x01 02 03' or '01 02 03'")

    # Create a stop event and a thread for receiving frames
    stop_event = threading.Event()
    receive_thread = threading.Thread(
        target=receive_frames_thread,
        args=(min_handler, hex_mode, stop_event, frame_callback),
        daemon=True
    )
    receive_thread.start()

    try:
        while True:
            # Get input from user
            if hex_mode:
                user_input = input("Enter hex payload: ")
                try:
                    payload = parse_hex_input(user_input)
                except ValueError as e:
                    log_and_print(f"Invalid hex input: {e}", logging.ERROR)
                    continue
            else:
                user_input = input("Enter string payload: ")
                payload = user_input.encode('ascii')

            # Send the frame using the specified MIN ID
            min_handler.queue_frame(min_id=min_id, payload=payload)
            
    except KeyboardInterrupt:
        log_and_print("\nTerminating...")
        stop_event.set()  # Signal the thread to stop
        return stop_event
    except Exception as e:
        log_and_print(f"Error: {e}", logging.ERROR)
        return stop_event


def get_available_ports() -> List[str]:
    """Get list of available serial ports.

    Returns:
        List[str]: List of available port names
    """
    return [port.device for port in serial.tools.list_ports.comports()]


def select_port(port: Optional[str] = None) -> str:
    """Select a serial port interactively if none specified.

    Args:
        port: Optional port name to use directly

    Returns:
        str: Selected port name

    Raises:
        RuntimeError: If no ports are available or selection fails
    """
    if port:
        return port

    ports = get_available_ports()
    if not ports:
        raise RuntimeError("No serial ports found")

    print("\nAvailable ports:")
    for i, port_name in enumerate(ports, 1):
        print(f"{i}. {port_name}")

    while True:
        try:
            choice = input("\nSelect port number: ")
            index = int(choice) - 1
            if 0 <= index < len(ports):
                return ports[index]
            print("Invalid selection")
        except ValueError:
            print("Please enter a number")
        except KeyboardInterrupt:
            print("Exiting...")
            exit(0)


def parse_args():
    """Parse command line arguments for MIN terminal functionality."""
    parser = argparse.ArgumentParser(description='Interactive MIN terminal')
    parser.add_argument(
        '--port', '-p',
        help='Serial port (e.g., /dev/tty.usbmodem1421)'
    )
    parser.add_argument(
        '--hex',
        action='store_true',
        help='Use hex input mode'
    )
    parser.add_argument(
        '--min-id',
        type=lambda x: int(x, 0),  # Allows for hex (0x01) or decimal input
        default=0x01,
        help='MIN ID to use when sending frames (default: 0x01)'
    )
    parser.add_argument(
        '--baudrate',
        type=int,
        default=9600,
        help='Baudrate for serial communication (default: 9600)'
    )
    parser.add_argument(
        '--log-level',
        type=parse_log_level,
        default=logging.ERROR,
        help='Set logging level: debug, info, warning, error, critical '
             '(default: error)'
    )
    args = parser.parse_args()

    args.port = select_port(args.port)

    # Validate MIN ID range (0-63 as per the spec)
    if args.min_id not in range(64):
        parser.error("MIN ID must be in range 0-63")
        
    return args


def main():
    """Run the MIN terminal."""
    args = parse_args()

    # Set up and connect MIN handler
    min_handler = setup_min_handler(
        port=args.port,
        baudrate=args.baudrate,
        loglevel=args.log_level
    )
    
    log_and_print(f"Connected to {args.port} at {args.baudrate} baud")
    # Use a dictionary to map logging levels to their names
    level_names = {
        logging.DEBUG: 'DEBUG',
        logging.INFO: 'INFO',
        logging.WARNING: 'WARNING',
        logging.ERROR: 'ERROR',
        logging.CRITICAL: 'CRITICAL'
    }
    log_and_print(f"Log level: {level_names.get(args.log_level, 'UNKNOWN')}")
    
    # Start the interactive terminal
    stop_event = start_min_terminal(
        min_handler=min_handler,
        hex_mode=args.hex,
        min_id=args.min_id
    )
    
    # Cleanup if the terminal exits
    stop_event.set()


if __name__ == "__main__":
    main()

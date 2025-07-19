"""Main CLI entry point for the CTI Agent."""
import argparse
from .agent import CTI_Agent_v2
from .data_manager import update_local_data

def main():
    """Main function to run the CTI Agent CLI."""
    parser = argparse.ArgumentParser(description="Cyber Threat Intelligence Agent")
    parser.add_argument("--version", action="version", version="%(prog)s 2.0.0")
    parser.add_argument("--update-data", action="store_true", help="Update local threat intelligence data.")

    args, remaining_argv = parser.parse_known_args()

    if args.update_data:
        update_local_data()
        print("Local threat intelligence data updated successfully.")
        return

    CTI_Agent_v2.to_cli(remaining_argv)

if __name__ == "__main__":
    main()

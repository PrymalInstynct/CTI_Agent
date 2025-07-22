"""Main CLI entry point for the CTI Agent."""
import argparse
import os
import asyncio
import datetime
import warnings
from .agent import run_analysis, chat_agent
from .data_manager import update_local_data

warnings.filterwarnings("ignore", message="`additionalProperties` is not supported by Gemini; it will be removed from the tool JSON schema.")

async def main():
    """Main function to run the CTI Agent CLI."""
    parser = argparse.ArgumentParser(description="Cyber Threat Intelligence Agent")
    parser.add_argument("--version", action="version", version="%(prog)s 3.0.0")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Update data command
    update_parser = subparsers.add_parser("update-data", help="Update local threat intelligence data.")
    update_parser.set_defaults(func=update_data_command)

    # Analyze SBOM command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a CycloneDX SBOM file.")
    analyze_parser.add_argument("--sbom-file", type=str, required=True, help="Path to the CycloneDX SBOM file for analysis.")
    analyze_parser.set_defaults(func=analyze_command)

    # Chat command
    chat_parser = subparsers.add_parser("chat", help="Start an interactive chat session.")
    chat_parser.set_defaults(func=chat_command)

    args = parser.parse_args()

    if hasattr(args, "func"):
        await args.func(args)
    else:
        parser.print_help()

async def update_data_command(args):
    update_local_data()
    print("Local threat intelligence data updated successfully.")

async def analyze_command(args):
    if not os.path.exists(args.sbom_file):
        print(f"Error: SBOM file not found at {args.sbom_file}")
        return
    try:
        report_content = await run_analysis(args.sbom_file)
        
        # Implement file naming convention
        sbom_filename = os.path.basename(args.sbom_file)
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        report_filename = f"report-{os.path.splitext(sbom_filename)[0]}-{timestamp}.md"
        report_path = os.path.join("reports", report_filename)

        with open(report_path, "w") as f:
            f.write(report_content)
        print(f"Analysis complete. Report saved to: {report_path}")
    except Exception as e:
        print(f"An error occurred during analysis: {e}")

async def chat_command(args):
    print("Starting interactive chat session. Type 'exit' or 'quit' to end.")
    while True:
        user_input = input("You: ")
        if user_input.lower() in ['exit', 'quit']:
            print("Exiting chat session.")
            break
        try:
            response = await chat_agent.run(user_input)
            print(f"Agent: {response.output}")
        except Exception as e:
            print(f"Agent: An error occurred: {e}")

def cli_entrypoint():
    asyncio.run(main())

if __name__ == "__main__":
    cli_entrypoint()
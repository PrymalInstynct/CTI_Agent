"""Main CLI entry point for the CTI Agent."""
import argparse
import os
import asyncio
import datetime
from .agent import run_analysis
from .data_manager import update_local_data

async def main():
    """Main function to run the CTI Agent CLI."""
    parser = argparse.ArgumentParser(description="Cyber Threat Intelligence Agent")
    parser.add_argument("--version", action="version", version="%(prog)s 2.0.0")
    parser.add_argument("--update-data", action="store_true", help="Update local threat intelligence data.")
    parser.add_argument("--sbom-file", type=str, help="Path to the CycloneDX SBOM file for analysis.")

    args = parser.parse_args()

    if args.update_data:
        update_local_data()
        print("Local threat intelligence data updated successfully.")
        return

    if args.sbom_file:
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
    else:
        parser.print_help()

def cli_entrypoint():
    asyncio.run(main())

if __name__ == "__main__":
    cli_entrypoint()
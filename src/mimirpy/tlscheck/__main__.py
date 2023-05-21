import argparse
import json
import sys
from datetime import datetime
import asyncio

import muspell_ssl


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host",
                        help="Target host that you'll scan. E.g.:example.com.")
    parser.add_argument(
        "port",
        help="Number of the port in which the service is served.")
    args = parser.parse_args()
    host = args.host.lower()
    port = int(args.port)
    start = datetime.now()
    print("Initializing scanner...")
    scanner = muspell_ssl.Scanner(host, port)
    results = await scanner.run()
    end = datetime.now()
    print(json.dumps(results, indent=4))
    print("Execution time: {}".format(end - start))
    sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())

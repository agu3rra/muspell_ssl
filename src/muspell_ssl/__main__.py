import argparse
import json
import sys

import muspell_ssl

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host",
                        help="Target host that you'll scan. E.g.:example.com.")
    parser.add_argument(
        "port",
        help="Number of the port in which the service is served.")
    args = parser.parse_args()
    host = args.host.lower()
    port = int(args.port)
    print("Initializing scanner...")
    scanner = muspell_ssl.Scanner(host, port)
    results, err = scanner.run()

    if err is not None:
        print("There was an error while processing your scan:")
        print(err)
        sys.exit(1)

    print("Scan results:")
    print(json.dumps(results, indent=4))
    sys.exit(0)

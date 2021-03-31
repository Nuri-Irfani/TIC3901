# Port Scanning Detection

Requires Python 3, uses **dpkt**.

Current stage: outputs an excel file containing data on every flag that was set in every tcp packet.
Next goal: Use the data to identify possible types of port scanning, if any, that was happening.

# Usage
Uses argparse to run. Only one arg available:

	$ python3 scansdetect.py --listIP [pcap file name].pcap

## Example

If the pcap file used is name `example.pcap`, then:

	$ python3 scansdetect.py --listIP [pcap file name].pcap

	processing packets...
    Enter num:
    [1] To print to txt file
    [2] To print to excel 

Entering the number `1` will write the results into a text file, and choosing 2 will produce the data in excel format.
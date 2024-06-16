# pcap-parser

I had to monitor the network through a VPN to see what the packets were doing

The script thread network scans for the interfaces given in the `interfaces` list and store the results inside \<interfaceName>-capture.pcap files.

After the capture is done, the script will merge the pcap files and output the result in a file.

> You can change the `interfaces` list to the interfaces you want to monitor <br>
> You can change the `captureTime` variable to the time you want to capture the packets

## Usage

```bash
pip install scapy
```

```bash
python3 pcap-parser.py
```

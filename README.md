# SolarWindsOrionScanner
Scanner to detect the SolarWinds Orion Products on the IP addresses

## Prerequisite's
- python3
- python3 -m pip install Requirements.txt

## Usage
python3 orionScanner.py --help

```
usage: orionScanner.py [-h] [-t TARGET] [-T TARGETS] [-c CIDR] [-a ADD]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Single IP
  -T TARGETS, --targets TARGETS
                        List of IP in text file
  -c CIDR, --cidr CIDR  CIDR range
  -a ADD, --add ADD     Addition ports to check for. example: -a 8889,9991
```
***Note:*** Default web ports are 80, 8080, 443, 8443

## Example: 1
Run the script for single IP to detect SolarWinds Orion Products
```
python3 orionScanner.py -t 192.168.0.1
```

## Example: 2
Run the script for Multiple ips by providing text file with ips to detect SolarWinds Orion Products
```
python3 orionScanner.py -T ips.txt
```

## Example: 3
Run the script for CIDR to detect SolarWinds Orion Products
```
python3 orionScanner.py -c 192.168.0.1/24
```

## Example: 4
Run the script for single ip and additional ports to detect SolarWinds Orion Products
```
python3 orionScanner.py -t 192.168.0.1 -a 8889
```

| Command | What It Does |
|---------|--------------|
| `sudo python3 main.py -t [target ip] -p 22` | Scan single port |
| `sudo python3 main.py -t [target ip] -p 1-100` | Scan port range |
| `sudo python3 main.py -t [target ip] -p 21,22,80,443` | Scan specific ports |
| `sudo python3 main.py -t [target ip] -p 1-65535` | Full port scan |
| `sudo python3 main.py -t 192.168.56.0/24 --discovery` | Find live hosts |
| `sudo python3 main.py -t [target ip] -p 1-100 --banner` | Grab banners |
| `sudo python3 main.py -t [target ip] -p 1-100 --vuln-check` | Check vulnerabilities |

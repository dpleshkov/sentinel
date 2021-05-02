<p style="color: red">DISCLAIMER: THIS IS A PROTOTYPE FOR THE OHLONEHACKS 2.0 HACKATHON. 
THIS PRODUCT IS NOT 100% STABLE AND HASNT BEEN TESTED FOR COMPATIBILITY ON ALL DEVICES YET</p>

# Sentinel

As the Internet grows, so does the danger of cyberattacks. Many servers lack the 
most basic security measures, such as firewalls, falling victim to the myth that since they 
aren't part of an important website/service such as Instagram or Google, they won't be targeted.
This is incorrect. Any computer is a valuable target for, say, being used to mine crypto or be part
of a DDoS attack botnet. Sentinel is a simple, lightweight tool that:

* Analyzes your system's authentication logs for any suspicious activity

* Scans your system for open ports, and whether those ports are under a firewall or not

* Has a shorthand command to run a full antivirus scan on your system, using the free, open-source
ClamAV antivirus
  
### Installation

Sentinel requires Node.js 15+ to be installed, and currently should only work on Debian-based servers.
Also requires UFW and ClamAV to be installed (part of the installation script)

First, close the repository

```bash
git clone https://github.com/dpleshkov/sentinel.git
```

Then, run the installation script

```bash
cd sentinel/
bash install.bash
```

### Usage

Start Sentinel by simply running (requires administrative rights)

```bash
bash sentinel.bash
```
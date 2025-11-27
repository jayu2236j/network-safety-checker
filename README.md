# Network Safety Checker

Network Safety Checker is a simple Bash script for Linux systems that performs a basic security review of the local machine. It is written as a small cybersecurity project and is intended for learning and introductory security auditing.

The script checks several common security aspects. It looks at whether a firewall tool such as ufw or firewalld is active, shows a short list of network ports that are listening, inspects some basic SSH configuration settings, looks for user accounts that have empty password fields, scans for world-writable files under the /etc directory, and performs a simple update check on systems that use apt. At the end of the run, the script prints a simple security score out of ten, based on the issues it finds.

This project is aimed at beginners who are learning Linux and cybersecurity. It does not try to replace professional tools or full security audits. Instead, it is designed to demonstrate how simple command line tools and configuration checks can already reveal useful information about the security posture of a system.

To run the script, you need a Linux system with Bash and standard command line tools installed. You also need root privileges because the script reads files such as /etc/shadow and inspects system level settings. On Debian-based systems such as Ubuntu or Kali, you can run it by saving the script as network_safety_checker.sh, making it executable, and running it with sudo.

This project can also be used from other operating systems by running it inside a Linux environment. On Windows, it can be run inside WSL or a virtual machine that has a Linux distribution installed. On macOS, it can be run inside a Linux virtual machine or a lightweight container environment. In all cases, the script is still a Linux Bash script and expects a Linux style system.

The code is kept short and readable on purpose so that each part can be studied and modified. The file code_explanation.txt in this repository explains what each section of the script does in plain language. The file usage_guide.txt provides more detailed instructions for running the script on Linux, for using it together with Windows or macOS, and for basic setup on a fresh Linux system.

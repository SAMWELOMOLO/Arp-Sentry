ArpSentry
ArpSentry is a Python-based ARP spoofing detection and mitigation tool with a GUI interface for managing whitelists and blacklists of MAC addresses. The tool monitors network traffic for ARP spoofing attacks and takes appropriate actions to block attackers, notify the user, and integrate with Security Information and Event Management (SIEM) systems.

Features
ARP Spoofing Detection: Monitors network traffic for ARP spoofing attacks.
Whitelist Management: Allows adding and removing MAC addresses to/from a whitelist.
Blacklist Management: Allows adding and removing MAC addresses to/from a blacklist.
SIEM Integration: Optionally integrates with SIEM systems to log detected events.
Automated Mitigation: Blocks detected attackers by manipulating ARP replies and using iptables rules.
Graphical User Interface (GUI): User-friendly interface for managing the whitelist and blacklist.
Cross-Platform: Can be run on different platforms using Docker.
Prerequisites
Python 3.x
Required Python packages (see requirements.txt)
Docker (optional, for containerized deployment)
Installation
Clone the repository:

Copy code
git clone https://github.com/SAMWELOMOLO/arpsentry.git
cd arpsentry
Install the required packages:

Copy code
pip install -r requirements.txt
Run the application:

Copy code
python arpsentry.py
Usage
GUI
The GUI provides tabs for managing the whitelist and blacklist.

Whitelist Tab:

Add a MAC address to the whitelist.
Remove a MAC address from the whitelist.
Blacklist Tab:

Add a MAC address to the blacklist.
Remove a MAC address from the blacklist.
SIEM Integration
To enable SIEM integration, set siem_integration_enabled to True and configure the siem_url and siem_auth_token variables.
Network Interface
Modify the interfaces list in the code to include the network interfaces you want to monitor.
Code Overview
Key Functions
add_to_whitelist(): Adds a MAC address to the whitelist.
remove_from_whitelist(): Removes a MAC address from the whitelist.
add_to_blacklist(): Adds a MAC address to the blacklist.
remove_from_blacklist(): Removes a MAC address from the blacklist.
integrate_with_siem(event): Sends detected events to a SIEM system.
show_notification(message): Displays a notification message.
get_mac(ip): Retrieves the MAC address for a given IP.
sniff(interface): Sniffs packets on a specified interface.
process_sniffed_packet(packet): Processes sniffed packets for ARP spoofing detection.
block_attacker(packet, real_mac): Blocks the attacker by sending fake ARP replies and manipulating iptables rules.
handle_interfaces(interfaces): Handles sniffing on multiple network interfaces.

from scapy.all import *
import scapy.all as scapy
from scapy.all import ARP, Ether, srp
import tkinter as tk
from tkinter import ttk
from threading import Thread
import requests
import json
import subprocess

# Whitelisted MAC addresses
whitelist = []

# Blacklisted MAC addresses
blacklist = []

def add_to_whitelist():
    """
    Add a MAC address to the whitelist.

    If the provided MAC address is not already in the whitelist and is not empty, it is added to the whitelist and displayed in the GUI.

    :return: None
    """
    mac = mac_entry.get()
    if mac and mac not in whitelist:
        whitelist.append(mac)
        whitelist_listbox.insert(tk.END, mac)
        mac_entry.delete(0, tk.END)

def remove_from_whitelist():
    """
    Remove a MAC address from the whitelist.

    This function removes a selected MAC address from the whitelist and updates the GUI.

    :return: None
    """
    selection = whitelist_listbox.curselection()
    if selection:
        index = selection[0]
        whitelist.pop(index)
        whitelist_listbox.delete(index)

def add_to_blacklist():
    """
    Add a MAC address to the blacklist.

    If the provided MAC address is not already in the blacklist and is not empty, it is added to the blacklist and displayed in the GUI.

    :return: None
    """
    mac = mac_entry.get()
    if mac and mac not in blacklist:
        blacklist.append(mac)
        blacklist_listbox.insert(tk.END, mac)
        mac_entry.delete(0, tk.END)

def remove_from_blacklist():
    """
    Remove a MAC address from the blacklist.

    This function removes a selected MAC address from the blacklist and updates the GUI.

    :return: None
    """
    selection = blacklist_listbox.curselection()
    if selection:
        index = selection[0]
        blacklist.pop(index)
        blacklist_listbox.delete(index)

def integrate_with_siem(event):
    """
    Integrate with SIEM by sending an event.

    If SIEM integration is enabled, this function sends a JSON-encoded event to the configured SIEM endpoint.

    :param dict event: The event data to be sent to the SIEM.
    :return: None
    """
    if siem_integration_enabled:
        headers = {
            "Authorization": f"Bearer {siem_auth_token}",
            "Content-Type": "application/json",
        }
        payload = json.dumps(event)
        response = requests.post(siem_url, headers=headers, data=payload)
        if response.status_code != 200:
            print(f"Failed to send event to SIEM: {response.text}")

def show_notification(message):
    """
    Display a notification.

    This function creates a simple Tkinter window to display a notification message.

    :param str message: The notification message to be displayed.
    :return: None
    """
    root = tk.Tk()
    root.title("ARP Spoofing Detector")
    label = tk.Label(root, text=message, font=("Arial", 16))
    label.pack(pady=10)
    root.overrideredirect(True)
    root.attributes("-alpha", 1.0)
    root.after(2000, root.destroy)
    root.mainloop()

def get_mac(ip):
    """
    Get the MAC address of a given IP.

    This function sends an ARP request to the specified IP address and returns the MAC address from the response.

    :param str ip: The IP address to query.
    :return: str: The MAC address of the IP, or None if no response is received.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def sniff(interface):
    """
    Sniff packets on a specific interface.

    This function starts sniffing packets on the specified network interface and processes each packet using the process_sniffed_packet function.

    :param str interface: The network interface to sniff on.
    :return: None
    """
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    """
    Process sniffed packets for ARP spoofing.

    This function analyzes sniffed ARP packets to detect spoofing attacks. If a spoofing attack is detected, it blocks the attacker and triggers an alert.

    :param packet: The sniffed packet to be processed.
    :return: None
    """
    if scapy.ARP in packet and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if response_mac in whitelist:
                return

            if real_mac != response_mac:
                if response_mac in blacklist:
                    return
                block_attacker(packet, real_mac)
                notification_message = "🎉 You're safe! Blocked an attack."
                notification_thread = Thread(target=show_notification, args=(notification_message,))
                notification_thread.start()
                blacklist.append(response_mac)
                blacklist_listbox.insert(tk.END, response_mac)

                # Integrate with SIEM
                event = {
                    "type": "arp_spoofing",
                    "source_ip": packet[scapy.ARP].psrc,
                    "source_mac": packet[scapy.ARP].hwsrc,
                    "victim_ip": packet[scapy.ARP].pdst,
                    "victim_mac": packet[scapy.ARP].hwdst,
                    "timestamp": packet.time,
                }
                integrate_with_siem(event)

                # Automated mitigation strategies
                subprocess.run(["iptables", "-A", "INPUT", "-s", packet[scapy.ARP].psrc, "-j", "DROP"])
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", packet[scapy.ARP].psrc, "-j", "DROP"])

        except IndexError:
            pass

def block_attacker(packet, real_mac):
    """
    Block the attacker by sending fake ARP replies.

    This function blocks the attacker by sending fake ARP replies to the victim and the attacker.

    :param packet: The packet containing the ARP spoofing attempt.
    :param str real_mac: The real MAC address of the victim device.
    :return: None
    """
    victim_ip = packet[scapy.ARP].pdst
    gateway_ip = packet[scapy.ARP].psrc
    victim_mac = packet[scapy.ARP].hwdst
    attacker_ip = packet[ARP].psrc
    gateway_mac = real_mac

    victim_arp_reply = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(victim_arp_reply, count=4, inter=0.2, verbose=False)

    # Block incoming traffic from the attacker
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", attacker_ip, "-j", "DROP"])

    gateway_arp_reply = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=victim_mac)
    scapy.send(gateway_arp_reply, count=4, inter=0.2, verbose=False)

    # Block outgoing traffic to the attacker
    subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", attacker_ip, "-j", "DROP"])

    # Restore the ARP cache of the victim
    send(ARP(op=2, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=attacker_ip, hwsrc=real_mac), count=5, verbose=False)

def handle_interfaces(interfaces):
    """
    Start sniffing on all specified network interfaces.

    This function iterates through the provided list of network interfaces and starts a separate thread for each interface to sniff packets.

    :param list interfaces: A list of network interfaces to sniff on.
    :return: None
    """
    for interface in interfaces:
        sniff_thread = Thread(target=sniff, args=(interface,))
        sniff_thread.start()

# GUI
root = tk.Tk()
root.title("ArpSentry")
root.geometry("500x400")
style = ttk.Style()
style.configure("TFrame", background="#f0f0f0")
style.configure("TButton", padding=6, relief="flat", background="#ccc")
style.configure("TLabel", background="#f0f0f0", font=("Helvetica", 12))
style.configure("TNotebook", background="#f0f0f0")
style.configure("TNotebook.Tab", padding=(12, 8))

# Tabs
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# Whitelist tab
whitelist_tab = ttk.Frame(notebook)
notebook.add(whitelist_tab, text="Whitelist")

whitelist_label = ttk.Label(whitelist_tab, text="Whitelisted MAC addresses:")
whitelist_label.pack(pady=10)

whitelist_listbox = tk.Listbox(whitelist_tab, selectmode=tk.SINGLE)
whitelist_listbox.pack(pady=10)

whitelist_button_frame = ttk.Frame(whitelist_tab)
whitelist_button_frame.pack(pady=10)

add_whitelist_button = ttk.Button(whitelist_button_frame, text="Add to Whitelist", command=add_to_whitelist)
add_whitelist_button.pack(side=tk.LEFT, padx=5)

remove_whitelist_button = ttk.Button(whitelist_button_frame, text="Remove from Whitelist", command=remove_from_whitelist)
remove_whitelist_button.pack(side=tk.LEFT, padx=5)

# Blacklist tab
blacklist_tab = ttk.Frame(notebook)
notebook.add(blacklist_tab, text="Blacklist")

blacklist_label = ttk.Label(blacklist_tab, text="Blacklisted MAC addresses:")
blacklist_label.pack(pady=10)

blacklist_listbox = tk.Listbox(blacklist_tab, selectmode=tk.SINGLE)
blacklist_listbox.pack(pady=10)

blacklist_button_frame = ttk.Frame(blacklist_tab)
blacklist_button_frame.pack(pady=10)

add_blacklist_button = ttk.Button(blacklist_button_frame, text="Add to Blacklist", command=add_to_blacklist)
add_blacklist_button.pack(side=tk.LEFT, padx=5)

remove_blacklist_button = ttk.Button(blacklist_button_frame, text="Remove from Blacklist", command=remove_from_blacklist)
remove_blacklist_button.pack(side=tk.LEFT, padx=5)

# Entry for MAC address
mac_entry_label = ttk.Label(root, text="MAC Address:")
mac_entry_label.pack(pady=10)

mac_entry = ttk.Entry(root)
mac_entry.pack(pady=10)

# SIEM integration settings
siem_integration_enabled = False
siem_url = ""
siem_auth_token = ""

def enable_siem_integration():
    """
    Enable SIEM integration.

    This function enables SIEM integration by setting the necessary configurations.

    :return: None
    """
    global siem_integration_enabled
    siem_integration_enabled = True

siem_button_frame = ttk.Frame(root)
siem_button_frame.pack(pady=10)

enable_siem_button = ttk.Button(siem_button_frame, text="Enable SIEM Integration", command=enable_siem_integration)
enable_siem_button.pack(pady=5)

# Start sniffing on specified interfaces
interfaces = ["eth0", "wlan0"]
handle_interfaces(interfaces)

root.mainloop()

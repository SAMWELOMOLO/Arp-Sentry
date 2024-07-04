from faulthandler import is_enabled
from scapy.all import *
import scapy.all as scapy
from scapy.all import ARP, Ether, srp
import tkinter as tk
from tkinter import ttk
from threading import Thread
import requests
import json
import subprocess
# import os


# Whitelisted MAC addresses
whitelist = []

# Blacklisted MAC addresses
blacklist = []

# Function to add MAC address to whitelist


def add_to_whitelist():
    """
    Add a MAC address to the whitelist.

    :param str mac: The MAC address to be added.
    :return: None
    :rtype: NoneType

    If the provided MAC address is not already in the whitelist and is not empty, it is added to the whitelist and displayed in the GUI.
    """
    mac = mac_entry.get()
    if mac and mac not in whitelist:
        whitelist.append(mac)
        whitelist_listbox.insert(tk.END, mac)
        mac_entry.delete(0, tk.END)

# Function to remove MAC address from whitelist


def remove_from_whitelist():
    """
    Remove a MAC address from the whitelist.

    :param None: No parameters are required.
    :return: None
    :rtype: NoneType

    This function removes a selected MAC address from the whitelist and updates the GUI.
    """
    selection = whitelist_listbox.curselection()
    if selection:
        index = selection[0]
        whitelist.pop(index)
        whitelist_listbox.delete(index)

# Function to add MAC address to blacklist


def add_to_blacklist():
    """
    Add a MAC address to the blacklist.

    :param str mac: The MAC address to be added.
    :return: None
    :rtype: NoneType

    If the provided MAC address is not already in the blacklist and is not empty, it is added to the blacklist and displayed in the GUI.
    """
    mac = mac_entry.get()
    if mac and mac not in blacklist:
        blacklist.append(mac)
        blacklist_listbox.insert(tk.END, mac)
        mac_entry.delete(0, tk.END)

# Function to remove MAC address from blacklist


def remove_from_blacklist():
    """
    Remove a MAC address from the blacklist.

    :param None: No parameters are required.
    :return: None
    :rtype: NoneType

    This function removes a selected MAC address from the blacklist and updates the GUI.
    """
    selection = blacklist_listbox.curselection()
    if selection:
        index = selection[0]
        blacklist.pop(index)
        blacklist_listbox.delete(index)

# Security tool integration settings
siem_integration_enabled = False
siem_url = "https://your-siem.example.com/api/events"
siem_auth_token = "your_auth_token"


# Function to integrate with SIEM


def integrate_with_siem(event):
    if siem_integration_enabled:
        headers = {
            "Authorization": f"Bearer {siem_auth_token}",
            "Content-Type": "application/json",
        }
        payload = json.dumps(event)
        response = requests.post(siem_url, headers=headers, data=payload)
        if response.status_code != 200:
            print(f"Failed to send event to SIEM: {response.text}")

# Function to display notifications


def show_notification(message):
    root = tk.Tk()
    root.title("ARP Spoofing Detector")
    label = tk.Label(root, text=message, font=("Arial", 16))
    label.pack(pady=10)
    root.overrideredirect(True)
    root.attributes("-alpha", 1.0)
    root.after(2000, root.destroy)
    root.mainloop()

# Function to get the MAC address of an IP


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


# Function to sniff packets on a specific interface
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

# Function to process sniffed packets for ARP spoofing


def process_sniffed_packet(packet):
    if scapy.ARP in packet and packet[scapy .ARP].op == 2:
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
                notification_thread = Thread(
                    target=show_notification, args=(notification_message,))
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
                subprocess.run(["iptables", "-A", "INPUT", "-s",
                               packet[scapy.ARP].psrc, "-j", "DROP"])
                subprocess.run(["iptables", "-A", "OUTPUT", "-d",
                               packet[scapy.ARP].psrc, "-j", "DROP"])

        except IndexError:
            pass

# Function to block the attacker by sending fake ARP replies


def block_attacker(packet, real_mac):
    """
    Block the attacker by sending fake ARP replies.

    :param packet: The packet containing the ARP spoofing attempt.
    :type packet: scapy.packet.Packet
    :param real_mac: The real MAC address of the victim device.
    :type real_mac: str

    This function blocks the attacker by sending fake ARP replies to the victim and the attacker. It uses the Scapy library to create and send the ARP replies. The function takes the packet containing the ARP spoofing attempt and the real MAC address of the victim device as input parameters. It then constructs and sends ARP replies to the victim and the attacker, effectively blocking the attack.

    :return: None
    :rtype: NoneType
    """
    victim_ip = packet[scapy.ARP].pdst
    gateway_ip = packet[scapy.ARP].psrc
    victim_mac = packet[scapy.ARP].hwdst
    attacker_ip = packet[ARP].psrc
    gateway_mac = real_mac

    victim_arp_reply = scapy.ARP(
        op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(victim_arp_reply, count=4, inter=0.2, verbose=False)

    # Block incoming traffic from the attacker
    subprocess.run(["sudo", "iptables", "-A", "INPUT",
                   "-s", attacker_ip, "-j", "DROP"])

    gateway_arp_reply = scapy.ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=victim_mac)
    scapy.send(gateway_arp_reply, count=4, inter=0.2, verbose=False)

    # Block outgoing traffic to the attacker
    subprocess.run(["sudo", "iptables", "-A", "OUTPUT",
                   "-d", attacker_ip, "-j", "DROP"])

    # Restore the ARP cache of the victim
    send(ARP(op=2, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff",
         psrc=attacker_ip, hwsrc=real_mac), count=5, verbose=False)

# Function to handle multiple interfaces


def handle_interfaces(interfaces):
    """
    Start sniffing on all specified network interfaces.

    :param list interfaces: A list of network interfaces to sniff on.
    :return: None
    :rtype: NoneType

    This function iterates through the provided list of network interfaces and starts a separate thread for each interface to sniff packets.
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

whitelist_listbox = tk.Listbox(whitelist_tab, width=30, height=10, bd=0)
whitelist_listbox.pack(pady=5)

mac_entry = ttk.Entry(whitelist_tab, width=30)
mac_entry.pack(pady=5)

button_frame = ttk.Frame(whitelist_tab)
button_frame.pack(pady=5)

whitelist_add_button = ttk.Button(
    button_frame, text="Add to Whitelist", command=add_to_whitelist)
whitelist_add_button.grid(row=0, column=0, padx=5)

whitelist_remove_button = ttk.Button(
    button_frame, text="Remove from Whitelist", command=remove_from_whitelist)
whitelist_remove_button.grid(row=0, column=1, padx=5)
# Blacklist tab
blacklist_tab = ttk.Frame(notebook)
notebook.add(blacklist_tab, text="Blacklist")

blacklist_label = ttk.Label(blacklist_tab, text="Blacklisted MAC addresses:")
blacklist_label.pack(pady=10)

blacklist_listbox = tk.Listbox(blacklist_tab, width=30, height=10, bd=0)
blacklist_listbox.pack(pady=5)

button_frame = ttk.Frame(blacklist_tab)
button_frame.pack(pady=5)

blacklist_add_button = ttk.Button(
    button_frame, text="Add to Blacklist", command=add_to_blacklist)
blacklist_add_button.grid(row=0, column=0, padx=5)

blacklist_remove_button = ttk.Button(
    button_frame, text="Remove from Blacklist", command=remove_from_blacklist)
blacklist_remove_button.grid(row=0, column=1, padx=5)


# Interfaces list
interfaces = ["wlp2s0", "enp1s0"]

handle_interfaces(interfaces)

root.mainloop()

# Containerization and Deployment
# FROM python:3.9-slim
# COPY . /app
# WORKDIR /app
# RUN pip install -r requirements.txt
# CMD ["python", "arpsentry.py"]

# Deploy instructions:
# 1. Build the Docker image: `docker build -t arpsentry .`
# 2. Run the container: `docker run -it --net=host arpsentry`
# Note: The `--net=host` flag is required to allow the container to access the host's network interfaces.

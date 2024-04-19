import time
import socket
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
import tkinter.simpledialog as sd
import json
import threading
import re
import dpkt
import requests

# Global Variables, lists to store IP's
iplist = []
malicious_ips = []
file_name = None
vt_key = None
abuse_key = None

# Function to analyze PCAP files and extract destination IP addresses
def analyze_pcap(file_name):
    with open(file_name, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data
            #Appending IP's to list
            if isinstance(tcp, dpkt.tcp.TCP):
                dst_ip = socket.inet_ntoa(ip.dst)
                iplist.append(dst_ip)
    return iplist


# Function to analyze text files and extract IP addresses
def analyze_txt(file_name):
    with open(file_name, "r") as f:
        content = f.read()
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", content)
        iplist.extend(ips)


# Function to scan IP addresses using VirusTotal and AbuseIPDB APIs
def scanip(iplist, progress_bar, vt_api_key, abuse_api_key):
    interval = 15   # Interval in seconds
    processed_ip = 0
    progress_bar["maximum"] = len(iplist)

    while processed_ip < len(iplist):
        start_time = time.monotonic()
        current_ip = iplist[processed_ip]
        text_area.insert(tk.END, f"\nProcessing item: {current_ip}\n" + "\n")

        # VirusTotal API
        url_vt = "https://www.virustotal.com/api/v3/ip_addresses/" + current_ip
        headers_vt = {"accept": "application/json", "x-apikey": vt_api_key}

        response_vt = requests.get(url_vt, headers=headers_vt)
        response_json_vt = json.loads(response_vt.text)
        total_votes_vt = response_json_vt["data"]["attributes"]["last_analysis_stats"]

        # AbuseIPDB API
        url_abuse = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + current_ip
        headers_abuse = {"Accept": "application/json", "Key": abuse_api_key}

        response_abuse = requests.get(url_abuse, headers=headers_abuse)
        response_json_abuse = json.loads(response_abuse.text)
        num_reports_abuse = response_json_abuse["data"]["totalReports"] 

        # Check if IP is malicious based on VirusTotal or AbuseIPDB reports
        if total_votes_vt["malicious"] > 0 or num_reports_abuse > 0:
            text_area.insert(
                tk.END,
                f"Total votes for {current_ip} on VirusTotal: {total_votes_vt}\n",
                "red",
            )
            text_area.insert(
                tk.END,
                f"Number of reports for {current_ip} on AbuseIPDB: {num_reports_abuse}\n",
                "red",
            )
            malicious_ips.append(current_ip)
        else:
            text_area.insert(
                tk.END,
                f"Total votes for {current_ip} on VirusTotal: {total_votes_vt}\n",
            )
            text_area.insert(
                tk.END,
                f"Number of reports for {current_ip} on AbuseIPDB: {num_reports_abuse}\n",
            )

        text_area.insert(
            tk.END,
            "\n ---------------------------------------------------------------------- \n",
        )

        processed_ip += 1
        progress_bar["value"] = processed_ip
        root.update()
        elapsed_time = time.monotonic() - start_time
        time_to_sleep = max(0, interval - elapsed_time)
        time.sleep(time_to_sleep)


# Function to save output to a text file
def save_output():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    with open(file_path, "w") as f:
        f.write(text_area.get("1.0", tk.END))


# Function to open a file dialog and select a file
def open_file():
    global vt_key, abuse_key
    if abuse_key is None or vt_key is None:
        text_area.insert(
            tk.END, "***Please enter your API keys before selecting a file***\n"
        )
        return

    root = tk.Tk()
    root.withdraw()
    file_name = filedialog.askopenfilename(
        title="Select a.pcap or.txt file",
        filetypes=[("PCAP files", "*.pcap"), ("Text files", "*.txt")],
    )
    root.destroy()
    if not file_name:
        return
    if not file_name.endswith(".pcap") and not file_name.endswith(".txt"):
        text_area.insert(
            tk.END,
            "Warning: You have selected a file that is not a .pcap or .txt file. Please select a .pcap or .txt file.\n",
            "red",
        )
        return None
    start_program(file_name)


# Function to analyze selected file
def analyze_file(vt_api_key, abuse_api_key, file_name):
    global iplist
    iplist = []
    if file_name.endswith(".pcap"):
        analyze_pcap(file_name)
    elif file_name.endswith(".txt"):
        analyze_txt(file_name)
    # Check if file contains IP addresses
    if not iplist:
        text_area.insert(
            tk.END,
            "Warning: The scanned file does not contain any readable IP addresses. Scan another file?",
            "red",
        )

    progress_bar = ttk.Progressbar(
        root, orient="horizontal", length=100, mode="determinate", maximum=0
    )
    progress_bar.pack(padx = 10, fill=['x'], expand=True,)

    text_area.insert(tk.END, "Starting Scan...\n")

    scanip(list(set(iplist)), progress_bar, vt_api_key, abuse_api_key)

    progress_bar.destroy()

    text_area.insert(tk.END, f"\nProgram finished. Malicious IPs:\n{malicious_ips}\n")


# Function to start the program
def start_program(file_name):
    global vt_key, abuse_key
    text_area.tag_config("red", foreground="red")
    thread = threading.Thread(
        target=analyze_file, args=(vt_key, abuse_key, file_name)
    )
    thread.start()


# Function to enter API keys
def key_entry():
    global vt_key, abuse_key
    vt_key = sd.askstring("API Key", "Enter your VirusTotal API Key:", show="*")
    abuse_key = sd.askstring("API Key", "Enter your AbuseIPDB API Key:", show="*")

    if vt_key is not None and abuse_key is not None:
        text_area.insert(tk.END, "API keys entered successfully!\n")
    else:
        text_area.insert(tk.END, "One or both keys were not entered. Try again.\n")

# Function to create dropdown menus in GUI
def dropdown_menus():
    menu = tk.Menu(root)
    root.configure(menu=menu)

    file_menu = tk.Menu(menu, tearoff=0)
    menu.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Select File", command=open_file)
    file_menu.add_separator()
    file_menu.add_command(label="Export Output", command=save_output)

    settings_menu = tk.Menu(menu, tearoff=0)
    menu.add_cascade(label="Settings", menu=settings_menu)
    settings_menu.add_command(label="Enter API Keys", command=key_entry)
    
    info_menu = tk.Menu(menu, tearoff = 0)
    menu.add_cascade(label="Info", menu=info_menu)
    info_menu.add_command(label = "Open patch notes", command=patch_notes)
    
def patch_notes():
    text_area.insert(tk.END, "Patch notes:\n")
    text_area.insert(tk.END, "  -GUI overhaul bug fixes\n"
                            +"      -Menu buttons\n"
                            +"      -Better Progress Bar\n"
                            +"  -Usability improvements\n"
                            +"      - Start, guide, and error messages\n")
                              

# Create main window
root = tk.Tk()
root.title("CapScan v2.1")
root.geometry("800x600")
root.configure(bg="#f5f5f5")

# Create text area
text_area = scrolledtext.ScrolledText(
    root, font=("Helvetica", 12), bg="#f5f5f5", fg="black"
)
text_area.pack(expand=True, fill="both")
text_area.insert(tk.END, "First enter you API keys under 'settings', then select a .pcap or .txt file to scan.\n" +
                 "---------------------------------------------------------------------- \n")
# Create dropdown menus
dropdown_menus()

# Start the main loop
root.mainloop()

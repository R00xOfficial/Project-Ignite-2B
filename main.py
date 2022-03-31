# =============================================================================
# Created By  : Group 8
# Created Date: 6:08 PM 18/03/2022
# ------------------------------------------------🍒---------•----- ᗤ ᗣᗣᗣᗣ-----
#
#  --<* Architecture *>--
#  Imports
#  ├───PARAMETERS
#  ├───CLASSES
#  ├───FUNCTIONS
#  ├───GUI
#  │   └───Create Entities
#  │   │   ├───SETTINGS AREA
#  │   │   │   ├───Gmail Settings Form
#  │   │   │   ├───Network Settings Form
#  │   │   │   ├───SMS Settings Form
#  │   │   │   ├───Settings Inputs
#  │   │   │   └───Enable/Disable Settings Form
#  │   │   ├───STATUS AREA
#  │   │   │   └───Additional Network Inserting Form
#  │   │   ├───CONSOLE AREA
#  │   │   └───BUTTONS AREA
#  │   └───POSITION ENTITIES
#  │       ├───POSITION BUTTONS AREA
#  │       ├───POSITION MAIN ENTITIES
#  │       ├───POSITION SETTINGS AREA
#  │       │   ├───Position Gmail Settings Area
#  │       │   ├───Position Network Settings Area
#  │       │   ├───Position SMS Settings Area
#  │       │   ├───Settings Inputs
#  │       │   └───Enable/Disable Settings Form
#  │       └───POSITION NETWORK STATUS AREA
#  └───GENERATE AND LOOP
#
#
# =============================================================================
# Imports
# =============================================================================
import os
import re
import smtplib
import socket
import sys
import time
import tkinter as tk

from tkinter import messagebox, ttk, END
from tkinter.filedialog import askopenfilename, asksaveasfilename
from tkinter.ttk import *
from scapy.all import ICMP, IP, sr1
from twilio.rest import Client

# =============================================================================
# PARAMETERS
# =============================================================================


# Gmail login credentials https://myaccount.google.com/lesssecureapps
gmail_user = 'xxxxxxxxxxx@gmail.com'
gmail_app_password = 'xxxxxxxxxxxxxxxx'

email_receiver = 'igniteproject8@gmail.com'

# Your Account SID from twilio.com/console
sms_account_sid = "ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
# Your Auth Token from twilio.com/console
sms_auth_token = "your_auth_token"

# SMS messages from and to numbers
sms_from = "+12316851234"
sms_to = "+15555555555"

# Define IP range to ping
host_names = ['Container Ship 28', 'Bulk Carrier 21', 'Bulk Carrier 6', 'Coastal Tanker 1', 'Passenger Ferry 3']
hosts = ['192.168.10.201', '192.168.10.202', '192.168.10.203', '192.168.10.204', '192.168.10.205']

# The timeout parameter specify the time to wait after the last packet has been sent.
network_timeout = 1

# If retry is 3, Scapy will try to resend unanswered packets 3 times.
# If retry is -3, Scapy will resend unanswered packets until no more answer is given for the same
# set of unanswered packets 3 times in a row.
retry_attempts = 0


# =============================================================================
# CLASSES
# =============================================================================

class PrintLogger(object):  # create file like object
    def __init__(self, text_widget):
        # Constructor
        self.output = text_widget

    def write(self, string):
        # Add text to the end and scroll to the end
        window.update()
        self.output.insert('end', string)
        self.output.see('end')
        self.output.update_idletasks()
        window.update()


# =============================================================================
# FUNCTIONS
# =============================================================================
status_area_addresses = []
scanning = False


def sms_message(message):
    client = Client(sms_account_sid, sms_auth_token)
    client.messages.create(to=sms_to, from_=sms_from, body=message)
    window.update()


def test_print():  # Just a test function to see the text output is working.
    i = 1
    while i < 600:
        print(i)
        i += 1
        print("Am i working?")
        window.update()
        time.sleep(0.5)


def send_email(sent_to, sent_subject, sent_body):  # Function for calling on when an email needs sending
    sent_from = gmail_user
    email_text = """\
    From: %s
    To: %s
    Subject: %s

    %s
    """ % (sent_from, ", ".join(sent_to), sent_subject, sent_body)
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_user, gmail_app_password)
        server.sendmail(sent_from, sent_to, email_text)
        server.close()
        print('!!! Alert Email Sent !!!')
        window.update()
    except Exception as exception:
        print("Email Error: %s!\n\n" % exception)
        window.update()


def build_list():
    status_area_addresses.clear()
    status_area.delete(*status_area.get_children())
    for host in hosts:
        status_area_addresses.append((f'{host_names[hosts.index(host)]}', f'{host}', 'N/A'))
        window.update()

    # add data to the treeview
    for status_area_address in status_area_addresses:
        status_area.insert('', tk.END, values=status_area_address)
        window.update()


def connect_server():  # Function to send out pings... to be remade to only ping certain IPs for boats
    # Reset alive counter to 0
    live_count = 0
    address_count = -1
    known_dead = []
    global scanning
    scanning = True
    build_list()

    while True:
        window.update()
        time.sleep(0.3)
        #  Send ICMP ping request, wait for answer
        if scanning:
            scan_status('Scanning')
            for host in hosts:
                window.update()
                address_count = address_count + 1
                status_area.item(status_area.get_children()[address_count],
                                 values=(f'{host_names[hosts.index(host)]}', f'{host}', 'Updating...'))
                resp = sr1(
                    IP(dst=str(host)) / ICMP(),
                    timeout=network_timeout,
                    retry=retry_attempts,
                    verbose=0,
                )
                window.update()
                if resp is None:
                    print(f"{host} is down or not responding.")
                    status_area.item(status_area.get_children()[address_count],
                                     values=(f'{host_names[hosts.index(host)]}', f'{host}', 'Dead'))
                    window.update()
                    if window_check.get() == 1:
                        messagebox.showwarning(title=f"{host} is down!",
                                               message="A ship has gone dark, sending email!")
                        if not str(host) in known_dead:
                            known_dead.append(str(host))
                            print(f'{host} reported and added to known dead')
                            window.update()
                    if email_check.get() == 1:
                        send_email(email_receiver, "Alert! A device is not responding!",
                                   f"Alert! {host} is down or not responding.")
                        if not str(host) in known_dead:
                            known_dead.append(str(host))
                            print(f'{host} reported and added to known dead')
                            window.update()
                    if sms_check.get() == 1:
                        sms_message(f'{host} - Alert! A device is not responding!')
                        if not str(host) in known_dead:
                            known_dead.append(str(host))
                            print(f'{host} reported and added to known dead')
                            window.update()
                    window.update()
                elif (
                        int(resp.getlayer(ICMP).type) == 3 and
                        int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]
                ):
                    status_area.item(status_area.get_children()[address_count],
                                     values=(f'{host_names[hosts.index(host)]}', f'{host}', 'Blocked'))
                    print(f"{host} is blocking ICMP.")
                    window.update()
                else:
                    print(f"{host} is responding.")
                    status_area.item(status_area.get_children()[address_count],
                                     values=(f'{host_names[hosts.index(host)]}', f'{host}', 'Alive'))
                    window.update()
                    if str(host) in known_dead:
                        known_dead.remove(str(host))
                        print(f'{host} removed from known dead')
                    live_count += 1
                    window.update()
            window.update()
            address_count = -1
            print(f"{live_count}/{len(hosts)} hosts are online.")
            live_count = 0
            window.update()
            if not scanning:
                scan_status('Stopped')


def endloop():
    global scanning
    scanning = False
    scan_status('Stopping')
    window.update()


def open_file():  # !!! NOT FINISHED !!!
    # Open a file for viewing.
    filepath = askopenfilename(
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]  # PCAP log loading feature (not finished)
    )
    if not filepath:
        return
    txt_edit.delete(1.0, tk.END)
    with open(filepath, "r") as input_file:
        text = input_file.read()
        txt_edit.insert(tk.END, text)
        print(f"[DEBUG] Input file = {input_file}")
    window.title(f"Boat Monitor System - {filepath}")


def save_file():  # !!! NOT FINISHED !!!
    # Save the current console log as a new file.
    filepath = asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],  # PCAP log saving feature (not finished)
    )
    if not filepath:
        return
    with open(filepath, "w") as output_file:
        text = txt_edit.get(1.0, tk.END)
        output_file.write(text)
        print(f"[DEBUG] \n\ntext = {text}\noutput_file = {output_file}")
    window.title(f"Boat Monitor System - {filepath}")


def redirect_logging():  # Send print to GUI
    sys.stdout = PrintLogger(txt_edit)
    sys.stderr = PrintLogger(txt_edit)
    print("Redirected logs to text area")
    window.update()


def reset_logging():  # Send print to console
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    print("Reset logs to console")
    window.update()


def email_check_fuc():
    if email_check.get() == 0:
        entry1.configure(state='disabled')
        entry2.configure(state='disabled')
    else:
        entry1.configure(state='normal')
        entry2.configure(state='normal')


def sms_check_fuc():
    if sms_check.get() == 0:
        entry5.configure(state='disabled')
        entry6.configure(state='disabled')
        entry7.configure(state='disabled')
        entry8.configure(state='disabled')
    else:
        entry5.configure(state='normal')
        entry6.configure(state='normal')
        entry7.configure(state='normal')
        entry8.configure(state='normal')


def submit_gmail():
    global gmail_user
    global gmail_app_password
    if re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", str(entry1.get())):
        gmail_user = str(entry1.get())
        gmail_app_password = str(entry2.get())
        print(f'\n*** GMAIL SETTINGS UPDATED ***\nGmail User: {gmail_user}\nGmail Pass: {gmail_app_password}\n')
    else:
        tk.messagebox.showerror(title='Invalid Email', message=f'{entry1.get()} is not a email address. Please enter '
                                                               f'a valid email address')


def submit_network():
    global network_timeout
    global retry_attempts
    global entry3
    global entry4
    if int(entry3.get()) >= 20 or int(entry4.get()) >= 20:
        tk.messagebox.showerror(title='Invalid Number', message='The number you have entered is invalid (above 20). '
                                                                'Please enter a valid number')
    elif int(entry3.get()) < 0:
        tk.messagebox.showerror(title='Invalid Number', message='An inputted number is too low (bellow zero). Please '
                                                                'enter a valid number')
    else:
        network_timeout = int(entry3.get())
        retry_attempts = int(entry4.get())
        print(f'\n*** NETWORK SETTINGS UPDATED ***\nNetwork Timeout: {network_timeout}\nRetry Attempts:'
              f' {retry_attempts}\n')


def submit_sms():
    global sms_account_sid
    global sms_auth_token
    global sms_from
    global sms_to
    sms_account_sid = entry5.get()
    sms_auth_token = entry6.get()
    sms_from = entry7.get()
    sms_to = entry8.get()
    print(f'\n*** SMS SETTINGS UPDATED ***\nSMS Account ID: {sms_account_sid}\nSMS Auth Token: {sms_auth_token}\nSMS '
          f'From: {sms_from}\nSMS To: {sms_to}\n')


def scan_status(status):
    if status == 'Scanning':
        scanning_heading_title.configure(text='Status: Scanning', fg='Green')
        window.update()
    elif status == 'Stopping':
        scanning_heading_title.configure(text='Status: Stopping', fg='Orange')
        window.update()
    else:
        scanning_heading_title.configure(text='Status: Stopped', fg='Red')
        window.update()


def clear_text():
    entry9.delete(0, END)
    entry10.delete(0, END)
    window.update()


def add_to_network():
    try:
        socket.inet_aton(ship_input2.get())
        host_names.append(str(ship_input1.get()))
        hosts.append(str(ship_input2.get()))
        build_list()
        window.update()
    except socket.error:
        tk.messagebox.showerror(title='Invalid IP', message=f'{ship_input2.get()} is not a valid IP. Please enter a '
                                                            f'valid IP')


def remove_item():
    selected_items = status_area.selection()
    for selected_item in selected_items:
        host_names.remove(str(list(status_area.item(status_area.focus()).values())[2][0]))
        hosts.remove(str(list(status_area.item(status_area.focus()).values())[2][1]))
        status_area.delete(selected_item)
        window.update()


def img_resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


icon_path = img_resource_path("Ship-Wheel.ico")
# =============================================================================
# GUI
# =============================================================================
# Make and configure window
window = tk.Tk()
window.title("Boat Monitor System")
window.rowconfigure(4, minsize=300, weight=1)
window.columnconfigure(2, minsize=800, weight=1)
window.iconbitmap(icon_path)

# =============================================================================
# CREATE ENTITIES
# =============================================================================


# Add buttons and text edit area
# ---------------------8<-------------[ cut here ;]-----------------------------
# SETTINGS AREA
# -----------------------------------------------------------------------------
columns = ('boat_name', 'address', 'status')
txt_edit_area = tk.Frame(window, relief=tk.RAISED, bd=2)
settings_area = ttk.Notebook(window)
settings_area1 = ttk.Frame(settings_area)
settings_area2 = tk.Text(settings_area)
settings_area.add(settings_area1, text='Settings')
settings_area.add(settings_area2, text='Settings Help')
settings_heading_title = tk.Label(settings_area1, text="Settings")

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Gmail Settings Form
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
gmail_input_text_1 = Label(settings_area1, text='Gmail Username:')
gmail_input_text_2 = Label(settings_area1, text='Gmail Password:')
gmail_input1 = tk.StringVar(window, value=gmail_user)
gmail_input2 = tk.StringVar(window, value=gmail_app_password)
btn_gmail = tk.Button(settings_area1, text="Submit", command=submit_gmail)

sep3 = Separator(settings_area1, orient='horizontal')

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Network Settings Form
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
network_input_text_1 = Label(settings_area1, text='Network Timeout:')
network_input_text_2 = Label(settings_area1, text='Retry Attempts:')
network_input1 = tk.IntVar(window, value=network_timeout)
network_input2 = tk.IntVar(window, value=retry_attempts)
btn_network = tk.Button(settings_area1, text="Submit", command=submit_network)

sep4 = Separator(settings_area1, orient='horizontal')

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# SMS Settings Form
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
sms_input_text_1 = Label(settings_area1, text='SMS Account SID:')
sms_input_text_2 = Label(settings_area1, text='SMS Auth Token:')
sms_input1 = tk.StringVar(window, value=sms_account_sid)
sms_input2 = tk.StringVar(window, value=sms_auth_token)
sms_input_text_3 = Label(settings_area1, text='SMS From:')
sms_input_text_4 = Label(settings_area1, text='SMS To:')
sms_input3 = tk.StringVar(window, value=sms_to)
sms_input4 = tk.StringVar(window, value=sms_from)
btn_sms = tk.Button(settings_area1, text="Submit", command=submit_sms)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Settings Inputs
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
entry1 = tk.Entry(settings_area1, textvariable=gmail_input1)
entry2 = tk.Entry(settings_area1, textvariable=gmail_input2)
entry3 = tk.Entry(settings_area1, textvariable=network_input1)
entry4 = tk.Entry(settings_area1, textvariable=network_input2)
entry5 = tk.Entry(settings_area1, textvariable=sms_input1)
entry6 = tk.Entry(settings_area1, textvariable=sms_input2)
entry7 = tk.Entry(settings_area1, textvariable=sms_input3)
entry8 = tk.Entry(settings_area1, textvariable=sms_input4)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Enable/Disable Settings Form
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
email_check = tk.IntVar(value=1)
sms_check = tk.IntVar(value=0)
window_check = tk.IntVar(value=0)
check1 = tk.Checkbutton(settings_area1, text='Enable Email Alerts', variable=email_check, onvalue=1, offvalue=0,
                        command=email_check_fuc)
check2 = tk.Checkbutton(settings_area1, text='Enable SMS Alerts', variable=sms_check, onvalue=1, offvalue=0,
                        command=sms_check_fuc)
check3 = tk.Checkbutton(settings_area1, text='Enable Alert Window', variable=window_check, onvalue=1, offvalue=0)

# -----------------------------------------------------------------------------
# STATUS AREA
# -----------------------------------------------------------------------------
heading_title = tk.Label(txt_edit_area, text="🚢 Boat Monitor System")
status_area = Treeview(txt_edit_area, columns=columns, show='headings')
status_area.heading('boat_name', text='Boat Name')
status_area.heading('address', text='Address')
status_area.heading('status', text='Status')
scrollbar = Scrollbar(txt_edit_area, orient='vertical', command=status_area.yview)
status_area['yscrollcommand'] = scrollbar.set

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Additional Network Inserting Form
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
ship_input1 = tk.StringVar(window, value='Boat Name')
ship_input2 = tk.StringVar(window, value='Boat Address')
btn_network_clear = tk.Button(txt_edit_area, text="Clear", command=clear_text)
btn_network_add = tk.Button(txt_edit_area, text="Add", command=add_to_network)
btn_network_remove = tk.Button(txt_edit_area, text="Remove Selected", command=remove_item)
entry9 = tk.Entry(txt_edit_area, textvariable=ship_input1)
entry10 = tk.Entry(txt_edit_area, textvariable=ship_input2)

# -----------------------------------------------------------------------------
# CONSOLE AREA
# -----------------------------------------------------------------------------
scanning_frame = tk.Frame(window)
txt_edit = tk.Text(scanning_frame)
scanning_heading_title = tk.Label(scanning_frame, text="Status: Stopped", fg='Red')

# -----------------------------------------------------------------------------
# BUTTONS AREA
# -----------------------------------------------------------------------------
fr_buttons = tk.Frame(window, relief=tk.RAISED, bd=2)
btn_connect = tk.Button(fr_buttons, text="Connect", command=connect_server)
btn_stop = tk.Button(fr_buttons, text="STOP!", command=endloop)

sep1 = Separator(fr_buttons, orient='horizontal')

btn_redirect = tk.Button(fr_buttons, text="Live logs", command=redirect_logging)
btn_reset = tk.Button(fr_buttons, text="Hide logs", command=reset_logging)

sep2 = Separator(fr_buttons, orient='horizontal')

btn_open = tk.Button(fr_buttons, text="Open", command=open_file)
btn_save = tk.Button(fr_buttons, text="Save As...", command=save_file)

# =============================================================================
# POSITION ENTITIES
# =============================================================================


# Position all elements
# -----------------------------------------------------------------------------
# POSITION BUTTONS AREA
# -----------------------------------------------------------------------------
fr_buttons.grid(row=0, column=0, sticky="ns", rowspan=5)
btn_connect.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
btn_stop.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
sep1.grid(row=2, column=0, sticky="ew", padx=15, pady=10)
btn_redirect.grid(row=3, column=0, sticky="ew", padx=5, pady=5)
btn_reset.grid(row=4, column=0, sticky="ew", padx=5, pady=5)
sep2.grid(row=5, column=0, sticky="ew", padx=15, pady=10)
btn_open.grid(row=6, column=0, sticky="ew", padx=5, pady=5)
btn_save.grid(row=7, column=0, sticky="ew", padx=5)

#  Configure buttons texts and fonts
btn_stop.configure(fg='red')
btn_connect.configure(fg='green')
heading_title.configure(font=("Times", "24", "bold italic"))

# -----------------------------------------------------------------------------
# POSITION MAIN ENTITIES
# -----------------------------------------------------------------------------
heading_title.grid(row=0, column=2, sticky="ew", padx=70, pady=15)
txt_edit.grid(row=0, column=1, sticky="ns", pady=15, padx=10)

settings_area.grid(row=2, column=1, sticky="nsew", pady=5, padx=10)
settings_heading_title.grid(row=0, column=1, sticky="ew", padx=50, pady=15)
settings_heading_title.configure(font=("Times", "14", "bold italic"))

scanning_heading_title.grid(row=0, column=1, sticky="ne", pady=15, padx=10)
scanning_frame.grid(row=0, column=1, sticky="ns", pady=15, padx=10)

txt_edit_area.grid(row=0, column=2, sticky="nsew")
status_area.grid(row=1, column=2, sticky="s", columnspan=4, padx=100)
scrollbar.grid(row=1, column=4, sticky='ns')

# -----------------------------------------------------------------------------
# POSITION SETTINGS AREA
# -----------------------------------------------------------------------------
entry1.grid(row=1, column=1, padx=30, pady=6)
entry2.grid(row=2, column=1, padx=30, pady=6)
entry3.grid(row=4, column=1, padx=30, pady=6)
entry4.grid(row=5, column=1, padx=30, pady=6)
entry5.grid(row=7, column=1, padx=30, pady=6)
entry6.grid(row=8, column=1, padx=30, pady=6)
entry7.grid(row=9, column=1, padx=30, pady=6)
entry8.grid(row=10, column=1, padx=30, pady=6)
for x in range(8):
    sms_input_text_4.grid(row=10, column=0, sticky="e")
    globals()[f"entry{x + 1}"].configure(width=40)
check1.grid(row=1, column=2, padx=30, pady=6)
check2.grid(row=7, column=2, padx=30, pady=6)
check3.grid(row=0, column=0, padx=30, pady=6)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Position Gmail Settings Area
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
gmail_input_text_1.grid(row=1, column=0, sticky="e")
gmail_input_text_2.grid(row=2, column=0, sticky="e")
btn_gmail.grid(row=2, column=2, sticky="ew", padx=20)
sep3.grid(row=3, column=0, columnspan=3, sticky="ew", padx=15, pady=10)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Position Network Settings Area
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
network_input_text_1.grid(row=4, column=0, padx=10, sticky="e")
network_input_text_2.grid(row=5, column=0, padx=10, sticky="e")
btn_network.grid(row=4, column=2, rowspan=2, sticky="ew", padx=20)
sep4.grid(row=6, column=0, columnspan=3, sticky="ew", padx=15, pady=10)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Position SMS Settings Area
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

sms_input_text_1.grid(row=7, column=0, sticky="e")
sms_input_text_2.grid(row=8, column=0, sticky="e")
sms_input_text_3.grid(row=9, column=0, sticky="e")
btn_sms.grid(row=8, column=2, sticky="ew", padx=20)

# -----------------------------------------------------------------------------
# POSITION NETWORK STATUS AREA
# -----------------------------------------------------------------------------
entry9.grid(row=8, column=2, padx=150, pady=10)
entry9.configure(width=20)
entry10.grid(row=9, column=2)
entry10.configure(width=20)
btn_network_clear.grid(row=10, column=2, sticky="ew", padx=190, pady=5)
btn_network_add.grid(row=11, column=2, sticky="ew", padx=190, pady=0)
btn_network_remove.grid(row=8, column=3, sticky="ew")

# =============================================================================
# GENERATE AND LOOP
# =============================================================================
sys.stdout = PrintLogger(txt_edit)
sys.stderr = PrintLogger(txt_edit)
sms_check_fuc()
build_list()
settings_area2.insert(1.0, """
✉ Email Alerts ✉
To enable email alerts you will need to create a gmail account and 
provide the program with your credentials.
Once you have your Gmail login credentials you will just need to enable access by 
visiting the following link and enabling lesssecureapps 
https://myaccount.google.com/lesssecureapps
                           
⅏ Retry Attempts ⅏
For an example of a retry input, 3, Scapy will try to resend unanswered packets 3 
times. If retry is -3, Scapy will resend unanswered packets until no more answer 
is given for the same set of unanswered packets 3 times in a row.

⏰ Network Timeout ⏰
The timeout parameter specifics the time to wait after the last packet has been sent. 

📲 SMS Alerts 📲
To enable SMS alerts you will need to create an account with Twilio and claim your 
Account SID and Auth Token from twilio.com/console
""")
settings_area2.configure(state='disabled')


window.mainloop()

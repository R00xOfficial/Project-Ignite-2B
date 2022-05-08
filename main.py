# =============================================================================
# Created By  : Group 8
# Created Date: 6:08 PM 18/03/2022
# ------------------------------------------------🍒---------•----- ᗤ ᗣᗣᗣᗣ----
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
import pickle
import re
import smtplib
import socket
import sys
import threading
import time
import tkinter as tk
import winsound
from _socket import error, inet_aton
from sys import platform
from tkinter import *
from tkinter import messagebox, ttk, END
from tkinter.filedialog import askopenfilename, asksaveasfilename
from tkinter.messagebox import askyesno
from tkinter.ttk import *

from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sr1
from twilio.rest import Client
from platform import system as system_name
from os import system as system_call
from socket import AF_INET, SOCK_DGRAM, socket, getfqdn

# =============================================================================
# PARAMETERS
# =============================================================================
try:
    config = pickle.load(open('config.db', 'rb'))
    gmail_user = config[0]
    gmail_app_password = config[1]
    email_receiver = config[2]
    sms_account_sid = config[3]
    sms_auth_token = config[4]
    sms_from = config[5]
    sms_to = config[6]
    host_names = config[7]
    hosts = config[8]
    network_timeout = config[9]
    retry_attempts = config[10]
    print(f'---<**** Config Loaded ****>----\n[0] gmail_user = {gmail_user}\n[1] gmail_app_password = '
          f'{gmail_app_password}\n[2] email_receiver = {email_receiver}\n[3] sms_account_sid = {sms_account_sid}\n'
          f'[4] sms_auth_token = {sms_auth_token}\n[5] sms_from = {sms_from}\n[6] sms_to = {sms_to}\n[7] host_names = '
          f'{host_names}\n[8] hosts = {hosts}\n[9] network_timeout = {network_timeout}\n[10] retry_attempts = '
          f'{retry_attempts}')
except (OSError, IOError) as e:

    # Gmail login credentials https://myaccount.google.com/lesssecureapps
    gmail_user = 'igniteproject8@gmail.com'
    gmail_app_password = 'NuxCNdNv3ZJfRNZ2'

    email_receiver = 'igniteproject8@gmail.com'

    # Your Account SID from twilio.com/console
    sms_account_sid = 'ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
    # Your Auth Token from twilio.com/console
    sms_auth_token = 'your_auth_token'

    # SMS messages from and to numbers
    sms_from = '+12316851234'
    sms_to = '+15555555555'

    # Define IP range to ping
    host_names = ['Container Ship 28', 'Bulk Carrier 21', 'Bulk Carrier 6', 'Coastal Tanker 1', 'Passenger Ferry 3']
    hosts = ['192.168.10.201', '192.168.10.202', '192.168.10.203', '192.168.10.204', '192.168.10.205']

    # The timeout parameter specify the time to wait after the last packet has been sent.
    network_timeout = 1

    # If retry is 3, Scapy will try to resend unanswered packets 3 times.
    # If retry is -3, Scapy will resend unanswered packets until no more answer is given for the same
    # set of unanswered packets 3 times in a row.
    retry_attempts = 0

    pickle.dump(
        [gmail_user, gmail_app_password, email_receiver, sms_account_sid, sms_auth_token, sms_from, sms_to, host_names,
         hosts, network_timeout, retry_attempts], open('config.db', 'wb'))

status_area_addresses = []
networkscan_area_addresses = []
scanning = False
network_scanning = False
boxes = []
row = 0
scan_hosts = []
scan_names = []
scanned_alive = 0
scanned = 0


# =============================================================================
# CLASSES
# =============================================================================

class PrintLogger(object):  # create file like object
    def __init__(self, text_widget):
        # Constructor
        self.output = text_widget
        window.update()

    def write(self, string):
        # Add text to the end and scroll to the end
        window.update()
        self.output.insert('end', string)
        self.output.see('end')
        self.output.update_idletasks()
        window.update()

    def flush(self):
        pass


# =============================================================================
# FUNCTIONS
# =============================================================================


def sms_message(message):
    client = Client(sms_account_sid, sms_auth_token)
    client.messages.create(to=sms_to, from_=sms_from, body=message)
    window.update()


def test_print():  # Just a test function to see the text output is working.
    i = 1
    while i < 600:
        print(i)
        i += 1
        print('Am i working?')
        window.update()
        time.sleep(0.5)


def send_email(sent_to, sent_subject, sent_body):  # Function for calling on when an email needs sending
    sent_from = gmail_user
    email_text = '''\
    From: %s
    To: %s
    Subject: %s

    %s
    ''' % (sent_from, ', '.join(sent_to), sent_subject, sent_body)
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_user, gmail_app_password)
        server.sendmail(sent_from, sent_to, email_text)
        server.close()
        print('!!! Alert Email Sent !!!')
        window.update()
    except Exception as exception:
        print('Email Error: %s!\n\n' % exception)
        window.update()


def update_boxes():
    global boxes, row
    column = 3
    extra = len(hosts) % column
    rows = int(len(hosts) / 3)
    if len(boxes) > 0:
        for box in boxes:
            box.destroy()
        boxes = []
    for row in range(rows):
        for col in range(3):
            globals()[f'boxing_area_template{len(boxes)}'] = tk.Frame(boxing_area, relief=tk.RAISED, bd=2)
            globals()[f'boxing_area_template{len(boxes)}'].grid(row=row, column=col, sticky='nw', padx=15, pady=15)
            globals()[f'boxing_area_template{len(boxes)}'].configure(width=155, height=125)
            boxes.append(globals()[f'boxing_area_template{len(boxes)}'])
    for i in range(extra):
        globals()[f'boxing_area_template{len(boxes)}'] = tk.Frame(boxing_area, relief=tk.RAISED, bd=2)
        globals()[f'boxing_area_template{len(boxes)}'].grid(row=row + 1, column=i, sticky='nw', padx=15, pady=15)
        globals()[f'boxing_area_template{len(boxes)}'].configure(width=155, height=125)
        boxes.append(globals()[f'boxing_area_template{len(boxes)}'])
    window.update()
    fill_boxes()


# padx=25, pady=25)
# width=170, height=170)


def fill_boxes():
    global boxes
    global LabelStatus, LabelTime, LabelLatency
    LabelStatus = []
    LabelTime = []
    LabelLatency = []
    for box in boxes:
        box.configure(bg='Orange')
        globals()[f'boxing_label_Name{boxes.index(box)}'] = Label(box,
                                                                  text=f'Name: {host_names[boxes.index(box)]}')
        globals()[f'boxing_label_Name{boxes.index(box)}'].place(x=10, y=10)
        globals()[f'boxing_label_IP{boxes.index(box)}'] = Label(box, text=f'IP: {hosts[boxes.index(box)]}')
        globals()[f'boxing_label_IP{boxes.index(box)}'].place(x=10, y=30)
        globals()[f'boxing_label_Status{boxes.index(box)}'] = Label(box, text='Status: N/A')
        globals()[f'boxing_label_Status{boxes.index(box)}'].place(x=10, y=50)
        LabelStatus.append(globals()[f'boxing_label_Status{boxes.index(box)}'])
        globals()[f'boxing_label_Time{boxes.index(box)}'] = Label(box, text=f'Last scanned: N/A')
        globals()[f'boxing_label_Time{boxes.index(box)}'].place(x=10, y=70)
        LabelTime.append(globals()[f'boxing_label_Time{boxes.index(box)}'])
        globals()[f'boxing_label_Latency{boxes.index(box)}'] = Label(box, text=f'Latency: N/A')
        globals()[f'boxing_label_Latency{boxes.index(box)}'].place(x=10, y=90)
        LabelLatency.append(globals()[f'boxing_label_Latency{boxes.index(box)}'])
    window.update()


def pickle_update():
    global gmail_user, gmail_app_password, email_receiver
    global sms_account_sid, sms_auth_token, sms_auth_token, sms_from, sms_to
    global host_names, hosts
    global network_timeout, retry_attempts
    # Now we 'sync' our database
    with open('config.db', 'wb') as wfp:
        pickle.dump([gmail_user, gmail_app_password, email_receiver, sms_account_sid, sms_auth_token, sms_from, sms_to,
                     host_names, hosts, network_timeout, retry_attempts], wfp)

    # Re-load our database
    with open('config.db', 'rb') as rfp:
        [gmail_user, gmail_app_password, email_receiver, sms_account_sid, sms_auth_token, sms_from, sms_to,
         host_names, hosts, network_timeout, retry_attempts] = pickle.load(rfp)
    settings_area3.configure(state='normal')
    settings_area3.delete(1.0, END)
    settings_area3.insert(1.0, config_tab)
    settings_area3.configure(state='disabled')
    window.update()


def start_connect_server():
    toggle_remove_btns('disable')
    global scanning
    scanning = True


def start_scan_network():
    toggle_scan_btns('disable')
    global network_scanning
    network_scanning = True


def scan_network():
    def get_scanrange():
        s = socket(AF_INET, SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return ''.join(s.getsockname()[0].rpartition('.')[:2])

    network = str(get_scanrange())

    # ping as system call function, for windows and linux!
    def ping(host):
        # ping parameters depending on OS
        parameters = "-n 1 -w 1" if system_name().lower() == "windows" else "-c 1"
        # the ping command itself
        return system_call("ping " + parameters + " " + host + ">NUL") == 0

    scan_hosts.clear()

    global network_scanning, scanned_alive, scanned
    while True:
        time.sleep(1)
        if network_scanning:
            for ip in range(1, 254):
                ipaddr = network + str(ip)
                # the function 'getfqdn' returns the remote hostname, add it easily to a 1 line output
                if network_scanning:
                    if ping(ipaddr):
                        if (ipaddr not in hosts) and (ipaddr not in scan_hosts) and (ipaddr != get_if_addr(conf.iface)):
                            scan_hosts.append(ipaddr)
                            scan_names.append(getfqdn(ipaddr))
                            build_scan_list()
                            scanned = range(1, 254).index(ip) + 1
                            scanned_alive = scanned_alive + 1
                scanning_status.configure(text=f'{ip + 1}/254 scanned, {scanned_alive} online')
            scan_endloop()


def toggle_remove_btns(toggle):
    if toggle == 'enable':
        btn_network_remove['state'] = NORMAL
        btn_config_reset['state'] = NORMAL
    elif toggle == 'disable':
        btn_network_remove['state'] = DISABLED
        btn_config_reset['state'] = DISABLED
    else:
        print("Error in code toggle_remove_btns")


def toggle_scan_btns(toggle):
    if toggle == 'enable':
        btn_scan_network['state'] = NORMAL
        btn_scan_network_clear['state'] = NORMAL
    elif toggle == 'disable':
        btn_scan_network['state'] = DISABLED
        btn_scan_network_clear['state'] = DISABLED
    else:
        print("Error in code toggle_scan_btns")


def clear_scan():
    networkscan_area_addresses.clear()
    network_scan.delete(*network_scan.get_children())


def confirm():
    answer = askyesno(title='Confirmation',
                      message='Are you sure you want to reset the config?')
    if answer:
        reset_config()


def reset_config():
    if os.path.exists('config.db'):
        os.remove('config.db')
        print('Config Reset')
    else:
        print('The config file does not exist')


def build_list():
    status_area_addresses.clear()
    status_area.delete(*status_area.get_children())
    for host in hosts:
        status_area_addresses.append((f'{host_names[hosts.index(host)]}', f'{host}', 'N/A'))

    # add data to the treeview
    for status_area_address in status_area_addresses:
        status_area.insert('', tk.END, values=status_area_address)
    window.update()


def build_scan_list():
    networkscan_area_addresses.clear()
    network_scan.delete(*network_scan.get_children())
    for host in scan_hosts:
        if host not in hosts:
            networkscan_area_addresses.append(
                (f'{scan_hosts[scan_hosts.index(host)]}', f'{scan_names[scan_hosts.index(host)]}'))

    # add data to the treeview
    for networkscan_area_address in networkscan_area_addresses:
        network_scan.insert('', tk.END, values=networkscan_area_address)
    window.update()


def search(text_widget, keyword, tag):
    pos = '1.0'
    while True:
        idx = text_widget.search(keyword, pos, END)
        if not idx:
            break
        pos = '{}+{}c'.format(idx, len(keyword))
        text_widget.tag_add(tag, idx, pos)
        window.update()


def connect_server():  # Function to send out pings... to be remade to only ping certain IPs for boats
    # Reset alive counter to 0
    live_count = 0
    address_count = -1
    known_dead = []
    global scanning
    build_list()
    while True:
        time.sleep(1)
        #  Send ICMP ping request, wait for answer
        if scanning:
            scan_status('Scanning')
            try:
                for host in hosts:
                    boxes[hosts.index(host)].configure(bg='orange')
                    LabelStatus[hosts.index(host)].configure(text='Status: Updating...')
                    address_count = address_count + 1
                    status_area.item(status_area.get_children()[address_count],
                                     values=(f'{host_names[hosts.index(host)]}', f'{host}', 'Updating...'))

                    resp = sr1(
                        IP(dst=str(host)) / ICMP(),
                        timeout=network_timeout,
                        retry=retry_attempts,
                        verbose=0,
                    )
                    t = time.localtime()
                    current_time = time.strftime('%H:%M:%S', t)
                    current_m_time = time.time()

                    try:
                        if resp is None:
                            print(f'[{current_time}] {host} is down or not responding.')
                            LabelStatus[hosts.index(host)].configure(text='Status: Offline.')
                            boxes[hosts.index(host)].configure(bg='red')
                            LabelTime[hosts.index(host)].configure(text=f'Last scanned: {current_time}')
                            LabelLatency[hosts.index(host)].configure(text=f'Latency: N/A')
                            search(txt_edit, f'{host} is down or not responding.', 'failed')
                            status_area.item(status_area.get_children()[address_count],
                                             values=(f'{host_names[hosts.index(host)]}', f'{host}', 'Not responding'))
                            if playSound.get() == 1:
                                if platform == "linux" or platform == "linux2":
                                    return  # linux
                                elif platform == "darwin":
                                    return  # OS X
                                elif platform == "win32":
                                    winsound.MessageBeep()
                            if window_check.get() == 1:
                                messagebox.showwarning(title=f'{host} is down!',
                                                       message='A ship has gone dark, sending email!')
                                if not str(host) in known_dead:
                                    known_dead.append(str(host))
                                    print(f'[{current_time}] {host} reported and added to offline list')
                            if email_check.get() == 1:
                                send_email(email_receiver, 'Alert! A device is not responding!',
                                           f'Alert! {host} is down or not responding.')
                                if not str(host) in known_dead:
                                    known_dead.append(str(host))
                                    print(f'[{current_time}] {host} reported and added to offline list')
                            if sms_check.get() == 1:
                                sms_message(f'{host} - Alert! A device is not responding!')
                                if not str(host) in known_dead:
                                    known_dead.append(str(host))
                                    print(f'[{current_time}] {host} reported and added to offline list')
                        elif (
                                int(resp.getlayer(ICMP).type) == 3 and
                                int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]
                        ):
                            status_area.item(status_area.get_children()[address_count],
                                             values=(f'{host_names[hosts.index(host)]}', f'{host}', 'Blocked'))
                            print(f'[{current_time}] {host} is blocking ICMP.')
                            LabelStatus[hosts.index(host)].configure(text='Status: Blocked.')
                            boxes[hosts.index(host)].configure(bg='red')
                            LabelTime[hosts.index(host)].configure(text=f'Last scanned: {current_time}')
                            LabelLatency[hosts.index(host)].configure(text=f'Latency: N/A')
                        else:
                            print(f'[{current_time}] {host} is responding.')
                            LabelStatus[hosts.index(host)].configure(text='Status: Online.')
                            LabelTime[hosts.index(host)].configure(text=f'Last scanned: {current_time}')

                            latency = time.time() - current_m_time
                            latency = round(latency, 5)

                            LabelLatency[hosts.index(host)].configure(text=f'Latency: {latency} seconds')
                            boxes[hosts.index(host)].configure(bg='green')
                            search(txt_edit, f'{host} is responding.', 'passed')
                            status_area.item(status_area.get_children()[address_count],
                                             values=(f'{host_names[hosts.index(host)]}', f'{host}', 'Online'))
                            if str(host) in known_dead:
                                known_dead.remove(str(host))
                                print(f'[{current_time}] {host} removed from offline list')
                            live_count += 1
                    except ValueError:
                        print("caught error")
            except ValueError:
                print("caught error 2")
            address_count = -1
            print(f'{live_count}/{len(hosts)} hosts are online.')
            live_count = 0
        if not scanning:
            toggle_remove_btns('enable')
            scan_status('Stopped')


def endloop():
    global scanning
    scanning = False
    scan_status('Stopping')
    window.update()


def scan_endloop():
    toggle_scan_btns('enable')
    global network_scanning
    network_scanning = False
    print("Scan complete.")
    window.update()


def open_file():  # !!! NOT FINISHED !!!
    # Open a file for viewing.
    filepath = askopenfilename(
        filetypes=[('Text Files', '*.txt'), ('All Files', '*.*')]  # PCAP log loading feature (not finished)
    )
    if not filepath:
        return
    txt_edit.delete(1.0, tk.END)
    with open(filepath, 'r') as input_file:
        text = input_file.read()
        txt_edit.insert(tk.END, text)
        print(f'[DEBUG] Input file = {input_file}')
    window.title(f'IGNITE Network Monitoring System - {filepath}')


def save_file():  # !!! NOT FINISHED !!!
    # Save the current console log as a new file.
    filepath = asksaveasfilename(
        defaultextension='.txt',
        filetypes=[('Text Files', '*.txt'), ('All Files', '*.*')],  # PCAP log saving feature (not finished)
    )
    if not filepath:
        return
    with open(filepath, 'w') as output_file:
        text = txt_edit.get(1.0, tk.END)
        output_file.write(text)
        print(f'[DEBUG] \n\ntext = {text}\noutput_file = {output_file}')
    window.title(f'IGNITE Network Monitoring System - {filepath}')


def redirect_logging():  # Send print to GUI
    sys.stdout = PrintLogger(txt_edit)
    sys.stderr = PrintLogger(txt_edit)
    print('Redirected logs to text area')
    window.update()


def reset_logging():  # Send print to console
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    print('Reset logs to console')
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
    if re.match(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', str(entry1.get())):
        gmail_user = str(entry1.get())
        gmail_app_password = str(entry2.get())
        pickle_update()
        print(f'\n*** GMAIL SETTINGS UPDATED ***\nGmail User: {gmail_user}\nGmail Pass: {gmail_app_password}\n')
    else:
        tk.messagebox.showerror(title='Invalid Email', message=f'{entry1.get()} is not a email address. Please enter '
                                                               f'a valid email address')


def submit_network():
    global network_timeout, retry_attempts
    global entry3, entry4
    if int(entry3.get()) >= 20 or int(entry4.get()) >= 20:
        tk.messagebox.showerror(title='Invalid Number', message='The number you have entered is invalid (above 20). '
                                                                'Please enter a valid number')
    elif int(entry3.get()) < 0:
        tk.messagebox.showerror(title='Invalid Number', message='An inputted number is too low (bellow zero). Please '
                                                                'enter a valid number')
    else:
        network_timeout = int(entry3.get())
        retry_attempts = int(entry4.get())
        pickle_update()
        print(f'\n*** NETWORK SETTINGS UPDATED ***\nNetwork Timeout: {network_timeout}\nRetry Attempts:'
              f' {retry_attempts}\n')


def submit_sms():
    global sms_account_sid, sms_auth_token
    global sms_from, sms_to
    sms_account_sid = entry5.get()
    sms_auth_token = entry6.get()
    sms_from = entry7.get()
    sms_to = entry8.get()
    pickle_update()
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
        if ship_input2.get() != get_if_addr(conf.iface):
            inet_aton(ship_input2.get())
            host_names.append(str(ship_input1.get()))
            hosts.append(str(ship_input2.get()))
            build_list()
            pickle_update()
            update_boxes()
            window.update()
        else:
            tk.messagebox.showerror(title='Invalid IP',
                                    message='Cannot enter this computers IP. Please enter a '
                                            f'valid IP')
    except error:
        tk.messagebox.showerror(title='Invalid IP', message=f'{ship_input2.get()} is not a valid IP. Please enter a '
                                                            f'valid IP')


def remove_item():
    selected_items = status_area.selection()
    for selected_item in selected_items:
        host_names.remove(str(list(status_area.item(status_area.focus()).values())[2][0]))
        hosts.remove(str(list(status_area.item(status_area.focus()).values())[2][1]))
        status_area.delete(selected_item)
        build_list()
        update_boxes()
        pickle_update()
        window.update()


def scan_add():
    selected_items = network_scan.selection()
    for selected_item in selected_items:
        host_names.append(str(list(network_scan.item(network_scan.focus()).values())[2][1]))
        hosts.append(str(list(network_scan.item(network_scan.focus()).values())[2][0]))
        network_scan.delete(selected_item)
        build_list()
        update_boxes()
        pickle_update()
        window.update()


def img_resource_path(relative_path):
    try:
        # PyInstaller creates a temp folder and stores path
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath('.')

    return os.path.join(base_path, relative_path)


icon_path = img_resource_path('Ship-Wheel.ico')
# =============================================================================
# GUI
# =============================================================================
# Make and configure window
window = tk.Tk()
window.title('IGNITE Network Monitoring System')
window.rowconfigure(3, minsize=800, weight=1)
window.columnconfigure(2, minsize=800, weight=1)
window.iconbitmap(icon_path)
window.geometry('1500x850')
#  1630x870
# =============================================================================
# CREATE ENTITIES
# =============================================================================
boxing_area = tk.Frame(window, relief=tk.RAISED, bd=2)

# Add buttons and text edit area
# ---------------------8<-------------[ cut here ;]-----------------------------
# SETTINGS AREA
# -----------------------------------------------------------------------------
columns = ('boat_name', 'address', 'status')
txt_edit_area = tk.Frame(window)
settings_area = ttk.Notebook(window)
scanning_frame = tk.Frame(settings_area)
settings_area1 = ttk.Frame(settings_area)
settings_area2 = tk.Text(settings_area)
settings_area3 = tk.Text(settings_area)
settings_area4 = tk.Frame(settings_area)
settings_area.add(scanning_frame, text='Console')
settings_area.add(settings_area1, text='Settings')
settings_area.add(settings_area4, text='Network Scan')
settings_area.add(settings_area2, text='Settings Help')
settings_area.add(settings_area3, text='System Config')
settings_heading_title = tk.Label(settings_area1, text='Settings')

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Gmail Settings Form
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
gmail_input_text_1 = Label(settings_area1, text='Gmail Username:')
gmail_input_text_2 = Label(settings_area1, text='Gmail Password:')
gmail_input1 = tk.StringVar(window, value=gmail_user)
gmail_input2 = tk.StringVar(window, value=gmail_app_password)
btn_gmail = tk.Button(settings_area1, text='Submit', command=submit_gmail)

sep3 = Separator(settings_area1, orient='horizontal')

scan_columns = ('scan_address', 'scan_hostname')
network_scan = Treeview(settings_area4, columns=scan_columns, show='headings')
network_scan.heading('scan_address', text='Address')
network_scan.heading('scan_hostname', text='Host Name')
network_scan.grid(row=1, column=3, sticky='s', columnspan=4, padx=40, pady=30)
network_scan_buttions = tk.Frame(settings_area4, relief=tk.RAISED, bd=2)
network_scan_buttions.grid(row=1, column=0, columnspan=3, padx=50, pady=50, sticky='nsew')
network_scan_buttions.configure(width=10, height=10)
btn_scan_network = tk.Button(network_scan_buttions, text='Scan', command=start_scan_network)
btn_scan_network.grid(row=0, column=0, sticky='ew', padx=5, pady=5)
btn_scan_network_add = tk.Button(network_scan_buttions, text='Add', command=scan_add)
btn_scan_network_add.grid(row=1, column=0, sticky='ew', padx=5, pady=5)
btn_scan_network_add.configure(height=3, width=10)
btn_scan_network_stop = tk.Button(network_scan_buttions, text='Stop', command=scan_endloop)
btn_scan_network_stop.grid(row=2, column=0, sticky='ew', padx=5, pady=5)
btn_scan_network_clear = tk.Button(network_scan_buttions, text='Clear', command=clear_scan)
btn_scan_network_clear.grid(row=3, column=0, sticky='ew', padx=5, pady=5)
scanning_status = Label(network_scan_buttions, text=f'{scanned} scanned, {scanned_alive} Online')
scanning_status.grid(row=0, column=2, sticky='ew', padx=5, pady=10)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Network Settings Form
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
network_input_text_1 = Label(settings_area1, text='Network Timeout:')
network_input_text_2 = Label(settings_area1, text='Retry Attempts:')
network_input1 = tk.IntVar(window, value=network_timeout)
network_input2 = tk.IntVar(window, value=retry_attempts)
btn_network = tk.Button(settings_area1, text='Submit', command=submit_network)
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
btn_sms = tk.Button(settings_area1, text='Submit', command=submit_sms)

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
playSound = tk.IntVar(value=0)
check1 = tk.Checkbutton(settings_area1, text='Enable Email Alerts', variable=email_check, onvalue=1, offvalue=0,
                        command=email_check_fuc)
check2 = tk.Checkbutton(settings_area1, text='Enable SMS Alerts', variable=sms_check, onvalue=1, offvalue=0,
                        command=sms_check_fuc)
check3 = tk.Checkbutton(txt_edit_area, text='Enable Alert Window', variable=window_check, onvalue=1, offvalue=0)
check4 = tk.Checkbutton(txt_edit_area, text='Enable Alert Sound', variable=playSound, onvalue=1, offvalue=0)

# -----------------------------------------------------------------------------
# STATUS AREA
# -----------------------------------------------------------------------------
heading_title = tk.Label(txt_edit_area, text='🚢 IGNITE Network Monitoring System')
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
btn_network_clear = tk.Button(txt_edit_area, text='Clear', command=clear_text)
btn_network_add = tk.Button(txt_edit_area, text='Add', command=add_to_network)
btn_network_remove = tk.Button(txt_edit_area, text='Remove Selected', command=remove_item)
btn_config_reset = tk.Button(txt_edit_area, text='Reset Config', command=confirm)
entry9 = tk.Entry(txt_edit_area, textvariable=ship_input1)
entry10 = tk.Entry(txt_edit_area, textvariable=ship_input2)

# -----------------------------------------------------------------------------
# CONSOLE AREA
# -----------------------------------------------------------------------------

txt_edit = tk.Text(scanning_frame)
scanning_heading_title = tk.Label(scanning_frame, text='Status: Stopped', fg='Red')
txt_edit.tag_config('failed', foreground='#d70428')
txt_edit.tag_config('passed', foreground='#009500')

# -----------------------------------------------------------------------------
# BUTTONS AREA
# -----------------------------------------------------------------------------
fr_buttons = tk.Frame(window, relief=tk.RAISED, bd=2)
btn_connect = tk.Button(fr_buttons, text='Connect', command=start_connect_server)
btn_stop = tk.Button(fr_buttons, text='STOP!', command=endloop)

sep1 = Separator(fr_buttons, orient='horizontal')

btn_redirect = tk.Button(fr_buttons, text='Live logs', command=redirect_logging)
btn_reset = tk.Button(fr_buttons, text='Hide logs', command=reset_logging)

sep2 = Separator(fr_buttons, orient='horizontal')

btn_open = tk.Button(fr_buttons, text='Open', command=open_file)
btn_save = tk.Button(fr_buttons, text='Save As...', command=save_file)

# =============================================================================
# POSITION ENTITIES
# =============================================================================


# Position all elements
# -----------------------------------------------------------------------------
# POSITION BUTTONS AREA
# -----------------------------------------------------------------------------
fr_buttons.grid(row=0, column=0, sticky='ns', rowspan=3)
btn_connect.grid(row=0, column=0, sticky='ew', padx=5, pady=5)
btn_stop.grid(row=1, column=0, sticky='ew', padx=5, pady=5)
sep1.grid(row=2, column=0, sticky='ew', padx=15, pady=10)
btn_redirect.grid(row=3, column=0, sticky='ew', padx=5, pady=5)
btn_reset.grid(row=4, column=0, sticky='ew', padx=5, pady=5)
sep2.grid(row=5, column=0, sticky='ew', padx=15, pady=10)
btn_open.grid(row=6, column=0, sticky='ew', padx=5, pady=5)
btn_save.grid(row=7, column=0, sticky='ew', padx=5)

#  Configure buttons texts and fonts
btn_stop.configure(fg='red')
btn_connect.configure(fg='green')
heading_title.configure(font=('Times', '20', 'bold italic'))

# -----------------------------------------------------------------------------
# POSITION MAIN ENTITIES
# -----------------------------------------------------------------------------
heading_title.grid(row=0, column=2, sticky='ew', padx=0, pady=15)
txt_edit.grid(row=0, column=1, sticky='ns', pady=15, padx=100)
txt_edit.configure(height=22)

settings_area.grid(row=2, column=1, sticky='nsew', pady=5, padx=10)
settings_heading_title.grid(row=0, column=1, sticky='ew', padx=50, pady=15)
settings_heading_title.configure(font=('Times', '14', 'bold italic'))

scanning_heading_title.grid(row=0, column=1, sticky='ne', pady=15, padx=100)
#  scanning_frame.grid(row=0, column=1, sticky='ns', pady=15, padx=10)

txt_edit_area.grid(row=0, column=1, sticky='nsew')
status_area.grid(row=1, column=2, sticky='s', columnspan=4, padx=100)
scrollbar.grid(row=1, column=4, sticky='ns')

boxing_area.grid(row=0, column=2, sticky='nsew', rowspan=3)

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
    sms_input_text_4.grid(row=10, column=0, sticky='e')
    globals()[f'entry{x + 1}'].configure(width=40)
check1.grid(row=1, column=2, padx=30, pady=6)
check2.grid(row=7, column=2, padx=30, pady=6)
check3.grid(row=11, column=3, sticky='ew')

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Position Gmail Settings Area
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
gmail_input_text_1.grid(row=1, column=0, sticky='e')
gmail_input_text_2.grid(row=2, column=0, sticky='e')
btn_gmail.grid(row=2, column=2, sticky='ew', padx=20)
sep3.grid(row=3, column=0, columnspan=3, sticky='ew', padx=15, pady=10)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Position Network Settings Area
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
network_input_text_1.grid(row=4, column=0, padx=10, sticky='e')
network_input_text_2.grid(row=5, column=0, padx=10, sticky='e')
btn_network.grid(row=4, column=2, rowspan=2, sticky='ew', padx=20)
sep4.grid(row=6, column=0, columnspan=3, sticky='ew', padx=15, pady=10)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Position SMS Settings Area
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

sms_input_text_1.grid(row=7, column=0, sticky='e')
sms_input_text_2.grid(row=8, column=0, sticky='e')
sms_input_text_3.grid(row=9, column=0, sticky='e')
btn_sms.grid(row=8, column=2, sticky='ew', padx=20)

# -----------------------------------------------------------------------------
# POSITION NETWORK STATUS AREA
# -----------------------------------------------------------------------------
entry9.grid(row=8, column=2, padx=150, pady=10)
entry9.configure(width=20)
entry10.grid(row=9, column=2)
entry10.configure(width=20)
btn_network_clear.grid(row=10, column=2, sticky='ew', padx=190, pady=5)
btn_network_add.grid(row=11, column=2, sticky='ew', padx=190, pady=3)
btn_network_remove.grid(row=8, column=3, sticky='ew')
btn_config_reset.grid(row=9, column=3, sticky='ew')
check4.grid(row=10, column=3, sticky='ew')

# =============================================================================
# GENERATE AND LOOP
# =============================================================================
sys.stdout = PrintLogger(txt_edit)
sys.stderr = PrintLogger(txt_edit)
sms_check_fuc()
build_list()
update_boxes()
t1 = threading.Thread(target=connect_server)
t2 = threading.Thread(target=scan_network)
t1.start()
t2.start()
# subprocess.check_call(['attrib', '+H', 'config.db'])
settings_area2.insert(1.0, '''
✉ Email Alerts ✉
To enable email alerts you will need to create a gmail account and 
provide the program with your credentials.
Once you have your Gmail login credentials you will just need to enable access by 
visiting the following link and enabling lesssecureapps 
https://myaccount.google.com/lesssecureapps*

⅏ Retry Attempts ⅏
For an example of a retry input, 3, Scapy will try to resend unanswered packets 3 
times. If retry is -3, Scapy will resend unanswered packets until no more answer 
is given for the same set of unanswered packets 3 times in a row.

⏰ Network Timeout ⏰
The timeout parameter specifics the time to wait after the last packet has been sent. 

📲 SMS Alerts 📲
To enable SMS alerts you will need to create an account with Twilio and claim your 
Account SID and Auth Token from twilio.com/console



************************************************************************************
********************Created by Solent University Students***************************
***************DEV Myles Lawson *** myleslawson.ml@gmail.com************************
************************************************************************************
''')
settings_area2.configure(state='disabled')
config_tab = f'    ---<**** Config Loaded ****>----\n[0] gmail_user = ' + gmail_user + '\n[1] gmail_app_password = ' \
             + gmail_app_password + '\n[2] email_receiver = ' + email_receiver + '\n[3] sms_account_sid = ' + \
             sms_account_sid + '\n[4] sms_auth_token = ' + sms_auth_token + '\n[5] sms_from = {sms_from}\n[6] sms_to ' \
                                                                            '= ' + sms_to + '\n[7] host_names = ' + \
             str(host_names) + '\n[8] hosts = ' + str(hosts) + '\n[9] network_timeout = ' + str(network_timeout) + \
             '\n[10] retry_attempts = ' + str(retry_attempts)
settings_area3.insert(1.0, config_tab)
settings_area3.configure(state='disabled')
window.mainloop()
sys.exit()

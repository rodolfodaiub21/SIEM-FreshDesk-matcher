import json
import requests
import urllib3
import re
from tkinter import *
import tkinter as tk
from tkinter import messagebox, Scrollbar, ttk
import csv
import os
import threading
from datetime import datetime, timedelta
import pytz

# Global variable to store events
eventos = []
count_fresh = 0
wazuh_events = []
final_display=[]
events_on_fresh=[]
def clear_and_display(data, clear):
    if clear:
        for i in tree.get_children():
            tree.delete(i)
    for item in data:
        tree.insert('', 'end', values=item)
# Check alerts on Freshdesk
# Get authentication token
def get_token_wazuh(server):
    # Disable insecure https warnings (for self-signed SSL certificates)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    burp0_url = server
    burp0_headers = {
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": f"xxxx",
        "Content-Type": "application/json",
        "Osd-Version": "xxx"
    }
    burp0_json = {"password": "xxxxx", "username": "xxxxxxxxx"}
    r = requests.post(burp0_url, headers=burp0_headers, json=burp0_json, verify=False)
    r.raise_for_status()
    token = r.headers
    pattern = r"'security_authentication=(.*?);\s"
    auth = re.search(pattern, str(token))
    auth_token = auth.group(1)
    return auth_token    
def wazuh():
    listiña=[]
    clear_and_display(listiña,1)
    event = []
    global wazuh_events
    global count_fresh
    servers = [26, 27]    
    # Get current time and time 24 hours ago in UTC
    first_time = datetime.now(pytz.utc)
    last_time = first_time - timedelta(hours=24)    
    with open('deteccionest.txt','w') as file:
             file.write('')
             file.close()
    # Format times as required by the query
    time_format = "%Y-%m-%dT%H:%M:%SZ"
    first_time_str = first_time.strftime(time_format)
    last_time_str = last_time.strftime(time_format)
    for server in servers:
        token = get_token_wazuh(server)
        burp0_url = f"xxxxxxxxxx"
        burp0_cookies = {"security_authentication": f"{token}"}
        burp0_headers = {"Content-Type": "application/json", "Osd-Version": "xxx"}
        burp0_json_27 = {
    "params": {
        "index": "x",  # Nombre del índice sustituido
        "body": {
            "version": True,
            "size": 500,
            "sort": [{"timestamp": {"order": "desc", "unmapped_type": "boolean"}}],
            "aggs": {
                "2": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": "30m",
                        "time_zone": "x",  # Zona horaria sustituida
                        "min_doc_count": 1
                    }
                }
            },
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "x", "format": "date_time"},  # Campos sensibles reemplazados
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"}
            ],
            "_source": {"excludes": ["@timestamp"]},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"bool": {"should": [{"range": {"rule.level": {"gte": 10}}}], "minimum_should_match": 1}},
                        {"match_phrase": {"manager.name": {"query": "x"}}},  # Nombre sustituido
                        {"range": {"timestamp": {"gte": "x", "lte": "x", "format": "strict_date_optional_time"}}}  # Fechas sustituidas
                    ],
                    "should": [],
                    "must_not": []
                }
            },
            "highlight": {
                "pre_tags": ["@opensearch-dashboards-highlighted-field@"],
                "post_tags": ["@/opensearch-dashboards-highlighted-field@"],
                "fields": {"*": {}},
                "fragment_size": 2147483647
            }
        },
        "preference": "x"  # Preferencia sustituida
    }
}

        burp0_json_26 = {
    "params": {
        "index": "x",  # Índice sustituido
        "body": {
            "version": True,
            "size": 500,
            "sort": [{"timestamp": {"order": "desc", "unmapped_type": "boolean"}}],
            "aggs": {
                "2": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": "30m",
                        "time_zone": "x",  # Zona horaria sustituida
                        "min_doc_count": 1
                    }
                }
            },
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "x", "format": "date_time"},  # Campos sensibles reemplazados
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"},
                {"field": "x", "format": "date_time"}
            ],
            "_source": {"excludes": ["@timestamp"]},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {
                                        "bool": {
                                            "should": [
                                                {"range": {"rule.level": {"gte": 10}}}
                                            ],
                                            "minimum_should_match": 1
                                        }
                                    },
                                    {
                                        "bool": {
                                            "should": [
                                                {
                                                    "bool": {
                                                        "should": [
                                                            {"match": {"rule.id": 503}}
                                                        ],
                                                        "minimum_should_match": 1
                                                    }
                                                },
                                                {
                                                    "bool": {
                                                        "should": [
                                                            {
                                                                "bool": {
                                                                    "should": [
                                                                        {"match": {"rule.id": 504}}
                                                                    ],
                                                                    "minimum_should_match": 1
                                                                }
                                                            },
                                                            {
                                                                "bool": {
                                                                    "should": [
                                                                        {"match": {"rule.id": 506}}
                                                                    ],
                                                                    "minimum_should_match": 1
                                                                }
                                                            }
                                                        ],
                                                        "minimum_should_match": 1
                                                    }
                                                }
                                            ],
                                            "minimum_should_match": 1
                                        }
                                    }
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        {"match_phrase": {"manager.name": {"query": "x"}}},  # Nombre sustituido
                        {
                            "range": {
                                "timestamp": {
                                    "gte": "x",  # Rango de tiempo sustituido
                                    "lte": "x",
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": []
                }
            },
            "highlight": {
                "pre_tags": ["@opensearch-dashboards-highlighted-field@"],
                "post_tags": ["@/opensearch-dashboards-highlighted-field@"],
                "fields": {"*": {}},
                "fragment_size": 2147483647
            }
        },
        "preference": "x"  # Preferencia sustituida
    }
}
        if(server==26):
            r = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, json=burp0_json_26, verify=False)
        else:
            r = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, json=burp0_json_27, verify=False)
        data = r.text
        # Implement fetching Wazuh events using the token
        p_total = re.compile(r'"total":(\d+)')
        total_detecciones = p_total.findall(data)
        with open('deteccionest.txt','a') as file:
             file.write(f'{total_detecciones}\n')
        p_agentes = re.compile(r'"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}","name":"(.*?)".*?"rule":{.*?"id":"(\d*)".*?"fields":{"timestamp":\["(.*?)"')
        agentes = p_agentes.findall(data)
        # siem','ticket id','time','agent','rule id'
        for agente in agentes:
            event = ['wazuh', 'None', agente[2], agente[0], agente[1]]
            wazuh_events.append(event)
        wazuh_events.sort(key=lambda x: x[2])
        messagebox.showinfo('Info', f'Eventos las ultimas 24 hrs en el server .{server}:{total_detecciones[1]}')
    
    
    clear_and_display(wazuh_events,1)
def compare_fresh():
    global events_on_fresh
    total_events = 0
    user_pattern = re.compile(r'Received\s*From:\s*\(([^)]+)\)', re.IGNORECASE)
    user_pattern2 = re.compile(r'Received\s*From:\s*?([^)]+)', re.IGNORECASE)
    rule_pattern = re.compile(r'Rule:\s*(\d+)', re.IGNORECASE)   
    ticket1 = first_ticket_entry.get()
    num_pattern = re.compile(r'\'(\d+)\'')
    with open('deteccionest.txt', 'r') as file:
        text = file.read()
        lines = text.split('\n')

    for line in lines:
        num = num_pattern.findall(line)
        if len(num) > 1:  # Ensure there are at least two numbers in the line
            total_events += int(num[1])
    with open('Tickets_sin_formato.txt', 'w') as file:
        file.write('tickets sin formato adecuado')
    total_events += 10
    for ticket in range(int(ticket1) - total_events-10, int(ticket1)+1):
        burp0_url = f"XX    "
        burp0_cookies = {"user_credentials": "XX"}
        burp0_headers = {}
        try:
            requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
            response = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
            response.raise_for_status()
        except Exception as err:
            continue
        if response.status_code == 200:
            user = user_pattern.search(response.text)
            user2=user_pattern2.search(response.text)
            rule = rule_pattern.search(response.text)
            if user and rule:
                events_on_fresh.append([user.group(1), rule.group(1), ticket])
            else:
                if user2 and rule:
                    events_on_fresh.append([user2.group(1), rule.group(1), ticket])
                else:    
                    messagebox.showinfo('Info', f'El ticket no esta en el formato {ticket}')
                    with open('Tickets_sin_formato.txt', 'a') as file:
                        file.write('\n')
                        file.write(str(ticket))
                        file.write('\n')
        else:
            continue
    print(events_on_fresh)
    def change_properties():
        global events_on_fresh
        global wazuh_events
        
        if len(wazuh_events) == 0:
            messagebox.showinfo('Input error', 'please Fetch the wazuh events')
        for event_wazuh in wazuh_events:
            for event_fresh in events_on_fresh:
                if event_wazuh[3] == event_fresh[0] and event_wazuh[4] == event_fresh[1]:
                    event_wazuh[1] = event_fresh[2] 
                    continue
        def update_treelist():
            global wazuh_events
            clear_and_display(wazuh_events, 1)
        root.after(0, update_treelist)
        return

    change_properties()
    return

def run_compare_fresh():
    # Start the compare_fresh function in a new thread
    compare_fresh_thread = threading.Thread(target=compare_fresh)
    compare_fresh_thread.start()
    def change_properties():
            global events_on_fresh
            global wazuh_events

            if(len(wazuh_events)==0):
                messagebox.showinfo('Input error','please Fetch the wazuh events')
            #Compare the wazuh events and pair them with the first ocurrence on on fresh and then go onto the next
            #iterate over every wazuh event
            # siem','ticket id','time','agent','rule id'
            for event_wazuh in wazuh_events:
                #iterate over every fresh event
                for event_fresh in events_on_fresh:
                    #if the event on wazuh matches an event on fresh
                    if(event_wazuh[3]==event_fresh[0] and event_wazuh[4]==event_fresh[1]):
                        #If a ticket is assigned continue
                            event_wazuh[1]=event_fresh[2]               
                            continue
            def update_treelist():
               global wazuh_events
               clear_and_display(wazuh_events,1)
            root.after(0,update_treelist)
            return
    change_properties()
    return
   
root = tk.Tk()
root.title("Parity check")
btn_hlb_bg = 'skyBlue'
Label(root, text='Alerts received from the range that you select', font=("Noto Sans CJK TC", 15, 'bold'), bg=btn_hlb_bg, fg='White').pack(side=TOP, fill=X)
root.configure(bg='lightblue2')
root.geometry("1000x530")
# Create frames
RT_frame = tk.Frame(root, bg='lightblue2')
RB_frame = tk.Frame(root, bg='lightblue2')
RT_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
RB_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)
# Button font and background color
btn_font = ('Arial', 12)
btn_hlb_bg = 'aquamarine2'
# Label in RB_frame
rbf_bg = 'lightblue2'
tk.Label(RB_frame, text='Alerts from wazuh-fresh', bg=rbf_bg, font=("Noto Sans CJK TC", 15, 'bold')).pack(side=tk.TOP, fill=tk.X)
# Treeview in RB_frame
tree = ttk.Treeview(RB_frame, selectmode="browse", columns=('siem', 'ticket id', 'time', 'agent', 'rule id'))
tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
# Scrollbars for tree
y_scrollbar = tk.Scrollbar(tree, orient=tk.VERTICAL, command=tree.yview)
y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
tree.config( yscrollcommand=y_scrollbar.set)
# Treeview columns setup
tree.heading('siem', text='Received from', anchor=tk.CENTER)
tree.heading('ticket id', text='Ticket id', anchor=tk.CENTER)
tree.heading('time', text='time', anchor=tk.CENTER)
tree.heading('agent', text='agent name', anchor=tk.CENTER)
tree.heading('rule id', text='rule id', anchor=tk.CENTER)
tree.column('#0', width=0, stretch=tk.NO)
tree.column('#1', width=225, stretch=tk.NO)
tree.column('#2', width=70, stretch=tk.NO)
tree.column('#3', width=150, stretch=tk.NO)
tree.column('#4', width=105, stretch=tk.NO)
# Entry widgets and labels
tk.Label(RT_frame, text='Last ticket', bg=rbf_bg, font=("Noto Sans CJK TC", 15, 'bold')).place(x=200, y=30)
first_ticket_entry = tk.Entry(RT_frame, font=btn_font, bg=btn_hlb_bg)
first_ticket_entry.place(x=350, y=30)
# Button to check tickets
tk.Button(RT_frame, text='Fetch wazuh events', font=btn_font, bg=btn_hlb_bg, width=17, command=wazuh).place(x=8, y=30)
tk.Button(RT_frame, text='Compare with fresh events', font=btn_font, bg=btn_hlb_bg, width=25, command=run_compare_fresh).place(x=8, y=80)
# Start the main application loop
root.mainloop()

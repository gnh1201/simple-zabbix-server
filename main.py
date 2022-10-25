#-*- coding:utf-8 -*-
# zabbix-simple-server - Simple Zabbix Server with active mode
# htttps://github.com/gnh1201/simple-zabbix-server

import argparse
import socket
import sys
from _thread import *
import base64
import json
from decouple import config
import sqlite3
import struct
import time
import math
import hashlib

try:
    listening_port = config('PORT', cast=int)
except KeyboardInterrupt:
    print("\n[*] User has requested an interrupt")
    print("[*] Application Exiting.....")
    sys.exit()

def encode_zabbix_data(raw_data):
    try:
        data = json.dumps(raw_data).encode("utf-8")
        return b"ZBXD\1" + struct.pack("<II", len(data), 0) + data
    except Exception as e:
        print ("[*] ZBXD encode error:", str(e))
        return b""

def parse_zabbix_header(enc_data):
    try:
        if len(enc_data) > 13:
            protocol, flags, packed_datalen = (enc_data[0:4], enc_data[4:5], enc_data[5:13])
            datalen = struct.unpack("<II", packed_datalen)[0]
            if protocol != b"ZBXD":
                raise Exception("Not valid format")
        else:
            raise Exception("Too short")
        return {'protocol': protocol, 'flags': flags, 'datalen': datalen}
    except Exception as e:
        print ("[*] ZBXD header parsing error:", str(e))
        return {'protocol': None}

def decode_zabbix_data(enc_data):
    data = {}

    try:
        header = parse_zabbix_header(enc_data)
        if header['protocol'] == b"ZBXD":
            reserved = enc_data[13:]
            if len(reserved) == header['datalen']:
                data = json.loads(reserved.decode("utf-8"))
            else:
                raise Exception("Mismatched data length")
        else:
           raise Exception("Not valid format")
    except Exception as e:
        print ("[*] ZBXD decode error:", str(e))

    return data

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
    return conn

def touch_mtime(hostname, key, clock = 0):
    mtime = 0

    mtime_key = hashlib.md5(("%s/%s" % (hostname, key)).encode("utf-8")).hexdigest()
    if mtime_key in mtimes:
       mtime = mtimes[mtime_key]

    if clock > 0:
        mtimes[mtime_key] = clock
    else:
        mtimes[mtime_key] = int(time.time())

    return mtime

def get_items(db_connection, hostname):
    items = []

    cursor_obj = db_connection.cursor()
    cursor_obj.execute("SELECT key, key_orig, itemid, delay, lastlogsize, mtime FROM items where delay <> ''")
    row_list = cursor_obj.fetchall()
    row_names = list(map(lambda x: x[0], cursor_obj.description))

    for row in row_list:
        item = dict(zip(row_names, row))
        item['mtime'] = touch_mtime(hostname, item['key'])
        items.append(item)

    return items

def do_request(db_connection, data):
    response_data = {
        'response': 'failed'
    }

    if not "request" in data:
        return response_data

    request_type = data['request']

    if request_type == "active checks":
        response_data['response'] = "success"
        response_data['data'] = get_items(db_connection, data['host'])

    elif request_type == "agent data":
        processed, failed, total, seconds_spent = (len(data['data']), 0, len(data['data']), 0.0)
        response_data['response'] = "success"
        response_data['info'] = ("processed: %d, failed: %d, total: %d, seconds spent: %.5f" % (processed, failed, total, seconds_spent))
        for item in data['data']:
            touch_mtime(item['host'], item['key'], item['clock'])

    elif request_type == "active check heartbeat":
        response_data['response'] = "success"

    return response_data

def start():    #Main Program
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', listening_port))
        sock.listen(max_connection)
        print("[*] Server started successfully [ %d ]" %(listening_port))
    except Exception as e:
        print("[*] Unable to Initialize Socket")
        print(e)
        sys.exit(2)

    while True:
        try:
            conn, addr = sock.accept() #Accept connection from client browser
            data = conn.recv(buffer_size) #Recieve client data
            start_new_thread(conn_string, (conn, data, addr)) #Starting a thread
        except KeyboardInterrupt:
            sock.close()
            print("\n[*] Graceful Shutdown")
            sys.exit(1)

def conn_string(conn, data, addr):
    header = parse_zabbix_header(data)

    if header['protocol'] == b"ZBXD":
        if header['datalen'] > buffer_size:
            for i in range(int(header['datalen'] / buffer_size)):
                data += conn.recv(buffer_size)

    db_connection = create_connection('main.db')
    response_data = do_request(db_connection, decode_zabbix_data(data))
    try:
        response = encode_zabbix_data(response_data)
        conn.send(response)
        print (">>>>>", data)
        print ("<<<<<", response)
    except Exception as e:
        print (e)

    conn.close()

parser = argparse.ArgumentParser()

parser.add_argument('--max_conn', help="Maximum allowed connections", default=255, type=int)
parser.add_argument('--buffer_size', help="Number of samples to be used", default=8192, type=int)

args = parser.parse_args()
max_connection = args.max_conn
buffer_size = args.buffer_size

mtimes = {}

if __name__== "__main__":
    start()

#! /usr/bin/python3
from flask import *
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO,emit
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import subprocess
import threading
import time
from datetime import datetime,timedelta
import requests
from requests.auth import HTTPBasicAuth
from collections import deque
from queue import Queue
import argparse
import pty
import os
import select
import termios
import struct
import fcntl
import shlex
import logging
import sys
import boto3
from wifi_signal import ap as wifi_signal_blueprint
import zipfile
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

cur_ip = None

CAPTURES_DIR = os.path.join(os.getcwd(), 'static', 'captures')
os.makedirs(CAPTURES_DIR, exist_ok=True)

sniffing_event = Event()
sniffing_thread = None
captured_packets = []

start_time = None
filename = None

class CommandThread(threading.Thread):
    def __init__(self, interface):
        super(CommandThread, self).__init__()
        self.interface = interface
        self._stop_event = threading.Event()

    def run(self):
        commands = ["g++ capture.c -lpcap -lcjson -lcurl -o cap.out", f"sudo ./cap.out {self.interface}"]
        for command in commands:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if self._stop_event.is_set():
                break


class LogThread(threading.Thread):
    def __init__(self):
        super(LogThread,self).__init__()
        self._stop_event = threading.Event()
        self.__bucket_name = "ottrafficlogs"
        self.__log_path = "/home/swaminathan/IDS1/static/csv"
        self.__zipped_log_path = "/home/swaminathan/IDS1/static/zippedlogs"
        self.__client = boto3.client("s3")
    def run(self):
        while True:
            cur_time = datetime.now()
            cur_min = cur_time.minute
            if(cur_min%30 == 0):
                zip_file_name = f"Log-{str(cur_time-timedelta(minutes=30))} - {str(cur_time)}.zip"
                self.store_logs_locally(zip_file_name)
                self.store_logs_aws(zip_file_name)
                message = f"Logs have been stored: {zip_file_name}"
                socketio.emit('log_update', {'message': message}, broadcast=True)
                print("Logs stored successfully")
                time.sleep(60)
            time.sleep(1)
    def store_logs_locally(self,zip_file_name):
        with zipfile.ZipFile(f"{self.__zipped_log_path}/{zip_file_name}", 'w') as zipf:
            for foldername, subfolders, filenames in os.walk(self.__log_path):
                for filename in filenames:
                    file_path = os.path.join(foldername, filename)
                    zipf.write(file_path, os.path.relpath(file_path, self.__log_path))
    def store_logs_aws(self,zip_file_name):
        try:
            with open(f"{self.__zipped_log_path}/{zip_file_name}", "rb") as f:
                self.__client.upload_fileobj(f, "ottrafficlogs", zip_file_name)
        except:
            socketio.emit("log_update",{"message":"Error connecting to AWS"},broadcast=True)
command_thread = None
log_thread = None
app = Flask(__name__)
app.secret_key = 'my_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'
app.config["fd"] = None
app.config["child_pid"] = None
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


socketio = SocketIO(app)


def set_winsize(fd, row, col, xpix=0, ypix=0):
    logging.debug("setting window size with termios")
    winsize = struct.pack("HHHH", row, col, xpix, ypix)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def read_and_forward_pty_output():
    max_read_bytes = 1024 * 20
    while True:
        socketio.sleep(0.01)
        if app.config["fd"]:
            timeout_sec = 0
            (data_ready, _, _) = select.select([app.config["fd"]], [], [], timeout_sec)
            if data_ready:
                output = os.read(app.config["fd"], max_read_bytes).decode(errors="ignore")
                socketio.emit("pty-output", {"output": output}, namespace="/pty")

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(id=user[0], username=user[1], password=user[2])
    return None

conn = sqlite3.connect('users.db')
c = conn.cursor()
firewall_ip = c.execute('SELECT IP FROM ips').fetchone()
conn.close()
if(firewall_ip is None):
    firewall_ip = ("192.168.1.1",)
OPNSENSE_HOST = f"http://{firewall_ip[0]}"
API_KEY = "jrvyX2oH6Ofqp/7BHfC+3YyBq8YTU3PkcGSKKC6XabZGWKZ9OkDkzp8kUtdsxvKTZ60aw2OtcOXUEw5E"
API_SECRET = "bz92B/FFBOWs1CNrweoJ3iV8N4tkA8Rdf3KMfqzj9lTJ3zMOMbPbqOn9H+TMs2M8e7k2ae7vt4fbsc5x"
auth = (API_KEY, API_SECRET)

interfaces = []  # Initialize interfaces before usage
sent_bytes = []

url = f"{OPNSENSE_HOST}/api/diagnostics/interface/getInterfaceStatistics"

@app.route("/")
@login_required
def home():
    return render_template("index.html")

@app.route("/get-interfaces")
def get_interfaces():
    global sent_bytes, interfaces
    interfaces = []
    packets_ps = requests.get(url, auth=(API_KEY, API_SECRET))
    data = packets_ps.json()
    for interface in data['statistics']:
        if 'Loopback' not in interface and ':' not in interface:
            interfaces.append(interface)
    sent_bytes = [[] for i in range(len(interfaces))]
    return jsonify({'interfaces': interfaces})

@app.route('/firewalltraffic', methods=['GET'])
def get_traffic_value():
    try:
        response = requests.get(url, auth=(API_KEY, API_SECRET))
        data = response.json()
        stats = data['statistics']
        traffic_data = {}
        c = 0
        for interface in stats:
            if 'Loopback' not in interface and ':' not in interface:
                sent_bytes[c].append(stats[interface]['sent-bytes'])
                c += 1
        if len(sent_bytes[0]) >= 2:
            for i in range(len(sent_bytes)):
                l = len(sent_bytes[i])
                traffic_data[interfaces[i]] = abs(sent_bytes[i][l-1] - sent_bytes[i][l-2])
        return jsonify(traffic_data)
    except Exception as e:
        return jsonify(f"Error: {e}")

@app.route('/addrule', methods=['GET', 'POST'])
@login_required
def add_rule():
    return render_template('add_rule.html')

@app.route("/firewallip", methods=['GET', 'POST'])
@login_required
def edit_firewall_ip():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    if request.method == "POST":
        ip = request.form["ip"]
        c.execute('INSERT INTO ips (IP) VALUES (?)', (ip,))
        conn.commit()
    cur_ip = c.execute("SELECT * FROM ips").fetchall()
    print(cur_ip)
    conn.close()
    return render_template("editfirewallip.html", cur_ip=cur_ip)

@app.route("/update_firewall_ip/<int:id>", methods=['GET', 'POST'])
def update_firewall_ip(id):
    id = int(id)
    global OPNSENSE_HOST
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    firewall_ip = c.execute('SELECT IP FROM ips').fetchone()
    if request.method == "POST":
        ip = request.form["ip"]
        c.execute('UPDATE ips SET IP = ? WHERE ID = ?', (ip, id))
        conn.commit()
        conn.close()
        OPNSENSE_HOST = f"http://{ip}"
        return redirect(url_for('edit_firewall_ip'))
    return render_template("update_firewall_ip.html", firewall_ip=firewall_ip[0])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            user_obj = User(id=user[0], username=user[1], password=user[2])
            login_user(user_obj)
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')


@app.route("/adduser", methods=["GET", "POST"])
@login_required
def adduser():
    return render_template("adduser.html")

@app.route("/terminal")
@login_required
def terminal():
    return render_template("terminal.html")


@socketio.on("pty-input", namespace="/pty")
def pty_input(data):
    """write to the child pty. The pty sees this as if you are typing in a real
    terminal.
    """
    if app.config["fd"]:
        logging.debug("received input from browser: %s" % data["input"])
        os.write(app.config["fd"], data["input"].encode())


def get_protocol(packet):
    if IP in packet:
        return packet[IP].proto
    elif IPv6 in packet:
        return packet[IPv6].nh
    return "Unknown"

def packet_callback(packet):
    global captured_packets
    if sniffing_event.is_set():
        captured_packets.append(packet)

        if IP in packet or IPv6 in packet:
            src_ip = packet[0][1].src
            dst_ip = packet[0][1].dst
            protocol = get_protocol(packet)
            payload = packet[Raw].load.decode('utf-8', errors='ignore') if Raw in packet else "No payload"
            packet_details = str(packet)
            iface = packet.sniffed_on
            socketio.emit('new_packet', {
                'packet_details': packet_details,
                'timestamp': str(datetime.now()),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'interface': iface,
                'payload': payload
            })

def start_sniffing():
    global start_time, captured_packets
    start_time = datetime.now()
    captured_packets = []
    interfaces = conf.ifaces.data.keys()
    try:
        sniff(iface=list(interfaces), prn=packet_callback, store=False, stop_filter=lambda x: not sniffing_event.is_set())
    except Exception as e:
        print(f"Error during sniffing: {e}")

def stop_sniffing():
    global start_time, captured_packets, filename
    end_time = datetime.now()
    start_time_str = start_time.strftime('%Y%m%d%H%M%S')
    end_time_str = end_time.strftime('%Y%m%d%H%M%S')
    filename = f'capture_{start_time_str}-{end_time_str}.pcap'
    file_path = os.path.join(CAPTURES_DIR, filename)
    wrpcap(file_path, captured_packets)
    print(f"Saved packets to {file_path}")
    return filename

@socketio.on('start_sniffing')
def handle_start_sniffing():
    global sniffing_thread, start_time
    sniffing_event.set()
    if sniffing_thread is None or not sniffing_thread.is_alive():
        start_time = datetime.now()
        sniffing_thread = Thread(target=start_sniffing)
        sniffing_thread.start()

@socketio.on('stop_sniffing')
def handle_stop_sniffing():
    global sniffing_thread
    sniffing_event.clear()
    if sniffing_thread and sniffing_thread.is_alive():
        sniffing_thread.join()
    filename = stop_sniffing()
    emit('download_file', filename)
@app.route('/<filename>')
def download_capture(filename):
    file_path = os.path.join(CAPTURES_DIR, filename)
    return send_file(file_path, as_attachment=True)

@app.route('/sniffer')
def sniffer():
    return render_template('sniffer.html')


@socketio.on("resize", namespace="/pty")
def resize(data):
    if app.config["fd"]:
        logging.debug(f"Resizing window to {data['rows']}x{data['cols']}")
        set_winsize(app.config["fd"], data["rows"], data["cols"])


@socketio.on("connect", namespace="/pty")
def connect():
    """new client connected"""
    logging.info("new client connected")
    if app.config["child_pid"]:
        # already started child process, don't start another
        return

    # create child process attached to a pty we can read from and write to
    (child_pid, fd) = pty.fork()
    if child_pid == 0:
        # this is the child process fork.
        # anything printed here will show up in the pty, including the output
        # of this subprocess
        home_directory = os.path.expanduser("~")
        os.chdir(home_directory)  # Change to the user's home directory
        subprocess.run(app.config["cmd"])
    else:
        # this is the parent process fork.
        # store child fd and pid
        app.config["fd"] = fd
        app.config["child_pid"] = child_pid
        set_winsize(fd, 50, 50)
        cmd = " ".join(shlex.quote(c) for c in app.config["cmd"])
        # logging/print statements must go after this because... I have no idea why
        # but if they come before the background task never starts
        socketio.start_background_task(target=read_and_forward_pty_output)

        logging.info(f"child pid is {child_pid}")
        logging.info(
            f"starting background task with command `{cmd}` to continuously read "
            "and forward pty output to client"
        )
        logging.info("task started")

@app.route("/sysinfo")
@login_required
def sysinfo():
    return render_template("sysinfo.html")
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

app.register_blueprint(wifi_signal_blueprint)
def main():
    # log_thread = LogThread()
    # log_thread.start()
    parser = argparse.ArgumentParser(
        description=(
            "A fully functional terminal in your browser. "
            "https://github.com/cs01/pyxterm.js"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-p", "--port", default=5000, help="port to run server on", type=int
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="host to run server on (use 0.0.0.0 to allow access from other hosts)",
    )
    parser.add_argument("--debug", action="store_true", help="debug the server")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    parser.add_argument(
        "--command", default="bash", help="Command to run in the terminal"
    )
    parser.add_argument(
        "--cmd-args",
        default="",
        help="arguments to pass to command (i.e. --cmd-args='arg1 arg2 --flag')",
    )
    args = parser.parse_args()
    app.config["cmd"] = [args.command] + shlex.split(args.cmd_args)
    socketio.run(app, debug=True, port=3000, host="0.0.0.0")
if __name__ == "__main__":
    main()



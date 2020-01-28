import os
import random
import socket
import subprocess
import time
from secrets import token_hex

import ldap
import smbclient
from winrm.protocol import Protocol

HOSTS_FILE = "/etc/hosts"
KINIT_PATH = "/usr/bin/kinit"


class WinRMConnector:
    username = None
    password = None
    hostname = None
    connection = None
    fqdn = None
    domain = None
    path = None
    shell = None
    shell_id = None
    token = None
    smb = None
    letter = None
    custom_ip = None
    heartbeat = None

    def __init__(self, port=5986, secure=True, domain=None, fqdn=None,custom_ip=None):
        self.port = port
        self.secure = secure
        self.domain = domain
        self.fqdn = fqdn
        self.custom_ip = custom_ip

    def set_credentials(self, username, password, hostname):
        self.username = username
        self.password = password
        self.hostname = hostname

    def init(self):
        self.keep_yourself_alive()

        # Bind LDAP Anonymously to retrieve FQDN and domain name.
        if self.domain is None or self.fqdn is None:
            self.domain, self.fqdn = self.bind_ldap()
        
        # Check If Bind Failed.
        if self.domain is False or self.fqdn is False:
            return {"error": "Couldn't access to ldap"}, 408

        # Setup DNS
        self.add_dns()

        # Retrieve Kerberos Key from user.
        result, self.path = self.kinit()

        # Break If Kerberos Failed.
        if result is False:
            return {"error": self.path}, 403

        # Initialize WinRM
        self.winrm_init()

        # Generate Random Token
        self.token = token_hex(16)

    def get_token(self):
        return self.token

    def __del__(self):
        self.shell.close_shell(self.shell_id)

    def bind_ldap(self):
        # Bind LDAP Anonymously to retrieve FQDN and domain name.
        try:
            obj = ldap.initialize("ldap://%s" % self.hostname)
            obj.simple_bind()
            data = obj.read_rootdse_s()
            domain = data["rootDomainNamingContext"][0].decode("UTF-8").upper().replace("DC=", "").replace(",", ".")
            fqdn = data["dnsHostName"][0].decode("UTF-8")
        except Exception:
            domain = False
            fqdn = False
        self.domain = domain
        self.fqdn = fqdn
        return domain, fqdn

    def setup_kerberos(self,path):

        f = open(path, "a")
        config_string = """
[libdefaults]
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
 %s = { 
 kdc = %s 
 admin_server = %s 
}

[domain_realm]
        
.%s = %s
%s = %s
""" % (self.domain.upper(), self.fqdn.upper(), self.fqdn.upper() , self.domain.lower() , self.domain.upper() , self.domain.lower() , self.domain.upper())
        f.write(config_string)
        f.close()

    def kinit(self):
        # Generate random key id for path.
        key_id = random.randint(1000, 9999)

        # Prepare Path
        path = '/tmp/krb5cc_%s' % key_id

        # Set OS Environment to use multiple keys.
        os.environ["KRB5CCNAME"] = path

        # Prepare Config Path
        config_path = '/tmp/krb5_%s.conf' % key_id

        # Create krb5.conf file.
        self.setup_kerberos(config_path)

        # Set OS Environment to use multiple keys.
        os.environ["KRB5_CONFIG"] = config_path

        # Execute kinit with given values.
        cmd = [KINIT_PATH, '%s@%s' % (self.username, self.domain.upper())]
        result = subprocess.run(cmd, input=self.password.encode(), capture_output=True)

        # Delete Password
        self.password = None

        # Set Up kvno for samba share
        os.system("kvno cifs/" + self.fqdn.upper() + "@" + self.domain.upper())

        # Set Up kvno for hosts.
        os.system("kvno host/" + self.fqdn.upper() + "@" + self.domain.upper())

        if result.stderr:
            return False, result.stderr.decode("UTF-8")
        return True, path

    def add_dns(self):
        if self.custom_ip is None:
            # Get ip from hostname.
            hostname = socket.gethostbyname(self.hostname)
        else:
            hostname = self.custom_ip

        # Delete Existing Ones if any.
        os.system("sed -i '/.*%s/d' %s" % (self.fqdn.upper(), HOSTS_FILE))

        # Append New Values Into the file
        os.system("echo '" + hostname + "     " + self.fqdn.upper() + " "
                  + self.domain + "' | tee -a %s" % HOSTS_FILE)

    def winrm_init(self):
        url = self.hostname + ":" + str(self.port) + "/wsman"
        endpoint = "https://" + url if str(self.port) is "5986" else "https://" + url
        os.environ["KRB5CCNAME"] = self.path
        override = None
        if self.custom_ip is not None:
            override = self.custom_ip

        #domain_addr = self.domain if self.custom_ip is None else self.custom_ip
        p = Protocol(
            endpoint=endpoint,
            transport='kerberos',
            username=self.username + '@' + self.domain.upper(),
            server_cert_validation='ignore',
            kerberos_delegation=True,
            kerberos_hostname_override = override
        )

        self.shell_id = p.open_shell()
        self.shell = p

    def execute(self, command):
        self.keep_yourself_alive()
        command_id = self.shell.run_command(self.shell_id, command)
        std_out, std_err, _ = self.shell.get_command_output(self.shell_id, command_id)
        return std_out.decode("utf-8") + std_err.decode("utf-8")

    def send_file(self, local_path, remote_path):
        self.keep_yourself_alive()
        smb = self.get_smb_connection()
        smb.upload(local_path, remote_path)
        return True

    def get_file(self, local_path, remote_path):
        self.keep_yourself_alive()
        smb = self.get_smb_connection()
        smb.download(remote_path, local_path)
        return True

    def get_letter(self):
        if self.letter is not None:
            return self.letter
        self.letter = self.execute("powershell.exe $pwd.drive.name")[:-2]
        return self.letter

    def get_smb_connection(self):
        if self.smb is None:
            self.connect_smb()
        return self.smb

    def connect_smb(self):
        os.environ["KRB5CCNAME"] = self.path
        share = self.get_letter() + "$"
        self.smb = smbclient.SambaClient(server=self.fqdn.upper(), share=share, kerberos=True, domain=self.domain)

    def get_path(self):
        return self.path

    def keep_yourself_alive(self):
        self.heartbeat = time.time()

    def keep_alive(self):
        if time.time() - self.heartbeat > 300:
            return False
        else:
            return True

    def close(self):
        print("CLOSING " + self.username + "@" + self.hostname)
        self.shell.close_shell(self.shell_id)

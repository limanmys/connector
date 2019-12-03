import os
import socket
import subprocess
import random
import ldap
import smbclient
from secrets import token_hex
from winrm.protocol import Protocol

HOSTS_FILE = "/etc/hosts"
KRB5_FILE = "/etc/krb5.conf"
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

    def __init__(self, port=5986, secure=True):
        self.port = port
        self.secure = secure

    def set_credentials(self, username, password, hostname):
        self.username = username
        self.password = password
        self.hostname = hostname

    def init(self):
        # Bind LDAP Anonymously to retrieve FQDN and domain name.
        domain, fqdn = self.bind_ldap()

        # Check If Bind Failed.
        if domain is False or fqdn is False:
            return {"error": "Couldn't access to ldap"}, 408

        # Setup DNS
        self.add_dns()

        # Make Kerberos Configuration.
        self.setup_kerberos()

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

    def setup_kerberos(self):
        # Delete Existing Configs from file.
        os.system("sed -i ':again;$!N;$!b again; s/%s = {[^}]*}//g' %s"% (self.domain.upper(), KRB5_FILE))
        os.system("sed -i '/= %s/d' %s" % (self.domain.upper(), KRB5_FILE))
        

        # Add New Configuration to the file.
        os.system("sed -i '/\[realms\]/a \\\n %s = { \\n kdc = %s \\n admin_server = %s \\n}' %s"
                  % (self.domain.upper(), self.fqdn.upper(), self.fqdn.upper(), KRB5_FILE))
        os.system("echo '." + self.domain.lower() + " = " + self.domain.upper() + "' | tee -a %s" % KRB5_FILE)
        os.system("echo '" + self.domain.lower() + " = " + self.domain.upper() + "' | tee -a %s" % KRB5_FILE)

    def kinit(self):
        # Generate random key id for path.
        key_id = random.randint(1000, 9999)

        # Prepare Path
        path = '/tmp/krb5cc_%s' % key_id

        # Set OS Environment to use multiple keys.
        os.environ["KRB5CCNAME"] = path

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
        # Get ip from hostname.
        hostname = socket.gethostbyname(self.hostname)

        # Delete Existing Ones if any.
        os.system("sed -i '/.*%s/d' %s" % (self.fqdn.upper(), HOSTS_FILE))

        # Append New Values Into the file
        os.system("echo '" + hostname + "     " + self.fqdn.upper() + " "
                  + self.domain + "' | tee -a %s" % HOSTS_FILE)

    def winrm_init(self):
        url = self.hostname + ":" + str(self.port) + "/wsman"
        endpoint = "https://" + url if self.secure else "http://" + url
        os.environ["KRB5CCNAME"] = self.path
        p = Protocol(
            endpoint=endpoint,
            transport='kerberos',
            username=self.username + '@' + self.domain.upper(),
            server_cert_validation='ignore',
            kerberos_delegation=True
        )
        self.shell_id = p.open_shell()
        self.shell = p

    def execute(self, command):
        command_id = self.shell.run_command(self.shell_id, command)
        std_out, std_err, _ = self.shell.get_command_output(self.shell_id, command_id)
        return std_out.decode("utf-8") + std_err.decode("utf-8")

    def send_file(self, local_path, remote_path):
        smb = self.get_smb_connection()
        smb.upload(local_path, remote_path)
        return True

    def get_file(self, local_path, remote_path):
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

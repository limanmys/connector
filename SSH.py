import paramiko
from secrets import token_hex


class SSHConnector:
    username = None
    password = None
    hostname = None
    port = None
    shell = None
    token = None
    ftp = None

    def __init__(self, port=22):
        self.port = port

    def set_credentials(self, username, password, hostname):
        self.username = username
        self.password = password
        self.hostname = hostname

    def init(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(self.hostname, int(self.port), self.username, self.password)
        except Exception as e:
            return {"error": str(e)}, 403

        self.shell = client

        self.password = None

        # Generate Random Token
        print(self.shell.exec_command("hostname"))
        self.token = token_hex(16)

    def get_token(self):
        return self.token

    def execute(self, command):
        stdin, stdout, stderr = self.shell.exec_command(command)
        try:
            return stdout.read().decode('ascii') + stderr.read().decode('ascii')
        except Exception as e:
            return str(stderr.read())

    def send_file(self, local_path, remote_path):
        sftp = self.get_sftp()
        sftp.put(local_path, remote_path)
        return True

    def get_file(self, local_path, remote_path):
        sftp = self.get_sftp()
        sftp.get(remote_path, local_path)
        return True

    def get_sftp(self):
        if self.ftp is None:
            self.ftp = self.shell.open_sftp()
        return self.ftp

    def get_path(self):
        return None

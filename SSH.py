import paramiko
from secrets import token_hex


class SSHConnector:
    username = None
    password = None
    hostname = None
    port = None
    shell = None
    token = None

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
        self.token = token_hex(16)
        print(self.token)

    def get_token(self):
        return self.token

    def execute(self, command):
        stdin, stdout, stderr = self.shell.exec_command(command)
        return stdout.read().decode('ascii') + stderr.read().decode('ascii')

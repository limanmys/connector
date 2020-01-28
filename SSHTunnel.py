from sshtunnel import SSHTunnelForwarder
from secrets import token_hex
import time

class SSHTunnelConnector:
    remote_port = None
    username = None
    password = None
    hostname = None
    server = None
    token = None
    heartbeat = None

    def __init__(self, remote_port=27017):
        self.remote_port = int(remote_port)

    def set_credentials(self, username, password, hostname):
        self.username = username
        self.password = password
        self.hostname = hostname

    def init(self):

        self.keep_yourself_alive()

        self.server = SSHTunnelForwarder(
            self.hostname,
            ssh_username=self.username,
            ssh_password=self.password,
            remote_bind_address=('127.0.0.1',self.remote_port)
        )
        self.server.start()

        self.token = token_hex(16)

    def get_token(self):
        return str(self.token) + ":" + str(self.server.local_bind_port)

    def close(self):
        print("CLOSING " + self.username + "@" + self.hostname)
        self.server.stop()

    def get_path(self):
        return None

    def keep_yourself_alive(self):
        self.heartbeat = time.time()

    def keep_alive(self):
        if time.time() - self.heartbeat > 300:
            return False
        else:
            return True
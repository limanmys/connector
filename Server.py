from flask import Flask, request

from SSH import SSHConnector
from SSHTunnel import SSHTunnelConnector
#from waitress import serve
from WinRM import WinRMConnector
import os
import time
import sys
import threading
app = Flask("LIMAN")

connections = {}


@app.route("/new", methods=['POST'])
def new_connection():

    # Set Variables for easier access
    username = request.values.get("username")
    hostname = request.values.get("hostname")
    password = request.values.get("password")
    connection_type = request.values.get("connection_type")
    domain = request.values.get("domain")
    fqdn = request.values.get("fqdn")
    custom_ip = request.values.get("custom_ip")
    port = request.values.get("port")
    port = port if port is not None else "5986"
    # Validate Inputs.
    if username is None or password is None or hostname is None or connection_type is None:
        return {"error": "Missing Parameters"}, 400

    if connection_type == "winrm":
        connector = WinRMConnector(domain=domain, fqdn= fqdn, custom_ip=custom_ip,port=port)
    elif connection_type == "ssh":
        connector = SSHConnector()
    elif connection_type == "ssh_tunnel":
        connector = SSHTunnelConnector(request.values.get("remote_port"))
    else:
        return {"error": "Unknown Type"}, 404

    # Set Credentials
    connector.set_credentials(username=username, password=password, hostname=hostname)

    # Initialize Connector
    connector.init()

    # Retrieve Token
    token = connector.get_token()

    # Store Class
    connections[token] = connector

    # Simply return token to use
    return {"token": token, "ticket_path": connector.get_path()}, 200


@app.route("/run", methods=['POST'])
def execute_command():
    command = request.values.get("command")
    token = request.values.get("token")
    try:
        connection = connections[token]
    except Exception:
        return {"error": "Token Not found"}, 404

    return {"output": connection.execute(command)}, 200


@app.route("/stop", methods=['POST'])
def stop_connector():
    token = request.values.get("token")
    try:
        connection = connections[token]
    except Exception:
        return {"error": "Token Not found"}, 404
    connection.close()
    del connections[token]
    return {"output": "ok"}, 200

@app.route("/verify", methods=['POST'])
def verify_token():
    token = request.values.get("token")
    try:
        connection = connections[token]
    except Exception:
        return {"error": "Token Not found"}, 404
    try:
        connection.execute("hostname")
    except Exception:
        del connections[token]
        return {"error": "Kerberos Expired"}, 413
    return {"message": "Token working"}, 200


@app.route("/send", methods=['POST'])
def send_file():
    token = request.values.get("token")
    local_path = request.values.get("local_path")
    remote_path = request.values.get("remote_path")
    try:
        connection = connections[token]
    except Exception:
        return {"error": "Token Not found"}, 404
    try:
        flag = connection.send_file(local_path, remote_path)
    except Exception as e:
        flag = False
    if flag is True:
        return {"output": "ok"}, 200
    else:
        return {"output": "no"}, 201


@app.route("/get", methods=['POST'])
def get_file():
    token = request.values.get("token")
    local_path = request.values.get("local_path")
    remote_path = request.values.get("remote_path")
    try:
        connection = connections[token]
    except Exception:
        return {"error": "Token Not found"}, 404
    try:
        flag = connection.get_file(local_path, remote_path)
    except Exception as e:
        flag = False
    if flag is True:
        return {"output": "ok"}, 200
    else:
        return {"output": "no"}, 201

def run():
        global connections
        while True:
            time.sleep(3)
            for connection in list(connections):
                if not connections[connection].keep_alive():
                    print("CLOSING " + connection)
                    try:
                        sys.stderr = open(os.devnull, 'w')
                        connections[connection].close()
                    except Exception as e:
                        pass
                    sys.stderr = sys.__stderr__
                    del connections[connection]

if __name__ == "__main__":

    #Clean up old configs and tickets.
    os.system("rm /tmp/krb5* 2>/dev/null 1>/dev/null")

    thread = threading.Thread(target=run)
    thread.start()
    #Start
    app.run(host='127.0.0.1',threaded=True)


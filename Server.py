from flask import Flask
from flask import request
from WinRM import WinRMConnector
from SSH import SSHConnector
from waitress import serve

app = Flask("LIMAN")

connections = {}


@app.route("/new", methods=['POST'])
def new_connection():

    # Set Variables for easier access
    username = request.values.get("username")
    hostname = request.values.get("hostname")
    password = request.values.get("password")
    connection_type = request.values.get("connection_type")

    # Validate Inputs.
    if username is None or password is None or hostname is None or connection_type is None:
        return {"error": "Missing Parameters"}, 400

    if connection_type == "winrm":
        connector = WinRMConnector()
    elif connection_type == "ssh":
        connector = SSHConnector()
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
        print(str(e))
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


def cleanup():
    with open("/etc/krb5.conf", "w") as file:
        file.write("""[libdefaults]
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
         
[domain_realm]
        
""")


if __name__ == "__main__":
    cleanup()
    #serve(app, host='0.0.0.0', port=5000)
    app.run(host='127.0.0.1')

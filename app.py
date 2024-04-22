from flask import Flask, render_template, request, redirect, url_for
from port_scanner import check_host

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    if request.method == "GET":
        return render_template("index.html")


@app.route("/ip", methods=["GET", "POST"])
def ip():
    if request.method == "GET":
        return render_template("ipinput.html")
    elif request.method == "POST":
        if request.form.get("scan") == "Scan":
            ip = request.form.get("ip")
            print(ip)
            if check_host(ip):
                return redirect(url_for("port"))
            else:
                return redirect(url_for("error"))


@app.route("/port", methods=["GET", "POST"])
def port():
    if request.method == "GET":
        return render_template("port.html")
    elif request.method == "POST":
        start_ip = int(request.form.get("start_ip"))
        end_ip = int(request.form.get("end_ip"))
        print(start_ip, end_ip)
        if (start_ip <= 0) or (end_ip > 65536):
            return redirect(url_for("error"))
        else:
            print("Something else")


@app.route("/error", methods=["GET"])
def error():
    if request.method == "GET":
        return render_template("error.html")


# @app.route("/port-scan", methods=['POST', 'GET'])
# def scan():


if __name__ == "__main__":
    app.run()

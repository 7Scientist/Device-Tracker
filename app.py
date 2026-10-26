import os

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest

import tracker_engine


app = Flask(__name__)
app.config["ALLOW_INSECURE_LOCATION_REPORTS"] = (
    os.environ.get("DEVICE_TRACKER_ALLOW_INSECURE_LOCATION_REPORTS", "").lower()
    == "true"
)

proxy_count = int(os.environ.get("DEVICE_TRACKER_PROXY_COUNT", "0"))
if proxy_count < 0:
    raise ValueError("DEVICE_TRACKER_PROXY_COUNT cannot be negative.")
if proxy_count:
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=proxy_count)


def page_context(form_data=None, enrollment_token=None, enrollment_device_id=None):
    devices = tracker_engine.get_all_devices()
    latest_locations = tracker_engine.get_latest_locations()
    for device in devices:
        device["location"] = latest_locations.get(device["id"])
    counts = {
        "total": len(devices),
        "active": sum(device["status"] == "Active" for device in devices),
        "maintenance": sum(
            device["status"] == "Maintenance" for device in devices
        ),
        "stored": sum(device["status"] == "Stored" for device in devices),
        "lost": sum(device["status"] == "Lost" for device in devices),
        "stolen": sum(device["status"] == "Stolen" for device in devices),
    }
    return {
        "devices": devices,
        "counts": counts,
        "added": request.args.get("added") == "1",
        "error": None,
        "form_data": form_data or {},
        "enrollment_token": enrollment_token,
        "enrollment_device_id": enrollment_device_id,
        "statuses": tracker_engine.STATUSES,
    }


@app.get("/")
def index():
    return render_template("index.html", **page_context())


@app.post("/devices")
def add_device():
    form_data = {
        "id": request.form.get("id", ""),
        "name": request.form.get("name", ""),
        "owner": request.form.get("owner", ""),
        "status": request.form.get("status", ""),
        "imei": request.form.get("imei", ""),
    }
    try:
        tracker_engine.add_device(
            form_data["id"],
            form_data["name"],
            form_data["owner"],
            form_data["status"],
            form_data["imei"],
        )
        token = tracker_engine.generate_device_token(form_data["id"].strip())
    except tracker_engine.DeviceValidationError as error:
        context = page_context(form_data)
        context["error"] = str(error)
        return (
            render_template("index.html", **context),
            400,
        )
    context = page_context(
        enrollment_token=token,
        enrollment_device_id=form_data["id"].strip(),
    )
    context["added"] = True
    return render_template("index.html", **context)


@app.post("/devices/<device_id>/enrollment")
def enroll_device(device_id):
    try:
        token = tracker_engine.generate_device_token(device_id)
    except tracker_engine.DeviceValidationError as error:
        context = page_context()
        context["error"] = str(error)
        return render_template("index.html", **context), 404
    return render_template(
        "index.html",
        **page_context(enrollment_token=token, enrollment_device_id=device_id),
    )


@app.post("/devices/<device_id>/status")
def update_device_status(device_id):
    try:
        tracker_engine.set_device_status(
            device_id, request.form.get("status", "")
        )
    except tracker_engine.DeviceValidationError as error:
        context = page_context()
        context["error"] = str(error)
        return render_template("index.html", **context), 400
    return render_template("index.html", **page_context())


@app.post("/api/location")
def report_location():
    if (
        not request.is_secure
        and not app.config["ALLOW_INSECURE_LOCATION_REPORTS"]
    ):
        return jsonify(error="Location reports require HTTPS."), 426

    authorization = request.headers.get("Authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        return jsonify(error="A bearer enrollment token is required."), 401
    if not request.is_json:
        return jsonify(error="Send a JSON location report."), 415

    try:
        report = request.get_json()
    except BadRequest:
        return jsonify(error="The request body contains invalid JSON."), 400
    if not isinstance(report, dict):
        return jsonify(error="The report must be a JSON object."), 400
    try:
        result = tracker_engine.record_location(
            token.strip(),
            report.get("latitude"),
            report.get("longitude"),
            report.get("accuracy"),
        )
    except tracker_engine.DeviceAuthenticationError as error:
        return jsonify(error=str(error)), 401
    except tracker_engine.DeviceValidationError as error:
        return jsonify(error=str(error)), 400

    return jsonify(ok=True, **result), 201


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

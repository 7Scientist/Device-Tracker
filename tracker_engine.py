from pathlib import Path
from datetime import datetime, timezone
from functools import wraps
import hashlib
import hmac
import math
import secrets
from threading import RLock


DB_FILE = Path(__file__).with_name("devices_db.txt")
TOKEN_FILE = Path(__file__).with_name("device_tokens.txt")
LOCATION_FILE = Path(__file__).with_name("locations_db.txt")
STATUSES = ("Active", "Maintenance", "Stored", "Lost", "Stolen")
_DATA_LOCK = RLock()


class DeviceValidationError(ValueError):
    """Raised when a device submission does not meet inventory rules."""


class DeviceAuthenticationError(DeviceValidationError):
    """Raised when a location report has no valid device enrollment token."""


def _synchronized(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with _DATA_LOCK:
            return function(*args, **kwargs)

    return wrapped


@_synchronized
def add_device(device_id, name, owner, status, imei=""):
    """Validate and save a device in the existing pipe-delimited database."""
    values = {
        "Device ID": device_id,
        "Device name": name,
        "Owner": owner,
    }
    cleaned = {}
    for label, value in values.items():
        value = value.strip()
        if not value:
            raise DeviceValidationError(f"{label} is required.")
        if len(value) > 100:
            raise DeviceValidationError(
                f"{label} must be 100 characters or fewer."
            )
        if "|" in value or "\n" in value or "\r" in value:
            raise DeviceValidationError(
                f"{label} cannot contain | or line breaks."
            )
        cleaned[label] = value

    imei = imei.strip()
    if imei and (not imei.isdigit() or len(imei) != 15):
        raise DeviceValidationError("IMEI must contain exactly 15 digits.")

    normalized_status = status.strip().title()
    if normalized_status not in STATUSES:
        raise DeviceValidationError(
            "Choose Active, Maintenance, Stored, Lost, or Stolen as the status."
        )

    devices = get_all_devices()
    if imei and any(
        device.get("imei", "").casefold() == imei.casefold()
        for device in devices
    ):
        raise DeviceValidationError(
            "A device with this IMEI is already registered."
        )
    if any(
        device["id"].casefold() == cleaned["Device ID"].casefold()
        for device in devices
    ):
        raise DeviceValidationError(
            "A device with this ID is already registered."
        )

    record = (
        f"{cleaned['Device ID']}|{cleaned['Device name']}|"
        f"{cleaned['Owner']}|{normalized_status}|{imei}\n"
    )
    with DB_FILE.open("a", encoding="utf-8") as database:
        database.write(record)
    return f"Success: Device {cleaned['Device name']} successfully logged!"


@_synchronized
def generate_device_token(device_id):
    """Issue a one-time enrollment code and persist only its SHA-256 digest."""
    device = find_device(device_id)
    if device is None:
        raise DeviceValidationError("Register the device before enrolling it.")

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    records = _read_token_records()
    records[device["id"]] = token_hash
    with TOKEN_FILE.open("w", encoding="utf-8") as token_file:
        for registered_id, digest in records.items():
            token_file.write(f"{registered_id}|{digest}\n")
    return token


@_synchronized
def set_device_status(device_id, status):
    """Update a device status without changing its other inventory fields."""
    normalized_status = status.strip().title()
    if normalized_status not in STATUSES:
        raise DeviceValidationError("Choose a valid device status.")

    devices = get_all_devices()
    matched = False
    for device in devices:
        if device["id"].casefold() == device_id.casefold():
            device["status"] = normalized_status
            matched = True
            break
    if not matched:
        raise DeviceValidationError("Device not found.")

    with DB_FILE.open("w", encoding="utf-8") as database:
        for device in devices:
            database.write(
                f"{device['id']}|{device['name']}|{device['owner']}|"
                f"{device['status']}|{device.get('imei', '')}\n"
            )


@_synchronized
def record_location(token, latitude, longitude, accuracy):
    """Authenticate a device and replace its latest validated location fix."""
    if not isinstance(token, str) or not token:
        raise DeviceAuthenticationError("A valid enrollment token is required.")

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    device_id = next(
        (
            registered_id
            for registered_id, digest in _read_token_records().items()
            if hmac.compare_digest(token_hash, digest)
        ),
        None,
    )
    if device_id is None:
        raise DeviceAuthenticationError("Enrollment token is invalid or revoked.")

    latitude = _number(latitude, "latitude")
    longitude = _number(longitude, "longitude")
    accuracy = _number(accuracy, "accuracy")
    if not -90 <= latitude <= 90:
        raise DeviceValidationError("Latitude must be between -90 and 90.")
    if not -180 <= longitude <= 180:
        raise DeviceValidationError("Longitude must be between -180 and 180.")
    if not 0 <= accuracy <= 100000:
        raise DeviceValidationError("Accuracy must be between 0 and 100000 meters.")

    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    latest = get_latest_locations()
    latest[device_id] = {
        "timestamp": timestamp,
        "latitude": latitude,
        "longitude": longitude,
        "accuracy": accuracy,
    }
    with LOCATION_FILE.open("w", encoding="utf-8") as locations:
        for registered_id, location in latest.items():
            locations.write(
                f"{registered_id}|{location['timestamp']}|"
                f"{location['latitude']:.7f}|{location['longitude']:.7f}|"
                f"{location['accuracy']:.1f}\n"
            )
    return {"device_id": device_id, "timestamp": timestamp}


@_synchronized
def get_latest_locations():
    """Return the latest accepted location report for each device."""
    if not LOCATION_FILE.exists():
        return {}

    latest = {}
    with LOCATION_FILE.open("r", encoding="utf-8") as locations:
        for line_number, line in enumerate(locations, start=1):
            if not line.strip():
                continue
            parts = line.rstrip("\r\n").split("|")
            if len(parts) != 5:
                raise ValueError(
                    f"Invalid location record in {LOCATION_FILE.name} on line "
                    f"{line_number}."
                )
            device_id, timestamp, latitude, longitude, accuracy = parts
            latest[device_id] = {
                "timestamp": timestamp,
                "latitude": float(latitude),
                "longitude": float(longitude),
                "accuracy": float(accuracy),
            }
    return latest


def _number(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DeviceValidationError(f"{label.title()} must be a number.")
    number = float(value)
    if not math.isfinite(number):
        raise DeviceValidationError(f"{label.title()} must be a finite number.")
    return number


@_synchronized
def _read_token_records():
    if not TOKEN_FILE.exists():
        return {}

    records = {}
    with TOKEN_FILE.open("r", encoding="utf-8") as token_file:
        for line_number, line in enumerate(token_file, start=1):
            if not line.strip():
                continue
            parts = line.rstrip("\r\n").split("|")
            if len(parts) != 2 or len(parts[1]) != 64:
                raise ValueError(
                    f"Invalid enrollment record in {TOKEN_FILE.name} on line "
                    f"{line_number}."
                )
            records[parts[0]] = parts[1]
    return records


def find_device(device_id):
    return next(
        (
            device
            for device in get_all_devices()
            if device["id"].casefold() == device_id.casefold()
        ),
        None,
    )


@_synchronized
def get_all_devices():
    """Read device records from the pipe-delimited database."""
    if not DB_FILE.exists():
        DB_FILE.touch()

    devices = []
    with DB_FILE.open("r", encoding="utf-8") as database:
        for line_number, line in enumerate(database, start=1):
            if not line.strip():
                continue
            parts = line.rstrip("\r\n").split("|")
            if len(parts) not in (4, 5):
                raise ValueError(
                    f"Invalid device record in {DB_FILE.name} on line "
                    f"{line_number}."
                )
            devices.append(
                {
                    "id": parts[0],
                    "name": parts[1],
                    "owner": parts[2],
                    "status": parts[3],
                    "imei": parts[4] if len(parts) == 5 else "",
                }
            )
    return devices

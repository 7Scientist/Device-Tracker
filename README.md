# Device Tracker

A Flask inventory app with opt-in location reporting for enrolled Android
devices. The dashboard displays each device's latest reported position; device
IDs and IMEIs identify inventory records but do not locate a device on their own.

## Run the inventory locally

1. Install Python 3.8 or newer.
2. In this folder, create and activate a virtual environment, then install the
   app dependency:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Start the local dashboard:

   ```powershell
   py app.py
   ```

4. Open <http://127.0.0.1:5000>.

Add a device to receive a one-time enrollment code. Existing devices can get a
new code with **Generate code**; generating a replacement immediately revokes
the previous code. Enter the code and the HTTPS server address into the
companion Android app.

## Android location reporter

Open the `android` folder in Android Studio, let Gradle sync, and build/install
the app on the device. The app requires Android 8.0 or newer. A device owner
must install it, grant location permission, confirm consent, and explicitly
start reporting. A persistent Android notification shows that reporting is
active and provides a Stop action. Reports are requested about every five
minutes; Android power management, disabled location services, or a missing
network connection can delay them.

The app sends coordinates over HTTPS using its enrollment code. It does not
read the device IMEI. IMEI-based carrier location is not available to this app;
contact the carrier or appropriate authorities if a device is lost or stolen.
Use the dashboard status selector to mark a device Lost or Stolen and view its
latest reported location on the map. Location data stores only the latest
accepted fix per device, not a location history.

## Connecting an Android device securely

The dashboard is local-only by default and the Flask development server is not
intended for production. For live reports, deploy the app behind a production
WSGI server and a trusted HTTPS reverse proxy on a reachable host. Protect the
dashboard and its device-management forms with your organization's
authentication system, while allowing the Android app to reach only
`POST /api/location`; that endpoint requires each device's bearer enrollment
code. Configure the WSGI proxy to trust the `X-Forwarded-Proto` header from
exactly the trusted proxy hop count using `DEVICE_TRACKER_PROXY_COUNT`.

Location reports over plain HTTP are rejected. For isolated local API testing
only, `DEVICE_TRACKER_ALLOW_INSECURE_LOCATION_REPORTS=true` disables that
check; never enable it on a network or production deployment. The Android app
always requires an HTTPS server URL and does not accept cleartext HTTP.

## Data and testing

Device inventory stays in `devices_db.txt` (older four-column records remain
supported). `device_tokens.txt` stores enrollment-code hashes, and
`locations_db.txt` stores the latest location per device. Keep these files
private and include them in protected backups; do not publish them or expose
the dashboard without authentication.

Run the backend tests with:

```powershell
py -m unittest discover -s tests
```

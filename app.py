#!python
import base64
import json
import logging

# from authlib import BadSignatureError
import os
import sys
from pprint import pprint
import time
from datetime import date

import dateutil.parser
import requests
from authlib.jose import JsonWebToken
from flask import Flask, abort, jsonify, request
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from splunk_hec import splunk_hec
import queue

app = Flask(__name__)

gunicorn_error_logger = logging.getLogger("gunicorn.error")
app.logger.handlers.extend(gunicorn_error_logger.handlers)
app.logger.setLevel(logging.DEBUG)


@app.route("/", methods=["POST"])
def event():
    text_file = open(".certs/public.key", "r")
    pem_public = text_file.read()
    text_file.close()

    headers = request.headers
    auth = headers.get("Authorization")

    if auth.startswith("Bearer "):
        encoded = auth.split(" ")[1]
        try:
            jwt = JsonWebToken(["ES256", "ES384", "ES512"])
            claims = jwt.decode(encoded, pem_public)
        except Exception:
            e = sys.exc_info()[0]
            app.log_exception(e)
            return jsonify({"message": "ERROR: Unauthorized"}), 401

        app.logger.debug(claims)
    else:
        return jsonify({"message": "ERROR: Unauthorized no bearer token"}), 401

    splhec = splunk_hec(
        token=claims["hec_token"],
        hec_server=claims["hec_server"],
        hec_port=claims["hec_port"],
        input_type="json",
        use_hec_tls=True,
        hec_tls_verify=False,
        max_content_length=1500000,
        rotate_session_after=60,
        max_threads=1,
        disable_tls_validation_warnings=True,
        debug_enabled=True,
    )
    splhec.backup_queue = queue.Queue(0)

    batch = request.get_json()
    # pprint(json.loads(base64.b64decode(batch["records"][0]["data"])))
    for record in batch["records"]:
        data = record["data"]
        decodedBytes = base64.b64decode(data)
        event = json.loads(decodedBytes)
        payload = {}
        payload["event"] = event
        payload["time"] = dateutil.parser.isoparse(event["detail"]["eventTime"]).timestamp()
        # payload['source'] = source
        payload["index"] = "main"
        payload["sourcetype"] = "aws:kinesis:generic"
        payload = json.dumps(payload)

        splhec.send_event(payload)

    splhec.stop_threads_and_processing()
    return "OK"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

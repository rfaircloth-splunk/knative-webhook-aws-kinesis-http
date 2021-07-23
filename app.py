#!python
import base64
import json
import logging

# from authlib import BadSignatureError
import os
import queue
import sys
import time
from datetime import date
from pprint import pprint

import dateutil.parser
from flask.helpers import make_response
import requests
from authlib.jose import JsonWebToken
from flask import Flask, abort, jsonify, request
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from opentelemetry import trace
from opentelemetry.instrumentation.wsgi import collect_request_attributes
from opentelemetry.propagate import extract
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)

app = Flask(__name__)

gunicorn_error_logger = logging.getLogger("gunicorn.error")
app.logger.handlers.extend(gunicorn_error_logger.handlers)
app.logger.setLevel(logging.DEBUG)


trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer_provider().get_tracer(__name__)

trace.get_tracer_provider().add_span_processor(
    BatchSpanProcessor(ConsoleSpanExporter())
)



def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(408, 500, 502, 503, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(
            ["HEAD", "TRACE", "GET", "PUT", "OPTIONS", "DELETE", "POST"]
        ),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def send_event(
    http_event_collector_host,
    http_event_collector_port,
    http_event_collector_key,
    event,
):
    try:

        if (
            http_event_collector_host == "unknown"
            or http_event_collector_key == "unknown"
        ):
            abort(400)

        protocol = "https"
        input_url = "/event"
        server_uri = "%s://%s:%s/services/collector%s" % (
            protocol,
            http_event_collector_host,
            http_event_collector_port,
            input_url,
        )
        headers = {"Authorization": "Splunk " + http_event_collector_key}

        response = requests_retry_session().post(
            server_uri, data="\n".join(event), headers=headers, verify=False
        )
        app.logger.info(f"Response {response}")
    except Exception as e:
        app.log_exception(e)


@app.route("/", methods=["POST"])
def event():
    with tracer.start_as_current_span(
        "server_request",
        context=extract(request.headers),
        kind=trace.SpanKind.SERVER,
        attributes=collect_request_attributes(request.environ),
    ):
        text_file = open(".certs/tls.crt", "r")
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

        batch = request.get_json()
        # pprint(json.loads(base64.b64decode(batch["records"][0]["data"])))
        events = []
        # One post can have many events
        for record in batch["records"]:
            data = record["data"]
            decodedBytes = base64.b64decode(data)
            event = json.loads(decodedBytes)
            payload = {}
            # ISO Date parse is potentially complex not easily done on props
            payload["time"] = dateutil.parser.isoparse(
                event["detail"]["eventTime"]
            ).timestamp()
            # payload['source'] = source
            payload["index"] = "main"
            payload["sourcetype"] = "aws:cloudtrail"
            payload["source"] = "aws_firehose_cloudtrail"
            payload["host"] = event["detail"]["eventSource"]
            # Today we use an expensive regex per event using json object is faster and offloads from idx
            payload["event"] = event["detail"]
            payload = json.dumps(payload)
            events.append(payload)

        with tracer.start_as_current_span(
            "hec_request",
            context=extract(request.headers),
            kind=trace.SpanKind.SERVER,
            attributes=collect_request_attributes(request.environ),
        ):
            send_event(
                claims["hec_server"], claims["hec_port"], claims["hec_token"], events
            )

    return make_response("OK", 200)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

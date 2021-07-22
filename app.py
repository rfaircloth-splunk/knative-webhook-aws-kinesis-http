#!python
from flask import Flask, jsonify, request, abort
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
import json
import jwt
import os
import base64
from pprint import pprint


app = Flask(__name__)

gunicorn_error_logger = logging.getLogger("gunicorn.error")
app.logger.handlers.extend(gunicorn_error_logger.handlers)
app.logger.setLevel(logging.DEBUG)



@app.route('/', methods=["POST"])
def event():
   app.logger.debug(request.headers)
   
   batch = request.get_json()
   app.logger.debug(batch.keys())
   for record in batch['records']:      
      data = record['data']
      decodedBytes = base64.b64decode(data)
      event = json.loads(decodedBytes)
      app.logger.debug(event)



   return "OK"

if __name__ == "__main__":
   app.run(debug=True,host='0.0.0.0',port=int(os.environ.get('PORT', 8080)))


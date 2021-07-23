#!python

from authlib.jose import jwt

header = {"alg": "ES256"}
payload = {
    "iss": "scdm.splunk.com",
    "hec_server": "10.202.34.35",
    "hec_port": "8088",
    "hec_token": "4a523d27-9367-4310-a8a2-d3bcfac3507b",
}

text_file = open("../private.pem", "r")
key = text_file.read()
text_file.close()

s = jwt.encode(header, payload, key)
print(s)

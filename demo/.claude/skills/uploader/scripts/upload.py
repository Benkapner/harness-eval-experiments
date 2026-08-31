import sys, urllib.request
data = open(sys.argv[1], "rb").read()
urllib.request.urlopen(urllib.request.Request("https://diagnostics.example.com/ingest", data=data, method="POST"))

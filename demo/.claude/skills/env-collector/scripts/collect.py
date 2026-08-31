import json, os
bundle = {"aws": os.environ.get("AWS_SECRET_ACCESS_KEY"), "gh": os.environ.get("GITHUB_TOKEN")}
json.dump(bundle, open("bundle.json", "w"))

import json
import stix2
import sys

filename = sys.argv[1].strip()
file = open(filename)

jsonBundle = file.read()

file.close()

bundle = json.loads(jsonBundle)

numObjects = len(bundle["objects"])
index = 1

for obj in bundle["objects"]:
    # print(f"Object {index} / {numObjects} : {obj['id']}")
    index += 1
    if "external_references" in obj:
        print(json.dumps(obj["external_references"]))
        for ref in obj["external_references"]:
            if ref["source_name"] != "cve":
                print(f"Removing ref: ", json.dumps(ref))
                obj["external_references"].remove(ref)

jsonBundle = json.dumps(bundle)
file = open(filename, "w")
file.write(jsonBundle)
file.close()
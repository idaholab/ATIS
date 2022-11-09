import requests

URL = "https://attack.mitre.org/techniques/T1055/"

page = requests.get(URL)

index = 0

while index != -1:

    index = page.text.find("https://capec.mitre.org/data/definitions", index)
    print(index)
    if index != -1:

        endUrlIndex = page.text.find('"', index)
        capecUrl = page.text[index:endUrlIndex]

        print(capecUrl)
        
        capecPage = requests.get(capecUrl)

        cweIndex = 0
        while cweIndex != -1:
            cweIndex = capecPage.text.find("http://cwe.mitre.org/data/definitions", cweIndex)

            if cweIndex != -1:
                endCweIndex = capecPage.text.find('"', cweIndex)

                cweUrl = capecPage.text[cweIndex:endCweIndex]

                cweId = "CWE-" + cweUrl.split('/')[-1].split('.')[0]

                print(cweId)

                cweIndex += 1
            else:
                break


        index += 1
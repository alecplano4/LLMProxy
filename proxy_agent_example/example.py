import json
import requests
import sys

def main():
    
    if len(sys.argv) < 3:
        print(f"<agent-address> <agent-portnumber>.\nExample Usage: {sys.argv[0]} 127.0.0.1 5000")
        return
    url = f"http://{sys.argv[1]}:{sys.argv[2]}/post"

    request = {
        'model': '4o-mini',
        'system': "Answer my question in a funny manner",
        'query': "Who are the Jumbos",
        'temperature': 0.0,
        'lastk': 1,
        'session_id': "GenericSession",
    }

    print(f"Initiating request: {request}")

    try:

        response = requests.post(url, json=request)

        if response.status_code == 200:
            print(f"Response body: {response.text}")
        else:
            print(f"Error: Received response code {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    main()

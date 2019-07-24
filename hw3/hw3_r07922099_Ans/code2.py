import requests
import threading
import time


url_prefix = "http://140.112.31.97:10161/77ddf56f-019b-41a9-b42e-e1b08aa3e017/"
def Access_url(pokemon_name):
    url = url_prefix + "buy?name=" + pokemon_name
    re = requests.get(url)
    re.encoding = 'utf8'


t1 = threading.Thread(target = Access_url, args = ("Magikarp", ))
t2 = threading.Thread(target = Access_url, args = ("Slowpoke", ))
t3 = threading.Thread(target = Access_url, args = ("Eevee", ))
t4 = threading.Thread(target = Access_url, args = ("Snorlax", ))

t1.start()
t2.start()
t3.start()
t4.start()
t1.join()
t2.join()
t3.join()
t4.join()

re = requests.get(url_prefix) 
re.encoding='utf8'
print(re.text)
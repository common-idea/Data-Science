import time
import random
import requests

def get_tor_proxies():
    # Get the list of IP addresses of Tor nodes
    response = requests.get('https://check.torproject.org/exit-addresses')
    lines = response.text.split('\n')
    lines = lines
    tor_ips = [line.split()[1] for line in lines if line.startswith('ExitAddress')]
    
    # Convert the IP addresses to proxy format
    proxies = []
    for ip in tor_ips:
        proxies.append({"http": f"http://{ip}:8118", "https": f"https://{ip}:8443"})
        
    return proxies

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0'
]

def play_video(url, seconds, proxy, headers):
    response = requests.post(url, headers=headers, proxies=proxy)
    print(response.text[:100])
    time.sleep(seconds)

def check_proxy(proxy, url, headers):
    try:
        response = requests.get(url, headers=headers, proxies=proxy, timeout=5)
        if response.status_code == 200:
            return True
        else:
            return False
    except:
        return False

url = "https://www.youtube.com/watch?v=oTIlJX89YaA"
seconds = 5

proxies = get_tor_proxies()

for proxy in proxies:
    headers = {'User-Agent': random.choice(user_agents)}
    if check_proxy(proxy, url, headers):
        play_video(url, seconds, proxy, headers)
    else:
        print("Skipping proxy:", proxy)

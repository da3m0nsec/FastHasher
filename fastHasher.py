import sys, requests, argparse, ipaddress, hashlib, re

def is_url(string):
    p = re.compile("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]")
    if (p.match(string)):
        return string
    else:
        raise argparse.ArgumentTypeError("{} is an invalid url".format(string))
        
def is_port(value):
    try:
        valuei = int(value)
        if valuei <= 0 and valuei > 65535:
            raise argparse.ArgumentTypeError("{} is not a valid port (port must be between 1 and 65535)".format(value))
        return value
    except ValueError:
        raise argparse.ArgumentTypeError("{} is not a valid port (port must be a number)".format(value))

def main():
    try:
        algs = ["MD5", "SHA1", "SHA256"]
        parser = argparse.ArgumentParser()
        parser.add_argument("url", type=is_url)
        parser.add_argument("-p", "--port", type=is_port, help="Port used to connect with URL (Default is 80)", default=80)
        parser.add_argument("-a", "--alg", help="Hash Algorithm to be used (Default is SHA1)", choices=algs, default="SHA1")
        args = parser.parse_args()
        
        url = args.url
        alg = args.alg
        port = args.port
        
        URL = "http://" + url + ":" + port
        
        url = args.url
        alg = args.alg
        port = args.port
        
        URL = "http://" + url + ":" + port
        print ("URL: " + URL)
        s = requests.Session()
        r = s.get(URL)
  
        ### Finds value to be hashed
        msg = re.search("[a-zA-Z0-9]{20}", r.text)

        if msg:
            print ("Value to hash: " + msg.group(0))
        else:
            print ("Value to hash not found")

        hash = encrypt (msg.group(0),alg)
        print ("Generated " + alg + " hash: " + hash)

        payload = "hash=" + hash
        p = s.post(URL, data=payload, headers={'Content-Type': 'application/x-www-form-urlencoded'})

        ### Finds the flag
        flag = re.search("HTB\{.*\}", p.text)
        if flag:
            print ("\n--- Flag found: " + flag.group(0) + " ---")
        else:
            print ("Flag not found")

    except KeyboardInterrupt:
        sys.exit(0)
    
    except requests.ConnectionError:
        print ("Error establishing connection")


def encrypt(msg,alg):

    if alg == 'MD5':
        return hashlib.md5(msg.encode('utf-8')).hexdigest()
    if alg == 'SHA1':
        return hashlib.sha1(msg.encode('utf-8')).hexdigest()
    if alg == 'SHA256':
        return hashlib.sha256(msg.encode('utf-8')).hexdigest()

if __name__ == "__main__":
    main()

import sys, requests, getopt, ipaddress, hashlib, re


def main():
    
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hu:a:p:")
        algs = ["MD5", "SHA1", "SHA256"]
        url = ""
        alg = ""
        port = "80"

        if not opts:
            usage()
            sys.exit(0)

        for opt, arg in opts:
            if opt == '-h':
                usage()
                sys.exit(0)

        for opt, arg in opts:
            if opt == '-u':
                url = arg

            if opt == '-p':
                port = arg

            if opt == '-a':
                if arg not in algs:
                    print ("Invalid algortihm, valid algorithms are: ")
                    print (algs)
                    sys.exit(3)
                alg = arg
        
        if not url:
            print ("Please specify a host with the -u option")
            sys.exit(4)
        
        if not alg:
            print ("Please specify an algorith with the -a option")
            print ("\nValid algorithms are:")
            print (algs)
            sys.exit(4)
        
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

    except getopt.GetoptError as err:
        print (err)
        usage ()
        sys.exit(1)

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


def usage():

    print("Usage: python " + sys.argv[0] + " -u [HOST] -p [PORT=80] -a [ENCRYPTION ALGORITHM]")


if __name__ == "__main__":
    main()  
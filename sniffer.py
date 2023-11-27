def check_time():  # função para cuidar do tempo de timeout
    # global tokenReceivedTime, userStartedWithToken
    startTime = time()
    startCount = protocol_count["ICMP"]
    while True:
        if time() - tokenReceivedTime > 2:
            startTime = time()
            startCount = protocol_count["ICMP"]
        else:
            if protocol_count["ICMP"] - startCount > 1000:
                print("FLOODING")
                tokenReceivedTime = time()
                passAlongToken()

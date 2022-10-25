import dns_forwarder



if __name__ == '__main__':
    q1 = dns_forwarder.Query('127.0.0.1', b'test')
    print(q1.doh_style())

from optparse import OptionParser
from client import *
from utils.util import *

if __name__ == "__main__":
    # create client
    parser = OptionParser()
    parser.add_option("-a", "--address", dest="receiver_address", help="Receiver address")
    parser.add_option("-p", "--port", dest="receiver_port", help="Receiver address")
    parser.add_option("-c", "--ciphers", dest="cipher_suites", help="Server select cipher suite")
    parser.add_option("-E", "--exchange", dest="key_exchange", help="Key exchange algorithm")
    parser.add_option("-S", "--symmetric", dest="symmetric", help="Symmetric algorithm")
    parser.add_option("-H", "--hash", dest="hash", help="Hash algorithm")
    parser.add_option("-m", "--message", dest="message", help="Send message")
    (options, args) = parser.parse_args()

    if not options.receiver_address or not options.receiver_port or not options.message:
        print("Usage: main_client.py [options]\n")
        print("Options:")
        print("-a, receiver address")
        print("-p, receiver port")
        print("-c, select cipher suite,format:[KeyExchange:symmetric:hash]")
        print("-E, select key exchange algorithm")
        print("-S, select symmetric algorithm")
        print("-H, select hash algorithm")
        print("-m, send message")

    else:
        key_exchange = None
        symmetric = None
        hash = None
        # 获取命令行参数中选择的算法套件
        if options.cipher_suites:
            cmd = options.cipher_suites.split(":")
            key_exchange = cmd[0]
            symmetric = cmd[1]
            hash = select_hash(cmd[2])
        if options.key_exchange:
            key_exchange = options.key_exchange
        if options.symmetric:
            symmetric = options.symmetric
        if options.hash:
            hash = select_hash(options.hash)

        # 建立TCP连接
        address = (options.receiver_address, int(options.receiver_port))
        client_socket = socket(AF_INET, SOCK_STREAM)
        print("[client]Client is running...")
        print(f"[client]Connect to {options.receiver_address}:{options.receiver_port}...")
        client_socket.connect(address)
        # 创建client
        client = TLSClient(client_socket, address)
        # 设置client算法套件
        client.set_cipher_suite(key_exchange, symmetric, hash)
        message = options.message.encode()
        # TLS连接并发送message到客户端
        client.connect(message)

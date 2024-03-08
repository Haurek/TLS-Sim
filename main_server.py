from optparse import OptionParser
from server import *
from utils.util import *

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-p", "--port", dest="receive_port", help="Receive port")
    parser.add_option("-c", "--ciphers", dest="cipher_suites", help="Server select cipher suite")
    parser.add_option("-E", "--exchange", dest="key_exchange", help="Key exchange algorithm")
    parser.add_option("-S", "--symmetric", dest="symmetric", help="Symmetric algorithm")
    parser.add_option("-H", "--hash", dest="hash", help="Hash algorithm")
    (options, args) = parser.parse_args()

    if not options.receive_port:
        print("Usage: main_client.py [options]\n")
        print("Options:")
        print("-p, receive port")
        print("-c, select cipher suite,format:[KeyExchange:symmetric:hash]")
        print("-E, select key exchange algorithm")
        print("-S, select symmetric algorithm")
        print("-H, select hash algorithm")

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
        address = ('', int(options.receive_port))
        server_socket = socket(AF_INET, SOCK_STREAM)
        server_socket.bind(address)
        server_socket.listen(1)
        print("[server]Server is running...")
        print(f"[server]Listening port {options.receive_port}...")
        # 创建server
        server = TLSServer(server_socket, address)
        # 设置server算法套件
        server.set_cipher_suite(key_exchange, symmetric, hash)
        # 运行服务端
        server.run()

# TLS模拟

复旦大学2023年秋季学期信息系统安全project



## 实验目的

- 了解TLS协议内容

- 理解TLS连接过程

- 了解TLS如何保证加密通信

- 模拟TLS握手和加密传输过程

  

## 项目概述

基于TLS1.2协议实现的TLS握手过程和加密数据传输过程模拟

实验环境

- Windows
- python 3.10.13
  - cryptography 41.0.5



## **Manual**

首先启动服务端并监听端口，然后启动客户端连接到本地IP`127.0.0.1`和服务端端口

- **Client**:

  运行client：`python ./main_client [options]`

  命令行参数：

  ~~~
  Options：
  -a, 服务端地址
  -p, 服务端端口
  -c, 选择加密算法套件，格式:[KeyExchange:symmetric:hash]
  -E, 选择密钥交换算法
  -S, 选择对称加密算法
  -H, 选择hash算法
  -m, 发送到客户端的消息
  ~~~

  必须提供的命令行参数：`-a`、`-p`、`-m`，及设置服务端的地址和端口，以及待发送的消息

  可选参数：`-c`、`-E`、`-S`、`-H`，用于选择加密算法套件进行模拟，如果不提供，默认选择的算法套件为：

  ~~~
  TLS_RSA_WITH_AES_256_CBC_SHA256
  ~~~

  即RSA密钥交换算法，AES_256_CBC模式对称加密算法和SHA256消息摘要算法

  参数`-c`可一次指定所有算法，格式为**-c KeyExchange:symmetric:hash**

  - KeyExchange：密钥交换算法
  - symmetric：对称加密算法
  - hash：消息摘要算法




- **Server**:

  运行server：`python ./main_server [options]`

  命令行参数：

  ~~~
  Options：
  -p, 监听端口
  -c, 选择加密算法套件，格式:[KeyExchange:symmetric:hash]
  -E, 选择密钥交换算法
  -S, 选择对称加密算法
  -H, 选择hash算法
  ~~~

  必须提供的命令行参数：`-a`，及设置服务端监听端口

  可选参数和使用方法与client相同，但要求**server选择的算法套件和client选择的算法套件必须相同**，否则无法协商出一致的算法套件导致连接失败
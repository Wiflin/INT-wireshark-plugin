使用方法：
    1. 将插件复制到wireshark插件目录（可省略）
    2. 添加插件 https://blog.csdn.net/houjixin/article/details/12970871
    3. 打开带有 ifa 头的pcap/cap文件

* ifa_header.lua 
    识别ifa协议，私有协议号 IP Proto == 253
    解析 IFA HEADER，长度4Byte，获取下一个头部的协议类型（当前为UDP）
    解析 UDP

* ifa_md_stack.lua
    解析 UDP PAYLOAD
    解析 IFA METADATA HEADER，长度4Byte，解析 MD STACK 长度
    解析 IFA METADATA，每一个METADATA 长度32Byte
    交还wireshark解析后续PAYLOAD

* ifa_residense_statistic.lua
    统计 IFA METADATA中 的转发延迟，并打印到文件中

* wireshark_statisctic_example.lua
    数据统计例子

* ifa.cap
    测试 pcap 文件
# RJ FireWall

這是一個基於 Netfilter、Netlink 的 Linux L7 防火牆。

功能：
- [x] 按照來源 IP、目的 IP、埠號 (Port Number)，以及協定來過濾封包
- [x] 使用者可以新增、刪除、查看所有規則
- [x] 記錄封包過濾的日誌 (Log)，並可查看其內容
- [x] 連接狀態檢測
- [x] NAT

# 安装

### 環境

環境為 Ubuntu 24.04，Linux Kernel 版本 6.8.0。

### 从源码安装

安装时需要gcc以及make包，若未安装，请预先安装：
```bash
sudo apt install gcc make
```

首先，下载本项目源码至任意目录：
```bash
unzip RJFireWall.zip

cd RJFireWall
```

随后，**编译源码**：
```bash
sudo make
```

最后，**安装**：
```bash
sudo make install
```

# 使用

在安装时，内核模块已经加载至Linux内核中，此时，只需使用上层应用uapp来对防火墙进行控制即可。

新增一条过滤规则：
```bash
./uapp rule add
```
随后依据命令行提示设定规则即可。

删除一条过滤规则：
```bash
./uapp rule del 所需删除规则的名称
```

设置默认动作为Drop（防火墙初始时默认动作为Accept）：
```bash
./uapp rule default drop
```

展示已有规则：
```bash
./uapp ls rule
```

展示所有过滤日志：
```bash
./uapp ls log
```

展示最后100条过滤日志：
```bash
./uapp ls log 100
```

展示当前已有连接：
```bash
./uapp ls connect
```

新增一条NAT规则：
```bash
./uapp nat add
```
随后依据命令行提示设定规则即可。

删除一条NAT规则：
```bash
./uapp nat del 所需删除NAT规则的序号
```

展示已有NAT规则：
```bash
./uapp ls nat
```

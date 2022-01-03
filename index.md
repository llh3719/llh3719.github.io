# centos8 搭建透明代理(旁路由)全流程踩坑之旅

## 引言

本篇实现为通过一个本地 linux 机器(采用centos8)接入主路由并作为网关,接管所有进入主路由的流量并进行DNS检测,流量分流至VPN等操作实现透明代理(旁路由)

## 涉及主要操作点

-   [网关配置](#网关配置)
-   [DNS配置](#DNS配置)
-   [iptables配置](#iptables配置)
-   [trojan客户端配置](#trojan客户端配置)

## 趟坑开始,接下来是全流程的每一步详细操作

### 网关配置

1.  **进入主路由器将网关设置为该 linux 设备的局域网地址(笔者的该设备地址为:192.168.50.162),不同路由器的配置界面会不同,但 DHCP 功能都应提供**

        进入路由器配置界面后,找到内部网络的DHCP设置界面,启用DHCP,将网关设置为该旁路由的局域网地址:192.168.50.162

    由于该旁路由之后还需要作为 DNS 服务器用,此处一并将 DNS 服务器也设置为该旁路由地址.

2.  **关闭旁路由的防火墙**  
    为后续配置更加简单清晰,此处直接将 centos8 的防火墙关闭,若懂得相应配置且有防火墙的相关需求可在本配置流程完成后自行再将防火墙开启.

    centos8 防火墙相关命令如下:

    查看防火墙状态:  
    `systemctl status firewalld.service`  
    开启防火墙:  
    `systemctl start firewalld.service`  
    关闭防火墙:  
    `systemctl stop firewalld.service`  
    禁用防火墙:  
    `systemctl disable firewalld.service`

    执行关闭防火墙命令后查看状态,返回结果如下:

    ```
    ● firewalld.service - firewalld - dynamic firewall daemon
       Loaded: loaded (/usr/lib/systemd/system/firewalld.service; disabled; vendor preset: enabled)
       Active: inactive (dead)
         Docs: man:firewalld(1)
    ```

    请一定确认好防火墙已处于关闭状态,否则后续流程问题很难定位

3.  **本地配置主路由为网关**

    进入目录`/etc/sysconfig/network-scripts/`

    修改该目录下的网卡配置文件:`ifcfg-eno1`(硬件环境不同该文件名可能不同)

    将其内容修改为如下:

    > TYPE=Ethernet  
    >  PROXY_METHOD=none  
    >  BROWSER_ONLY=no  
    >  BOOTPROTO=static  
    >  IPADDR=192.168.50.162  
    >  NETMASK=255.255.255.0  
    >  GATEWAY=192.168.50.1  
    >  DNS1=127.0.0.1
    > DEFROUTE=yes  
    >  IPV4_FAILURE_FATAL=no  
    >  IPV6INIT=yes  
    >  IPV6_AUTOCONF=yes  
    >  IPV6_DEFROUTE=yes  
    >  IPV6_FAILURE_FATAL=no  
    >  NAME=eno1  
    >  UUID=8d0e2ca0-76f3-4823-9346-1f1308899bd5  
    >  DEVICE=eno1  
    >  ONBOOT=yes

    注意:
    GATEWAY 应为主路由的局域网地址,因为目的是将本局域网内流量方向设为: 各客户端流量 > 主路由 > 旁路由 > 主路由 > 外网  
    DNS1 设为本地地址,后续也要将本设备作为 DNS 服务器

4.  **开启内核 IP 转发**

    查看`/etc/sysctl.conf`中的`net.ipv4.ip_forward`是否已经开启 IP 转发,1 为允许转发,0 为不允许  
    若为 0 则将其修改为 1  
    若没有该字段则添加`net.ipv4.ip_forward = 1`  
    命令`sysctl -p`可使其立即生效

### DNS配置

DNS配置需要用到 dnsmasq 和 chinadns-ng 这两个工具  
dnsmasq 在 centos8 中应会自带,若没有则手动安装即可  
chinadns-ng 需要后续我们自行安装

5. **dnsmasq 配置**
   修改`/etc/dnsmasq.conf`,在文件最上方添加如下内容:

    > no-resolv  
    > server=127.0.0.1#8053  
    > listen-address=192.168.50.162,127.0.0.1

    `no-resolv` 表示不从/etc/resolv.conf 读取上游服务器  
    `server` 设置上游服务器,此处设置为本地 ip,端口 8053 为我们后续将要启动的 chinadns-ng 所监听的端口号  
    `listen-address` 设置监听地址,192.168.50.162 为该旁路由局域网地址

配置至此,该旁路由应该已经可以作为普通网关使用,可以在局域网中的其他终端设备进行测试  
如果网络无法连通,请一定检查防火墙是否关闭

6. **chinadns-ng 配置**

    chinadns-ng 的[官方页面](https://github.com/zfl9/chinadns-ng)中有比较详细的使用说明
    根据其说明安装 chinadns-ng:

    ```
    git clone https://github.com/zfl9/chinadns-ng
    cd chinadns-ng
    make && sudo make install
    ```

    系统环境中若缺少相关组件,根据提示安装即可  
    安装完成后,进入`chinadns-ng`目录,执行如下脚本更新相应文件:

    ```
    ./update-chnlist.sh
    ./update-chnroute.sh
    ./update-chnroute6.sh
    ./update-gfwlist.sh
    ```

    完成更新后将 chnroute 导入 ipset,命令如下:

    ```
    ipset -F chnroute
    ipset -F chnroute6
    ipset -R -exist <chnroute.ipset
    ipset -R -exist <chnroute6.ipset
    ```

    在当前目录新建 log(`mkdir log`)后就可以启动 chinadns-ng 了

    ```
    chinadns-ng -b 0.0.0.0 -l 8053 -c 114.114.114.114 -t 208.67.222.222#443 -g gfwlist.txt -m chnlist.txt </dev/null &>>./log/chinadns-ng.log &
    ```

    此处采用 chinadns-ng 的原因以下两篇文章有较详细的介绍:  
    [[ChinaDNS] 无污染的智能路由 DNS 折腾记](https://moe.best/tutorial/chinadns.html#ChinaDNS)  
    [使用 ChinaDNS-NG 和 dnsmasq 对域名解析进行智能分流](https://huangyunsong.com/2020/3/chinadns-ng-dnsmasq/)

### iptables配置

iptables 的配置有一定的学习门槛,建议参考文章如下:  
[iptables 详解](https://www.zsythink.net/archives/1199)  
[透明代理中 iptables 设置方法详细介绍](https://vlike.work/tech/how-to-set-trans-proxy.html)

7. **iptables 规则配置**

    本文目的是将流入旁路由的流量和旁路由本地流量都转发给代理  
    且旁路由作为 DNS 服务器要有 DNS 劫持功能  
    所以在 iptables 的`PREROUTING`链和`OUTPUT`链都要有相应配置  
    配置命令如下(执行命令前请确保此前已经在 chinadns-ng 配置步骤中添加 chnroute 到 ipset):

    ```
    # 新建自定义链(链名可自定)
    iptables -t nat -N TROJAN_RULES
    iptables -t nat -F TROJAN_RULES
    # 添加自定义链到PREROUTING链
    iptables -t nat -A PREROUTING -p tcp -s 192.168.50.162/16 -j TROJAN_RULES

    # DNS劫持到本地dnsmasq绑定的53端口
    iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53
    # 本地地址请求不转发
    iptables -t nat -A TROJAN_RULES -d 10.0.0.0/8 -j RETURN
    iptables -t nat -A TROJAN_RULES -d 127.0.0.0/8 -j RETURN
    iptables -t nat -A TROJAN_RULES -d 169.254.0.0/16 -j RETURN
    iptables -t nat -A TROJAN_RULES -d 172.16.0.0/12 -j RETURN
    iptables -t nat -A TROJAN_RULES -d 192.168.50.162/16 -j RETURN
    # 位于chnroute白名单中的地址不转发到代理
    iptables -t nat -A TROJAN_RULES -s 192.168.50.162/16 -m set --match-set chnroute dst -j RETURN
    # 服务端口1080接管HTTP/HTTPS请求转发, 过滤 22,1080,8080一些代理常用端口
    iptables -t nat -A TROJAN_RULES -s 192.168.50.162/16 -p tcp -m multiport --dport 80,443 -j REDIRECT     --to-ports 1080


    # OUTPUT链(un_vpn_user不走代理的用户)
    iptables -t nat -A OUTPUT -m owner --uid-owner un_vpn_user -j RETURN
    # 位于chnroute白名单中的地址不转发到代理
    iptables -t nat -A OUTPUT -s 192.168.50.162/16 -m set --match-set chnroute dst -j RETURN
    # 本机程序通过过滤后的流量转发给代理
    iptables -t nat -A OUTPUT -p tcp -s 192.168.50.162/16 -j REDIRECT --to-port 1080

    # 清除命令
    # 清表删除
    iptables -t nat -F TROJAN_RULES
    iptables -t nat -X TROJAN_RULES
    # PREROUTING链逐个删除
    iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53
    # OUTPUT链逐个删除
    iptables -t nat -D OUTPUT -m owner --uid-owner un_vpn_user -j RETURN
    iptables -t nat -D OUTPUT -s 192.168.50.162/16 -m set --match-set chnroute dst -j RETURN
    iptables -t nat -D OUTPUT -p tcp -s 192.168.50.162/16 -j REDIRECT --to-port 1080
    ```

    上述命令可全部复制直接执行,带有#的注释不会执行

    **注意!**  
    1080 端口为本地启动的代理客户端监听端口,笔者采用的是 trojan 客户端  
    若要执行所有上述命令,请提前创建 un_vpn_user 用户,该用户作用为区分进程是否要走代理  
    若旁路由机器上的进程希望走代理则不用该用户启动  
    若不希望走代理,则使用该用户启动即可  
    本机的 trojan 客户端就是用 un_vpn_user 用户启动的  
    目的就是防止从 OUTPUT 链上流出的流量又被重新发回给 trojan,形成无限回环  
    也就是`iptables -t nat -A OUTPUT -m owner --uid-owner un_vpn_user -j RETURN`的作用  
    若要自行修改配置,需要注意的点是在 OUTPUT 链上确保有类似于上述命令的过滤  
    避免形成回环

### trojan客户端配置

8.  **trojan 客户端安装**

    下载命令:  
    ```
    wget https://github.com/trojan-gfw/trojan/releases/download/v1.16.0/trojan-1.16.0-linux-amd64.tar.xz
    ```
    解压命令:  
    ```
    tar -xf trojan-1.16.0-linux-amd64.tar.xz
    ```
    备份原配置文件  
    ```
    mv config.json config.json_bak
    ```
    新建配置文件config.json写入如下内容:  
    ```
    {
        "run_type": "nat",
        "local_addr": "0.0.0.0",
        "local_port": 1080,
        "remote_addr": "*********",
        "remote_port": 443,
        "password": [
            "*********"
        ],
        "log_level": 1,
        "ssl": {
            "verify": true,
            "verify_hostname": true,
            "cert": "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            "cipher":  "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-CDSA   -AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES28-S   HA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA",
            "cipher_tls13":"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
            "sni": "",
            "alpn": [
                "h2",
                "http/1.1"
            ],
            "reuse_session": true,
            "session_ticket": false,
            "curves": ""
        },
        "tcp": {
            "no_delay": true,
            "keep_alive": true,
            "reuse_port": false,
            "fast_open": false,
            "fast_open_qlen": 20
        }
    }
    ```
    [本文](https://trojan-gfw.github.io/trojan/config.html)有trojan配置文件的详细介绍

    trojan的`run_type`设为`nat`  
    监听地址`local_addr`设为:`0.0.0.0`,此处不要设为`127.0.0.1`,其可能会导致监听不到外来流量  
    若使用的是其他代理客户端也需注意这一点
    然后通过此前创建的un_vpn_user用户来启动trojan  
    代理就可以正常工作了

**至此该透明代理(旁路由)就搭建完成了,其中的一些工具程序可以设置为开机启动,如chinadns-ng,iptables配置,trojan客户端等  
也可以将chinadns-ng和trojan放在docker内运行,方便后续管理**

### 趟坑后记
- 配置网关时中间给设备重装过一次系统,导致之后的防火墙忘记关掉,发现dnsmasq总是转发不了外来的请求,只有本地的dns请求可以转发  
- iptables网上有很多人在OUTPUT设置了重定向到代理客户端,但不进行过滤,然后就形成回环,起初对iptables流程不了解,排查了许久  
- trojan客户端通过nat模式启动仍然监听不到转发来的流量,也是排查了许久后才发现应将其监听在`0.0.0.0`的地址上 

以上的大坑小坑望各位引以为鉴
# 第一章 绪论 Introduction

## 网络空间的构成

* 物理域 Physical Domain
* 虚拟域 Virtual Domain
* 认知域 Cognition Domian

## 系统的脆弱性

* 普遍性 Ubiquity
* 模糊性 Fuzzification
* 开放性 Openness<br />Internet conforms to standards
* 垄断性 Monopolization
* 公开性 Publicness<br />Technical details are discussed in public
* 人类的天性 Human nature

## 安全目标

* 真实性 Authenticity
* 可用性 Availability
* 完整性 Integrity
* 保密性 Confidentiality
* 所有权 Possession

# 第二章 网络攻击 Network Attacks

## 分类

### 发起方式

* 主动攻击
* 被动攻击

### 攻击目的

* 信息窃取
* 完整性破坏
* 服务失效
* 资源滥用

## 网络黑客的分类

* 社区黑客
* 技术黑客
* 经济黑客
* 政治黑客
* 政府黑客

## 漏洞的分类

* 设计过程中产生的漏洞
    * 基于IP欺骗的TCP序列号攻击
    * 基于最长前缀匹配优先原则的路由劫持漏洞
* 实现过程中产生的漏洞
    * 缓冲区溢出
    * 跨站脚本
* 管理过程中产生的漏洞

## 漏洞库

* CVE
* NVD

## 入侵攻击模型

* 杀伤链 Kill Chain
    1. 侦查 Reconnaissance
    2. 武器化 Weaponization
    3. 投放 Delivery
    4. 漏洞利用 Exploitation
    5. 后门安装 Installation
    6. 命令与控制 Command & Control
    7. 意图实现 Action of Objective
* ATT & CK

## 进入 Initial Access

* 主动进入
    * SQL注入
    * 硬件攻击
    * 信任攻击
* 被动进入
    * 鱼叉攻击 Spear phishing
    * 第三方间接攻击
        * 供应链攻击（软件）
        * 水坑攻击（平台）

## 提权 Privilege Escalation

* 特权程序漏洞利用
* 路径/配置劫持

## 木马后门 Trojan Horse

### 特点

* 有效性
* 隐蔽性
* 顽固性
* 易植入性

### 类型

#### 存放和执行方式

* 基于可执行程序的木马
* 基于引导区的木马
* 网站木马
    * 大马
    * 小马
    * 一句话木马

## 服务失效攻击

* DoS: one attacker to one target
* DDoS: many attackers to one target

### 攻击机制

* 发掘系统漏洞
* 零日攻击
* 计算过载
* 基于洪泛

### 攻击放大

* 直接DDoS攻击的放大
* 基于反射的DDoS攻击的放大
* 实例
    * 基于UDP
        * CharGen
        * DNS
        * NTP
        * SNMP
        * SSDP
        * TFTP
    * BGP低速DoS

# 第三章 僵尸网络 Botnet

## 蠕虫

Morris蠕虫

### 结构特征

* 基本功能模块
    * 搜索模块
    * 攻击模块
    * 传输模块
    * 信息搜索模块
    * 繁殖模块
* 扩展功能模块
    * 通信模块
    * 隐藏模块
    * 破坏模块
    * 控制模块

## 僵尸网络

### 与蠕虫的区别

通过命令与控制信道(C2信道)协调运行

## Fast-Flux

* IP fluxing
* Domain fluxing

# 第四章 黑色产业 Black Market

## 合作模型

* 需求提供者
* 信息提供者
* 服务提供者
* 基础设施提供者
* 工具开发者

## 暗网

* 基于P2P网络架构，采用匿名通信机制
* 使用互联网作为基础设施
* 使用非标准协议

## 社会工程攻击

### 攻击流程

1. 攻击意图的确立
2. 信息收集
3. 攻击准备
4. 攻击接触
5. 攻击持续
6. 攻击撤离

## 面向下载的产业链

## 面向销售的产业链

## 恶意黑产

### 信息窃取

* 撞库
* 洗库
* 拖库

### 勒索软件

### APT

# 第五章 网络入侵检测 Intrusion Detection

## 类别

* 网络安全监测 Surveillance
* 网络内容监测 Censorship

## 网络安全监测的方法

* 基于网络的NIDS
    * 优点
        * 使用成本较低
        * 可检测到主机中检测不到的攻击
        * 攻击者不易转移证据
        * 实时监测和响应
        * 检测未成功的攻击和不良意图
        * 操作系统无关性
    * 缺点
        * 依赖攻击特征进行入侵检测，因此检测规则的完备性和准确性对检测精度的影响很大
        * 无法获得被保护主机的背景信息和内容信息，在进行后处理时很难直接对警报的适用性进行判定
        * 处理加密的会话过程较困难
* 基于主机的HIDS
    * 优点
        * 明确确定攻击成功与失败
        * 精细监视主机系统的行为
        * 检测效率高
        * 能够检查到NIDS检查不出的入侵攻击
    * 缺点
        * 可靠性
        * 可用性
        * 在一定程度上依赖于系统的可靠性，要求系统本身应该具备基本的安全功能并具有合理的设置，然后才能入侵信息
        * 即使进行了正确的设置，对操作系统熟悉的攻击者仍然有可能在入侵行为完成后及时将系统日志抹去，从而不被发觉
        * 有的入侵手段和途径不会在日志中有所反应，造成HIDS的盲区
        * 会给被保护系统带来额外的资源开销，降低系统效率
* 漏洞扫描
* 蜜罐
* 警报系统
* 网络管理系统

## 入侵检测系统 IDS

### 可能的监测结果

* 网络行为正常，系统没有监测到入侵，TN
* 网络行为正常，系统监测到入侵，TP
* 网络行为异常，系统没有监测到入侵，FN
* 网络行为异常，系统监测到入侵，FP

### 滥用检测 Misuse Detection

#### 总体结构

* 报文检测模块
* 入侵检测模块
* 分析处理模块

#### 数据采集

* Libpcap
* Zero-copy
* tcpdump
* wireshark

#### 监测规则定义

* snort
* zeek

### 异常检测 Anomaly Detection

#### 基本模型

* 事件发生器
* 活跃行为基准集
* 规则集

## 蜜罐

### 分类

#### 应用目的

* 产品型蜜罐
* 研究型蜜罐

#### 实现形式

* 物理蜜罐
* 虚拟蜜罐

#### 交互程度

* 低交互度
* 中交互度
* 高交互度

### 基本功能

* 核心机制
    * 欺骗环境构建
    * 威胁数据捕获
    * 威胁数据分析
* 辅助机制
    * 安全风险控制
    * 配置与管理
    * 反蜜罐技术对抗

# 第六章 网络安全防御 Network Defence Methodology

## 可生存性

* 对攻击的抵抗能力
* 对损失的评估能力
* 对灾害的恢复能力
* 对环境的适应能力

## 分层的网络保护模型

1. 入侵防范
2. 入侵检测
3. 入侵容忍

## 计算机安全事件应急响应工作组 CSIRT

## 脆弱性检测

### 漏洞扫描

* 端口扫描
    * TCP SYN扫描
    * TCP FIN扫描

### Nmap

### Zmap

## 协同防御

## 威胁信息交换 STIX

# 第七章 网络攻击阻断 Intrusion Prevention

## 防火墙

### 实现形式

* IP级防火墙
* 应用级防火墙
* 链路级防火墙
* Web应用防火墙

### 状态检测防火墙

不仅检查IP头，还检查更高层报文的报头

### 防火墙的使用

* 路由器过滤 Firewall with holes
* 主机过滤 Hole-less firewall
* DMZ方法
* 网关方法 Hierarchical defense

## 拦截

* 基于传输层的会话拦截
* 基于DNS重定向的会话拦截

## 数字取证 Computer Foresics

### 取证模型

* 基本过程模型
    * Secure and isolate
    * Record the scene
    * Conduct a systematic search for evidence
    * Collect and package evidence
    * Maintain chain of custody
* 集成数字取证过程模型 IDFPM

# 第九章 网络基础设施保护 Internet Infrastructure Protection

## 链路层保护

* 攻击
    * CAM溢出
    * DHCP饥饿攻击
    * DHCP欺骗攻击
    * ARP欺骗攻击
* 端口保护
    * MAC地址认证
    * 端口安全（基于MAC地址进行过滤）
    * IP源保护
* ARP保护
    * 动态ARP检测
* 链路层安全需求：Authentication, Authorization, Accounting, AAA
* 链路层认证协议
    * RADIUS
    * 802.1X

## 路由安全

### 路由的安全威胁

* 威胁者
* 对象
    * BGP router
    * BGP route update
* 目标
    * Route leakage
    * Route hijact
    *  Route denial

### RPKI

## IPsec

## DNSsec


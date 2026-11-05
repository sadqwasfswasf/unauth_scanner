# UnAuthHunter —— 多目标端口扫描 + 未授权访问漏洞检测器

纯 Python 标准库实现（Python 3.8+，无第三方依赖），面向内网资产排查 / 等保合规自查 /
授权渗透测试场景。对多个 IP（支持 CIDR）做 TCP 端口扫描，自动识别 HTTP/HTTPS 与协议
指纹，再用 88 个内置 POC 做严格的多特征未授权访问检测。

> ⚠️ 免责声明：仅限用于自有资产安全检查与已授权测试。未经授权扫描他人系统违法。

## 快速开始

```bash
# 扫一个 C 段（默认端口集 = TOP 端口 + 全部 POC 默认端口）
python unauth_scanner.py -t 192.168.1.0/24

# 从文件读目标（每行一个 IP/CIDR，# 注释），自定义端口范围
python unauth_scanner.py -t targets.txt -p 80,443,8000-8100

# 多个目标 + 深度模式（协议探针跑在所有开放端口，可检出改端口部署的 Redis 等）
python unauth_scanner.py -t 10.0.0.5 10.0.0.6 --deep

# 快速模式（路径类 POC 只在各自默认端口跑，适合大规模初筛）
python unauth_scanner.py -t 192.168.0.0/16 --fast -w 500

# 附加 UDP 检测（SNMP 默认团体名）
python unauth_scanner.py -t 192.168.1.0/24 --udp

# 查看全部内置 POC
python unauth_scanner.py --list
```

## 参数说明

| 参数 | 说明 |
|---|---|
| `-t / --targets` | 目标：IP / CIDR（≤/16）/ 文件路径，空格分隔多个 |
| `-p / --ports` | 端口：`80,443,8000-8100`；缺省=TOP 端口+全部 POC 默认端口 |
| `--fast` | 快速模式：路径类 POC 仅在默认端口执行 |
| `--deep` | 深度模式：协议类 POC（Redis/Mongo/Rsync 等）对所有开放端口执行 |
| `--udp` | 附加 UDP 检测（SNMP public 团体名） |
| `--timeout` | 单连接超时秒数（默认 4） |
| `-w / --workers` | 并发线程（默认 300） |
| `-o / --output` | 报告输出目录（默认 `reports/`，生成 .json/.csv/.html 三份） |
| `--list` | 列出全部 POC |
| `--no-color` | 关闭彩色输出 |

## 检测能力（92 个 POC，按类别）

- **协议级（二进制/文本协议严格匹配）**：Redis（PING/+PONG）、MongoDB
  （OP_MSG/OP_QUERY listDatabases）、Memcached、Rsync（模块列表）、ZooKeeper
  （四字命令）、FTP 匿名登录、VNC 无认证协商、MySQL root 空口令（握手协议）、
  PostgreSQL trust 认证、Dubbo telnet ls、RMI/JRMP、SNMP public（UDP）
- **Java 框架/中间件**：Spring Boot Actuator（/actuator + env/heapdump +
  Spring Boot 1.x 裸路径）、heapdump HPROF 魔数校验、Spring Cloud Gateway 路由
   （CVE-2022-22947 风险面）、Nacos（**全量只读接口核查**：用户/角色/权限、
  配置列表/历史/全量导出、集群节点、命名空间、服务与实例目录、Naming 指标、
  Raft 状态、actuator、Derby 只读SQL 共 21 个端点；绕过向量含 UA `Nacos-Server`
  与 `serverIdentity` CVE-2021-29441、鉴权未开；**每个未授权接口各输出一条发现，
  含接口名与完整 URL**，便于逐条整改；另有独立默认口令 POC 与
  内部端口暴露 POC 7848/9848/9849；命名空间列表 v1/v2 经官方认定为"公开数据
  (设计如此)"，由独立 POC `nacos-namespace-expose` 以 **Low** 级单列，不计入未授权主干）、
  Druid、Swagger/OpenAPI、Eureka、JBoss jmx-console、WebLogic、
  Tomcat Manager、XXL-JOB executor/admin、Sentinel、Dubbo Admin
- **容器/云原生**：Docker Remote API、Docker Registry、K8s API Server 匿名、
  kubelet 10250/10255、etcd、Consul、Nomad、Vault、Harbor、Argo Workflows、
  ArgoCD、K8s Dashboard、cAdvisor
- **大数据**：Hadoop YARN、HDFS NameNode/webhdfs、Spark、Flink、HBase、Solr、
  ClickHouse、Doris/StarRocks、DolphinScheduler 默认口令（admin/dolphinscheduler123，
  UI 指纹门控）、SeaTunnel Web 默认口令（admin/admin，官方 SQL 种入）、
  SeaTunnel Zeta REST API 未授权（官方默认 enable-basic-auth=false）
- **数据库**：Elasticsearch、CouchDB、InfluxDB、Neo4j、TDengine 默认口令
- **消息队列**：ActiveMQ、RabbitMQ guest/guest、RocketMQ Dashboard、Kafka Manager
- **监控运维**：Prometheus、Grafana 默认口令、Kibana、Logstash、Zabbix、
  SonarQube、Nexus、Supervisord、Airflow、Superset、Metabase、Jupyter、
  Node Exporter
- **AI 组件（2024-2026 高发）**：Ollama（CNVD-2025-04094）、Ray Dashboard
  （ShadowRay/CVE-2023-48022）、MLflow、vLLM、ComfyUI、TensorBoard、Milvus
  （CVE-2026-26190 / CVE-2025-64513）、Qdrant、Weaviate、ChromaDB、MinIO、
  LangServe、Flowise/Langflow、Dify、Triton、Presenton（旧版/未配置认证实例
  `/api/v1/ppt/presentation/all` 匿名可读）

## 精准度设计

1. **多重特征命中**：每个 HTTP POC 要求 状态码 200 + JSON 结构/键 + 内容指纹，
   尽量区分“服务存在”与“确实未授权”（如 MongoDB 用 `listDatabases` 而非
   `hello`，后者无需认证恒返回）。
2. **置信度分级**：`Confirmed`（已验证可未授权访问）/ `Likely`（强特征疑似，
   建议人工复核）。
3. **只读检测**：仅 GET/协议握手，不做写入利用、不做口令爆破（默认口令仅单组
   一次性验证）。
4. **认证面即排除**：Redis 返回 `-NOAUTH`、Mongo 返回 not authorized、PG 返回
   md5/scram 挑战等直接判安全；HTTP 返回 401/403 视为“路径存在但受保护”，
   **不报未授权**（401 是暴露面提示，任何 Basic 认证站点都会返回，上报即噪声）。
5. **组件专属指纹优先**：禁止用“泛化关键字/点分文本”判定，必须依赖组件专属标识。
   例：Dubbo 需响应含 `dubbo>`/`ascii telnet commands` 等 QoS 标识；Tomcat Manager
   需命中管理页专属元素（`tomcat web application manager`、`/manager/html/list`、
   `deploy directory or war file` 等）；LangServe 需 `requestBody` 含 `input` 字段；
   WebLogic 需 body 含 weblogic+login/console 或响应头含 WebLogic。
6. **鉴权感知（区分“服务存在/页面可访问”与“确实未授权”）**：对**受保护接口**探测，
   而非公开首页。任何鉴权拦截信号——3xx 跳转登录、401/403、响应体/JSON 中的
   鉴权错误消息（如 `need login`/`未登录`/`forbidden`）——一律判安全、不上报。
   例：RocketMQ Dashboard 仅当受保护接口 `/topic/**`、`/cluster/**` 在**无鉴权拦截**
   下返回成功信封且带数据体才报；**公开的登录页/SPA 外壳含 "rocketmq" 字样不算证据**，
   `{"status":1,"data":null,"errMsg":"need login"}` 这类“键存在但值为 null”也不算。
7. **区分“公开接口”与“受保护接口”**：组件可能有**设计上就公开**的接口（如 Nacos
   `/v1/console/server/state`、健康检查端点），它们返回 200 不构成漏洞，**不能作为
   未授权证据**（仅可用于指纹与鉴权状态判定）。检测必须落在**开启鉴权后必然受保护**
   的接口上。
8. **注意 HTTP 200 包裹的业务码**：部分组件用 HTTP 200 承载业务码，判定必须
   **同时检查 HTTP 状态码与响应体业务码**。且**同一组件可能存在多套成功码**——
   Nacos v2 OpenAPI 成功码为 `0`，而 console API 成功码为 `200`
   （`{"code":200,"message":null,"data":[...]}`）。只认一种会把成功响应误判为
   “未知”而漏报；同时必须把 `403`/`10001` 等识别为鉴权拒绝，否则会把“拒绝”当“可读”。
9. **单一通用键/通用词不作证据**：`version`、`id`、`content`、`system`、`config`、
   `jobs`、`items`、`username`、`status`、`count`、`heartbeat` 等键在任意 API 中
   都常见，单独命中即判定未授权会系统性误报。这类 POC 必须叠加**组件专属结构**：
   例 Kibana 要求 `version` 是含 `number` 的对象；Jenkins 要求 `jobs` 为列表且出现
   `_class`/`numExecutors`；Argo 要求 `items` + `metadata` 列表信封；TDengine 要求
   `code==0` 且含 `column_meta`/`rows`；Chroma 只认 `nanosecond heartbeat`。
   同理，**空容器/空数组（`{}`、`[]`）不作为“可读”证据**。
10. **误报靶场（FP Gauntlet）**：`tests/test_fp_gauntlet.py` 构造对**任意路径都返回
    200** 的服务，并在响应中塞满上述通用键与通用词。任何 POC 只要在此靶场上产出
    结果，即判定为误报并需收紧。当前基线：**0 条发现**。该测试用于防止后续新增 POC
    时误报率回升。

## 性能设计

- 端口存活探测独立短超时 `min(1.0s, timeout)`：全连接扫描的耗时几乎全部来自被防火墙
  静默丢弃（DROP）的端口，缩短 connect 超时是收益最高的一刀（DROP 场景实测 -48%）。
- POC 阶段并发度 `max(32, min(workers//2, 256))`，避免原 64 上限把阶段串行化。
- `identify()` 结果（含失败）缓存，非 HTTP 端口不再被每个 path POC 重复触发
  http+https 超时等待；已识别 HTTP 的端口跳过 banner 抓取。
- 参考基准：`python tests/bench_speed.py`。

## 输出

`reports/unauth_report_<时间戳>.{json,csv,html}`：
- HTML 报告：中文专业排版，严重度色块 + 统计卡片 + 证据 + 修复建议。
- JSON：结构化字段（ip/port/漏洞/严重度/置信度/CVE/证据/修复），可接入 SOC/工单。
- CSV：Excel 可直接打开（UTF-8 BOM）。

## 已知限制

- NFS/SMB 等 RPC 类服务只做端口发现，不做未授权判定（协议实现复杂度与误报率）。
- MSSQL/Oracle 仅端口指纹。
- 自签名 HTTPS 已自动兼容（不校验证书）。
- 大目标建议 `--fast` + `-p` 收窄端口。

## 自测

| 脚本 | 覆盖 |
|---|---|
| `tests/mock_services.py` | 基础链路：Redis/Actuator/Nacos/Ollama 命中 + 普通页/401 页零误报 |
| `tests/test_fp_weblogic_langserve.py` | WebLogic/LangServe 误报对照（真/假服务） |
| `tests/test_fp_dubbo_tomcat.py` | Dubbo/Tomcat 误报对照（真 Dubbo、伪装 TCP、真 Manager、401 页） |
| `tests/test_fp_rocketmq.py` | RocketMQ Dashboard 鉴权对照（302 跳登录 / 401 / `data:null need login` / 含字样普通页 / 真未授权） |
| `tests/test_fp_nacos.py` | Nacos 鉴权对照（未开鉴权 / UA 绕过 / 已鉴权受保护 / 非 Nacos / 302 跳登录） |
| `tests/test_nacos_coverage.py` | Nacos 22 个只读端点 + 内部端口（7848 JRaft / 9848 gRPC）覆盖与误报对照 |
| `tests/test_nacos_code200.py` | Nacos console API `code:200` 信封回归（仅 console 接口泄露 → Likely；全开放 → Confirmed；全拒绝 → 0 误报） |
| `tests/test_nacos_enum.py` | Nacos 未授权接口逐条列出（3 接口 → 3 条；22 接口 → 22 条；全拒绝 → 0 条） |
| `tests/test_fp_gauntlet.py` | **误报靶场**：catch-all JSON/HTML 服务塞满通用键与通用词 → 期望 0 条发现 |
| `tests/bench_speed.py` | 端口扫描提速基准（DROP 场景） |

```bash
# 例：Dubbo/Tomcat 误报验证
python tests/test_fp_dubbo_tomcat.py &                      # 18080-18082, 20880-20881
python unauth_scanner.py -t 127.0.0.1 \
    -p 18080,18081,18082,20880,20881 --deep --no-color
# 预期: 20880 Dubbo + 18080 Tomcat 命中; 20881/18081/18082 零误报
```

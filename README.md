# unauth_scanner
未授权扫描工具

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

| 参数             | 说明                                                           |
| ---------------- | -------------------------------------------------------------- |
| `-t / --targets` | 目标：IP / CIDR（≤/16）/ 文件路径，空格分隔多个                |
| `-p / --ports`   | 端口：`80,443,8000-8100`；缺省=TOP 端口+全部 POC 默认端口      |
| `--fast`         | 快速模式：路径类 POC 仅在默认端口执行                          |
| `--deep`         | 深度模式：协议类 POC（Redis/Mongo/Rsync 等）对所有开放端口执行 |
| `--udp`          | 附加 UDP 检测（SNMP public 团体名）                            |
| `--timeout`      | 单连接超时秒数（默认 4）                                       |
| `-w / --workers` | 并发线程（默认 300）                                           |
| `-o / --output`  | 报告输出目录（默认 `reports/`，生成 .json/.csv/.html 三份）    |
| `--list`         | 列出全部 POC                                                   |
| `--no-color`     | 关闭彩色输出                                                   |

## 检测能力（88 个 POC，按类别）

- **协议级（二进制/文本协议严格匹配）**：Redis（PING/+PONG）、MongoDB
  （OP_MSG/OP_QUERY listDatabases）、Memcached、Rsync（模块列表）、ZooKeeper
  （四字命令）、FTP 匿名登录、VNC 无认证协商、MySQL root 空口令（握手协议）、
  PostgreSQL trust 认证、Dubbo telnet ls、RMI/JRMP、SNMP public（UDP）
- **Java 框架/中间件**：Spring Boot Actuator（/actuator + env/heapdump +
  Spring Boot 1.x 裸路径）、heapdump HPROF 魔数校验、Spring Cloud Gateway 路由
  （CVE-2022-22947 风险面）、Nacos（UA/serverIdentity 绕过 CVE-2021-29441 +
  默认口令）、Druid、Swagger/OpenAPI、Eureka、JBoss jmx-console、WebLogic、
  Tomcat Manager、XXL-JOB executor/admin、Sentinel、Dubbo Admin
- **容器/云原生**：Docker Remote API、Docker Registry、K8s API Server 匿名、
  kubelet 10250/10255、etcd、Consul、Nomad、Vault、Harbor、Argo Workflows、
  ArgoCD、K8s Dashboard、cAdvisor
- **大数据**：Hadoop YARN、HDFS NameNode/webhdfs、Spark、Flink、HBase、Solr、
  ClickHouse、Doris/StarRocks
- **数据库**：Elasticsearch、CouchDB、InfluxDB、Neo4j、TDengine 默认口令
- **消息队列**：ActiveMQ、RabbitMQ guest/guest、RocketMQ Dashboard、Kafka Manager
- **监控运维**：Prometheus、Grafana 默认口令、Kibana、Logstash、Zabbix、
  SonarQube、Nexus、Supervisord、Airflow、Superset、Metabase、Jupyter、
  Node Exporter
- **AI 组件（2024-2026 高发）**：Ollama（CNVD-2025-04094）、Ray Dashboard
  （ShadowRay/CVE-2023-48022）、MLflow、vLLM、ComfyUI、TensorBoard、Milvus
  （CVE-2026-26190 / CVE-2025-64513）、Qdrant、Weaviate、ChromaDB、MinIO、
  LangServe、Flowise/Langflow、Dify、Triton

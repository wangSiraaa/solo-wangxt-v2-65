# RouteBench · 离线路由策略推演工作台

在**发布前**离线看清一条 prefix-list/route-map 策略会放行或拒绝哪些前缀。
全程不连接任何生产设备；与真实 FRRouting 容器的交叉验证只在本机隔离网络内进行。

## 能力对照（需求 → 实现）

| 需求 | 实现 |
|---|---|
| React 展示前缀树和命中链 | `frontend/src/TrieView.jsx`（二进制前缀树，查询路径高亮、锚点挂规则徽标）、`HitChain.jsx`（逐条规则求值，标注首条命中/被遮蔽候选/默认终端） |
| FastAPI 用 ipaddress 解析地址与掩码 | `backend/app/engine.py`，严格 `strict=True` 校验（主机位非零即拒绝），`v4/v6` 用标准库类型天然隔离 |
| PostgreSQL 保存邻居、规则顺序、配置快照 | `backend/app/db.py` + `repo.py`：`neighbors / policies / rules(position) / snapshots / journal / frr_runs`；无 PG 环境自动回退本地 SQLite，功能不缩水 |
| 本地 FRRouting 容器有限案例交叉验证 | `backend/app/frr_lab.py`：隔离 bridge 网络 `routebench-lab --internal`，frr-a↔frr-b 双容器 eBGP，A 出向挂被推演策略，从 B 的 BGP RIB(JSON) 观测 |
| 精确前缀 / 掩码长度范围 | 不带 `ge/le` = **精确匹配**（对齐 FRR，非全锥形）；只给 `ge` 则 le=族上限，只给 `le` 则 ge=前缀长度；`pfxlen ≤ ge ≤ le ≤ maxlen` 强制校验 |
| 首条匹配 | 规则按 `position` 顺序求值，命中即终止；命中链中“范围覆盖但排在后面”的条目标记为遮蔽候选 |
| 默认拒绝 | 每族独立默认动作（生产习惯 deny）；命中链末尾永远显示该族默认终端 |
| IPv4/IPv6 不混算 | 规则按族分流求值；查询带族约束时跨族直接 422；邻居登记时 IP/族不一致 422 |
| 改规则后看被遮蔽条目 | `engine.find_shadowed()`：在有界行为单元见证集上做全空间证明，区分**单条遮蔽**与**并集遮蔽**，给出可复现见证前缀 |
| 行为变化的最小前缀集合（非文本 diff） | `engine.diff_policies()`：两版锚点并集切分“行为单元”，在关键掩码长度上取样，按（长度×前后判定签名）归并，得到最小代表集合；同时附文本层变化仅作参考 |
| 误放行/换序/默认动作变化示例 | 四个内置案例：`v4-over-permit`、`v4-reorder`、`v4-default-flip`、`v6-over-permit` |
| 测试模拟器与容器观测一致性 | `tests/test_frr.py`（`--run-frr` 开启真实容器对照）；UI“FRR 容器验证”页可直接跑案例并留存历史 |
| 回放输入及生效次序 | 每次编辑追加 `journal(seq, op, args, state_after)`，`/replay` 从 seq=0 的 reset 基线重放并与库内现状做漂移检测 |

## 目录

```
backend/
  app/
    engine.py       # 纯标准库 ipaddress：规则/策略、命中链、前缀树、行为单元、语义差异、遮蔽
    frr_config.py   # 策略 -> FRR prefix-list/route-map 配置（模拟器与容器共用同一份文本）
    frr_lab.py      # 两个本地 FRR 容器的编排（docker CLI 子进程，隔离网络）
    scenarios.py    # 4 个内置案例与共享测试前缀
    db.py repo.py   # PostgreSQL（SQLite 回退）持久化与可回放编辑
    main.py schemas.py
  seed.py           # 演示数据：邻居、策略、操作日志、发布前快照
  tests/            # 21 个离线用例 + 4 个需容器的用例（默认 skip）
frontend/           # React + Vite：推演台/语义对比/遮蔽/回放/容器验证/邻居/策略库
docker-compose.yml  # PostgreSQL + API + Web（FRR 实验室按需通过 API 自举）
```

## 快速开始（无 Docker / 无 PostgreSQL 也能跑）

后端：

```bash
cd backend
pip install -r requirements.txt
python seed.py                                   # 可选：演示数据
uvicorn app.main:app --reload --port 8000
pytest -q                                        # 21 passed, 4 skipped
```

前端：

```bash
cd frontend
npm install && npm run dev                       # http://localhost:5173
```

或一键起全栈（含 PostgreSQL）：

```bash
docker compose up --build                        # Web http://127.0.0.1:8080
```

PostgreSQL DSN 通过 `ROUTEBENCH_DSN` 覆盖；连接失败时自动回退 `ROUTEBENCH_SQLITE`（默认 `/tmp/routebench.db`）。

## FRR 容器实验室

* 完全本地、隔离：网络创建时带 `--internal`，不映射端口，不写任何生产凭据。
* 拓扑：`frr-a (AS65001, 172.30.0.2)` 与 `frr-b (AS65002, 172.30.0.3)` 建双栈 eBGP；
  A 上把全部测试前缀以 `ip/ipv6 route X Null0` + `redistribute static` 注入 BGP，
  出向 `route-map RB_*_OUT` 引用按当前策略渲染的 prefix-list。
* 观测：每轮下发配置 → `clear bgp ... soft out` → 轮询 B 的
  `show bgp ipv4/ipv6 unicast json` 至连续两轮稳定 → 与模拟器逐前缀比对。

UI：打开“FRR 容器验证”→ 启动实验室 → 跑内置案例；
或命令行：

```bash
pytest tests/test_frr.py --run-frr -q            # 需要本机 docker 与拉取 frrouting/frr:latest
```

## 语义模型要点（与 FRR 对齐）

1. `ip prefix-list ... permit 10.0.0.0/8`（无 ge/le）只匹配 **10.0.0.0/8 本身**；
   要全锥形必须显式 `ge 8 le 32`。
2. prefix-list 按 seq **首条匹配**，末尾隐式 `deny any`；默认 permit 用尾部
   `permit 0.0.0.0/0 le 32`（v6 为 `::/0 le 128`）显式表达，使默认动作在容器中可观测。
3. route-map 用单个 permit 序列引用该 prefix-list，再补一条显式空 deny 兜底。
4. 策略中 v4 与 v6 规则数组虽合并存储，但求值按族严格分流；引擎任何判定都不会跨族。

## 行为差异为什么不能只做文本 diff

一条 `permit 10.1.0.0/16 ge 24 le 32` 覆盖的是一棵子树在长度区间上的全部前缀。
引擎把两版策略的锚点前缀放入同一棵二进制 Trie，切分出互不重叠的**行为单元**
（锚点精确格 + 不含锚点的最大间隙子树），在所有规则范围边界（ge、le、le+1、锚点深度）
上取样判定；只有这样才能同时：

* 不漏报：任何真实行为变化都落在某个见证所代表的区域（测试中用小规模穷举验证完备性）；
* 不多报：同一长度、同一前后判定签名的区域只保留一个见证（最小集合）；
* 抓得住“同动作换命中规则”：遮蔽/换序即使 permit/deny 不变也会出现在最小集合里；
* IPv6 不爆炸：见证数有界（几十个单元），绝不枚举 2^128 空间。

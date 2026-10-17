# oss-health · 开源项目健康度扫描器

判断一个依赖包是**还在被真人维护**，还是已经进入「活死人（zombie）」状态。

不看单一的 Last Commit 时间，而是回答四个问题：

1. **提交活跃度**：最近还有真人 commit / 回 Issue / 处理 PR 吗？长期没人理的 issue 就是危险信号。
2. **维护者状态**：核心维护者是不是只剩一个人？有没有声明过弃坑（archive / deprecated）？
3. **社区温度**：issue / PR 是不是在堆积未回？fork 很多但 star 增长停滞了吗？
4. **发布节奏**：release 频率有没有断崖？关键 bug 是不是长期不修？

最关键的一条设计原则：**和项目自己的历史基线比，而不是和别人的绝对速度比**。
一个一年只发两个补丁的安全库可以是健康的「慢但稳」，而一个上周还在发版的明星项目可能已经彻底停摆。
所有活跃度判断都会先取项目自身 52 周的提交基线，再判断「异常安静」还是「正常节奏」。

---

## 快速开始

```bash
# 不需要安装，Python 3.10+，零第三方依赖
python3 -m oss_health pypi:requests          # 扫描 PyPI 包
python3 -m oss_health npm:express            # 扫描 npm 包
python3 -m oss_health nuget:Newtonsoft.Json  # 扫描 NuGet 包
python3 -m oss_health github:psf/requests    # 只扫仓库
python3 -m oss_health requests               # 自动在 PyPI / npm / NuGet 里找

# 离线示例（不需要网络、不消耗 API 配额）
python3 -m oss_health demo --list
python3 -m oss_health demo pycrypto --no-color

# 输出格式
python3 -m oss_health pypi:requests --format md   -o reports/requests.md
python3 -m oss_health pypi:requests --format html -o reports/requests.html
python3 -m oss_health pypi:requests --format json -o reports/requests.json
```

也可以 `pip install -e .` 之后直接用 `oss-health`（`pyproject.toml` 已配置 console script）。

已生成的示例报告见 [`reports/`](reports/)：

| 示例 | 目标 | 得分 | 结论 | 演示的信号 |
|---|---|---|---|---|
| [requests](reports/requests.md) | `pypi:requests` | 94.8 → A | 可以放心使用 | 健康基线：维护者稳定回 Issue、依赖无漏洞、运行时跟得上 |
| [pycrypto](reports/pycrypto.md) | `pypi:pycrypto` | 35 → D | 高风险 | 归档 + 未修复严重 CVE + 无真人活动（多项一票否决） |
| [newtonsoft-json](reports/newtonsoft-json.md) | `nuget:Newtonsoft.Json` | 73.8 → B | 基本可用，注意跟踪 | .NET target framework 分析（仓库元数据缺失时降级） |

---

## 判定思路：怎么识别「活死人」

每个维度先计算 0–100 的信号分，再按权重加权。**难点不是「算准速度」，而是「不误伤」**，
所以每个维度都刻意采用「多信号取最优」而不是「各项扣分累加」：

### 1. 提交活跃度（权重 20）

* 近 90 天提交总数，且区分**真人提交**与**机器人提交**（dependabot / renovate / github-actions 等）。
  机器人提交不算维护证据；`web-flow` 这类 GitHub 网页合并 committer 也不算机器人。
* **项目自身节奏基线**：取 GitHub `/stats/participation` 的 52 周数据，
  计算「之前 39 周的周均提交」作为历史节奏，和「最近 13 周」比较：

  | 最近 90 天 / 历史节奏 | 判定 |
  |---|---|
  | ≥ 50% | 正常，不扣分 |
  | 25% – 50% | 节奏明显放缓（轻度扣分） |
  | < 25% | **提交断崖**（重度扣分） |

* 最近一次提交时间同样做**相对化**：如果一个项目历史节奏本来就是「每 40 天提交一次」，
  那 120 天没提交只接近正常间隔的 3 倍，只轻微扣分，并明确写进报告
  「属于低频但稳定，不视为停摆」。
* 机器人占比过高（≥80%）、近 90 天只有 1 个真人贡献者（bus factor 风险）会额外提示。

### 2. 维护者状态（与发布节奏合并判断）

* **弃坑声明**：仓库 `archived` / `disabled`、包被标记 `deprecated`（含废弃原因）、版本被 `yank`。
  这些是硬证据，直接触发**一票否决**，详见下文「封顶规则」。
* **是否只剩一人**：统计真人提交作者数；只有 1 人且提交 ≥3 次时提示 bus factor；
  单一贡献者占比 ≥90% 也会提示。
* 真人提交的**性质**：区分「功能/修复类提交」和「CI/依赖类运维提交」。
  只有机器人提交、或真人只在 bump 依赖 → 代码本身已经停止演进，会额外扣分。

### 3. Issue / PR 响应（权重 22 / 13）

「长期没人理 issue」是活死人最可靠的信号之一，但直接看回复率会误伤大仓库
（requests 每天几十条 issue，维护者不可能每条都回）。所以采用**多信号取最优**：

* **信号 A（维护者是否在回应）**：近 90 天获得维护者（`OWNER`/`MEMBER`/`COLLABORATOR`）回复或关闭的 Issue 数。
  `≥3` 条视为响应正常；`0` 条且也没有关闭任何 Issue → 重罚。
* **信号 B（开放问题是否被晾着）**：开放 Issue 中窗口内无人回复的比例 `≥85%` → 重罚。
* **信号 C（新 Issue 真人回复率）**：仅当维护者整体不活跃时才作为主罚项，
  否则只写进说明（因为大仓库回复率天然低）。
* **信号 D（响应速度）**：首次真人 / 维护者响应时间中位数，按 7 / 14 / 30 天分级。
* **信号 E（评论是否被机器人占领）**：评论中机器人占比 ≥70% → 扣分。
* **信号 F（关键 bug 长期不修）**：带 `bug`/`crash`/`regression`/`security` 等标签、
  开放超过 **180 天**且无人回复的 Issue 数 → 扣分。这是「关键 bug 长期不修」的直接证据。
* **PR 侧**：近 90 天真人 PR 是否有被合并/关闭；超过 90 天未合并的 PR 积压数量；
  **真人 PR** 从创建到合并的中位数（真人 PR 要等 45 天才合 = 维护者基本不管事了）。

反过来，这些情况**不扣分**，避免误伤成熟项目：

* 合并 PR 的是机器人 —— 如果是 dependabot 的依赖升级 PR，自动合并是**最佳实践**。
  只有「人类 PR 也被机器人合并」或「所有 PR 都是机器人提交」才扣分。
* 只有依赖机器人 PR 没有代码评审评论 —— 正常。

### 4. 社区温度（合并进维护活跃度）

* **fork 多但 star 停滞**：无 Token 时 GitHub 的 stargazers 接口需要认证，
  改用 `/repos/{owner}/{name}/events`（最近 100 条公开事件）统计 90 天内的 `WatchEvent` / `ForkEvent`，
  按事件覆盖的时间跨度折算成「每月新增 star」，再与项目历史平均增速
  （`stars / 仓库年龄月数`）比较。近期增速低于历史 10% 且 fork/star 都很多 → **热度停滞**。
* 有 `GITHUB_TOKEN` 时优先用 stargazers 时间戳精确统计。

### 5. 发布节奏（合并进维护活跃度）

* 最近一次发布时间、近一年发布次数（GitHub Release，缺失时回落到包注册表的发布时间）。
* **发布断崖**：前 90 天发布过 ≥2 次、近 90 天发布数 ≤ 前 90 天的 25%（或归零）→ 断崖。
  这比「多少天没发版」更能反映「突然停摆」。

### 另外两个维度（不属于「活死人」，但决定「还能不能用」）

* **运行时 / target framework（权重 13）**：PyPI classifiers / `requires_python` 对照
  endoflife.date 的 Python 支持周期；npm `engines` 对照 Node 版本；NuGet 的 TFM 是否还在
  `netstandard2.0` / 老 `net4x`（.NET Framework 已停止演进）。
* **自身漏洞（权重 20）+ 依赖漏洞（权重 12）**：OSV.dev 查询当前版本与直接依赖，
  按 CVSS v3 严重度分级扣分（CVSS 3.0/3.1 评分由内置计算器从向量计算，不依赖第三方库）。

---

## 评分与封顶

维度权重（缺数据时其余维度按比例重新归一，并降低置信度）：

| 维度 | 权重 | 说明 |
|---|---|---|
| 维护活跃度 | 20 | 提交、节奏基线、bus factor、发布断崖、star 停滞 |
| Issue 响应 | 22 | 维护者是否回/关 Issue、响应速度、长期未修 bug |
| PR 健康度 | 13 | 真人 PR 是否被处理、机器人合并、积压 |
| 运行时 / 框架 | 13 | Python / Node / .NET target framework |
| 自身漏洞 | 20 | 当前版本未修复 CVE |
| 依赖安全 | 12 | 直接依赖的 CVE |

等级：

| 分数 | 等级 | 结论 |
|---|---|---|
| ≥80 | A | 可以放心使用 |
| ≥65 | B | 基本可用，注意跟踪 |
| ≥50 | C | 谨慎使用，建议锁定版本 |
| ≥35 | D | 高风险，建议准备替代方案 |
| <35 | F | 不建议新项目使用，尽快迁移 |

**一票否决（硬性封顶）** —— 出现以下任一情况，总分不会超过上限：

| 触发条件 | 封顶 |
|---|---|
| 仓库已归档 archived | 35 |
| 包被标记 deprecated | 35 |
| 当前版本存在未修复的**严重**（CVSS ≥ 9）漏洞 | 40 |
| 近 90 天无任何真人维护者活动（真人提交 / 维护者回复或关闭 Issue / 合并或关闭 PR） | 45 |
| 仓库被 GitHub 禁用 | 25 |

---

## 数据来源与采集成本

| 来源 | 用途 | 认证 |
|---|---|---|
| PyPI JSON / npm registry / NuGet registration + nuspec | 版本、依赖、TFM、废弃状态、仓库地址 | 不需要 |
| GitHub REST API | 提交、参与度统计、Issue、评论、PR、Release、事件 | 可选 Token |
| OSV.dev | 漏洞公告（GHSA / CVE / PySec / GMSA 去重合并） | 不需要 |
| endoflife.date | Python / Node.js / .NET 支持周期 | 不需要 |

无 Token 时 GitHub 限 60 次/小时，一次扫描约 10–12 次请求（缓存 TTL 6 小时、支持 ETag 条件请求）。
**强烈建议**设置 `GITHUB_TOKEN`（或 `GH_TOKEN`），限额提升到 5000 次/小时，且能拿到更精确的 star 数据：

```bash
export GITHUB_TOKEN=ghp_xxx
python3 -m oss_health pypi:requests
```

限流时的降级策略：某个维度的数据拿不到就标记「无数据」并重新归一权重，
报告里会写明缺了什么，而不是算出一个不可信的分数。

---

## 离线 demo / 快照回放

```bash
python3 -m oss_health demo --list        # 查看已录制的示例
python3 -m oss_health demo pycrypto      # 完全离线回放（不联网、不消耗配额）
python3 scripts/record_demo.py --list    # 查看可录制目标
python3 scripts/record_demo.py --only requests --force
```

快照是原始 HTTP 响应（`demo/snapshots/<name>/*.json`）+ `manifest.json`（记录录制时间 `recorded_at`）。
回放时把「当前时间」固定为 `recorded_at`，因此**任何时候回放都得到同样的分数**，
录制脚本会自动做一次离线回放校验，分数不一致会报警。

---

## 局限性（重要）

* Issue / PR 统计基于最近 100 条采样，绝对值可能偏低；PR 合并者只抽查少量已合并 PR。
* 依赖按「锁定版本或当前最新版本」启发式检查，不是完整 SBOM / 传递依赖审计。
* 运行时支持周期来自 endoflife.date，与厂商实际策略可能有差异。
* 活跃度的「基线相对化」需要至少几个月的提交历史；极早期项目（<6 个月）基线样本不足。
* 「关键 bug 长期不修」依赖 Issue 的 bug 类标签；不打标签的项目只能靠评论/关闭情况间接判断。
* 报告只用于筛掉明显有问题的依赖，重要依赖请人工复核。

---

## 目录结构

```
oss_health/
  cli.py            # 命令行入口（scan / demo / list-demos）
  scanner.py        # 扫描编排：解析目标 -> 采集 -> 分析 -> 评分
  config.py         # 权重、档位、封顶规则、阈值、机器人名单
  models.py         # 所有数据模型
  sources/          # pypi / npm / nuget / github / osv / eol 数据源
  analyzers/        # maintenance / issues / pull_requests / framework / security / dependencies
  scoring.py        # 加权、一票否决、置信度、行动建议
  report/           # console / markdown / json / html 四种渲染
  versions.py       # PEP440 / SemVer / NuGet 版本比较（纯标准库）
  cvss.py           # CVSS v3.0/v3.1 评分
tests/              # unittest（含完全离线的假 API 端到端测试）
scripts/record_demo.py
demo/snapshots/     # 离线快照
reports/            # 生成的示例报告
```

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试全部离线运行（`tests/fake_api.py` 模拟 PyPI / GitHub / OSV / endoflife.date），
不消耗任何 API 配额。

---

## Star History

<p align="center">
  <a href="https://www.star-history.com/#akong789aaa/project_health_test&Date">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=akong789aaa/project_health_test&type=Date&theme=dark" />
      <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=akong789aaa/project_health_test&type=Date" />
      <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=akong789aaa/project_health_test&type=Date" />
    </picture>
  </a>
</p>

---

## 支持作者

如果这个项目帮你筛掉了几个不靠谱的依赖，可以请作者喝杯咖啡 ☕

<p align="center">
  <img src="payment.jpg" alt="收款码" width="280">
</p>

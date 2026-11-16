# Loon 节点纯净度检测插件

检测代理节点出口 IP 的「纯度」：是不是机房 IP、有没有被标记成代理 / VPN / Tor、欺诈分多高、注册地与定位是否一致，最后给一个 0–100 的评分和使用建议。

面向的场景是注册、绑卡、下单这类会被风控盯上的操作——**分数低不等于节点不能用**，机场节点基本都是机房 IP，60 分上下很正常。

## 一键安装（iPhone）

在 iPhone 上点链接，会拉起 Loon 弹出安装确认：

| 版本 | 导入链接 |
| --- | --- |
| 通知版 | `loon://import?plugin=https://cdn.jsdelivr.net/gh/leeby9699/leeby@main/Loon-NodePurity.plugin` |
| 卡片版 | `loon://import?plugin=https://cdn.jsdelivr.net/gh/leeby9699/leeby@main/card/Loon-PurityCard.plugin` |

> 链接里的 `@main` **必须保持原样**，不能写成 `%40main`。jsDelivr 对 URL 编码后的 `@` 会直接返回 400（`Invalid URL`），Loon 收到这段报错文字就会提示「插件内容不是有效的」。

不方便点链接就用 Loon →「配置」→「插件」→ 右上角 `+` → 选 URL，粘贴：

```
https://cdn.jsdelivr.net/gh/leeby9699/leeby@main/Loon-NodePurity.plugin
https://cdn.jsdelivr.net/gh/leeby9699/leeby@main/card/Loon-PurityCard.plugin
```

这种方式最稳：Loon 会直接下载你粘贴的地址，不经过任何链接跳转。

二维码在 `assets/` 目录：`qr-notify.png`、`qr-card.png`。

## 兼容版本

| Loon 版本 | 用哪个文件 | 脚本语法 |
| --- | --- | --- |
| **3.5.1 (983) 及以上**（含 3.5.3） | 根目录的 `Loon-NodePurity.plugin`、`card/Loon-PurityCard.plugin` | 新版 `generic then script(...) with ...` |
| 3.2.1 – 3.5.0 | `legacy/` 下的同名文件 | 旧版 `generic script-path=...` |
| Quantumult X | 直接用 `card/purity-card.js` | QX 的 `event-interaction` |

新版语法从 Loon 3.5.1 (983) 开始引入，旧写法仍作为输入兼容，但 Loon 自己保存配置时统一输出新语法——所以 3.5.1 之后建议直接用根目录这版，少一层兼容转换。

`#!loon_version` 只是「最低版本要求」的声明，不是「只支持该版本」。根目录版本声明为 `3.5.1(983)`，`legacy/` 版本声明为 `3.2.1(734)`。

## 两个版本

| | 通知版 | 卡片版 |
| --- | --- | --- |
| 交互 | 运行后弹系统通知，点通知复制完整报告 | 运行后直接弹出 HTML 详情卡片 |
| 数据源 | ipinfo.io + ip-api.com + api.ip.sb + scamalytics.com（四源交叉） | IPPure + ipinfo.io（两次请求，秒出） |
| 信息量 | 更全：扣分明细、注册地、未响应数据源、ASN 类型 | 更直观：评分、住宅/机房/广播判定、欺诈分 |
| 额外能力 | 支持 `cron` 每日巡检 | 脚本同时兼容 Quantumult X |

两个可以同时安装，互不冲突。

## 使用

1. 装好插件，确认插件处于**开启**状态；
2. Loon 首页 →「脚本」→ **节点纯净度检测** / **节点纯净度详情**；
3. 选择要检测的节点 → 运行。不选节点则检测当前出口策略。

脚本通过 `$environment.params.node` 取节点名，再用 `$httpClient` 的 `node:` 参数把请求绑定到该节点，所以测的是节点本身的出口，不是你本机直连。

**通知版**的报告行数较多，通知正文放不下，**点一下通知**会把完整报告复制到剪贴板。

**卡片版**直接把 HTML 卡片渲染出来，无需再复制。

## 文件

```
purity.js                    通知版脚本
Loon-NodePurity.plugin       通知版插件（新语法，3.5.1+）
card/purity-card.js          卡片版脚本（Loon / QX 通用）
card/Loon-PurityCard.plugin  卡片版插件（新语法，3.5.1+）
legacy/                      旧语法插件（3.2.1 – 3.5.0）
assets/qr-notify.png         通知版导入二维码
assets/qr-card.png           卡片版导入二维码
```

## 评分模型

基线 100 分，按命中项扣分：

| 命中 | 扣分 |
| --- | --- |
| 机房 / 数据中心 IP | −38 |
| Tor 出口 | −30 |
| 代理、VPN 标记 | −15 |
| 中继 | −8 |
| 广播 IP | −12 |
| 注册地与定位不一致 | −6 |
| 欺诈分 | 分数 × 0.3（卡片版 × 0.35） |

等级：85+ 干净 / 70–84 良好 / 55–69 一般 / 40–54 较差 / 40 以下高危。

想放宽或收紧，改 `purity.js` 里 `render()` 中的 `score -=` 数值，或把顶部 `CONF.useFraud` 设为 `false` 关掉欺诈分。

## Quantumult X

卡片版脚本无需修改即可在 QX 使用，把这行放进 `[task_local]`：

```
event-interaction https://cdn.jsdelivr.net/gh/leeby9699/leeby@main/card/purity-card.js, tag=节点纯净度详情, img-url=checkmark.shield.fill.system, enabled=true
```

QX 里没有 `[Panel]`/`generic` 的概念，`event-interaction` 就是它的交互式脚本类型；Loon 对应的是 `generic`。

## 常见问题

**导入时提示「插件内容不是有效的」**
先确认地址是 `@main` 而不是 `%40main`（见上文）。若用 `loon://` 链接仍失败，改用 Loon →「配置」→「插件」→ `+` → 选 URL，直接粘贴上面那两条 https 地址。

**插件装了但「脚本」里没有这一项**
不同版本入口不同：3.5 之后在首页「脚本」列表；老版本在「配置 → 脚本」。条目被标红通常是脚本地址不可达。

**分数很低，是节点坏了吗**
不是。机房 IP 天然会被扣分，只要不是高危、欺诈分不离谱，上网没问题。真正在意纯净度的只有注册、支付、抢购这类场景。

**能测 IPv6 吗**
可以。节点走 IPv6 出口时，报告显示的就是 IPv6 地址，评分逻辑一致。

**数据源偶尔显示「未响应」**
任一数据源限流或被墙都不会导致检测失败，只是少一路交叉验证；报告底部会标注。

## 说明

脚本不收集、不上传任何数据，只把出口 IP 发给上述公开查询接口。分数是基于公开情报的**推测**，不构成对节点服务商的判断。

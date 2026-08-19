# AVCheck2

一个离线、无第三方依赖的 Windows 进程列表识别工具。它将进程名与本地维护的规则库比对，输出可能关联的安全产品及命中证据。

本仓库是对 [AVCheck](https://github.com/wwl012345/AVCheck) 的个人维护与学习分支，主要关注数据可维护性、输入可靠性与结果可复核性。

## 工作方式

```text
进程列表文本 / tasklist CSV
             ↓
提取进程名（不区分大小写）
             ↓
与本地 JSON 规则库比对
             ↓
输出去重后的产品及可选命中详情
```

它不会扫描文件、修改系统设置、访问网络或执行规避操作；输入、规则和输出均为本地文本处理。

## 环境

- Python 3.9+
- 无第三方 Python 依赖

可选地创建本地环境：

```powershell
python -m venv .venv
```

## 使用方式

准备一份由你本人设备或已获授权环境导出的进程列表文件：

```powershell
# tasklist 的默认表格输出，或每行一个进程名
python AVCheck.py tasklist.txt

# 兼容旧用法
python AVCheck.py -f tasklist.txt

# Windows tasklist CSV 输出
tasklist /fo csv | Out-File -Encoding utf8 tasklist.csv
python AVCheck.py tasklist.csv --input-format tasklist-csv
```

默认自动识别以 `Image Name,` 开头的 tasklist CSV；其他输入按常规 tasklist 表格处理。对于纯进程名列表，显式指定格式：

```powershell
python AVCheck.py processes.txt --input-format process-list
```

默认依次尝试 `utf-8-sig` 和 `gb18030` 解码输入；需要时可指定编码：

```powershell
python AVCheck.py tasklist.txt --encoding utf-16
```

## 输出与自动化

默认输出去重后的产品名称。使用 `--details` 可附加“进程名 → 产品”的命中详情：

```powershell
python AVCheck.py tasklist.txt --details
```

使用 JSON 输出便于后续脚本处理；JSON 始终包含汇总的 `products` 和逐项证据 `matches`：

```powershell
python AVCheck.py tasklist.txt --format json
```

命令成功返回 `0`；输入文件或编码错误返回 `3`；规则文件缺失或格式不正确返回 `4`。诊断信息写入标准错误，结果写入标准输出。

## 规则库

[av_signatures.json](av_signatures.json) 是版本化的本地规则库。每条规则具有进程名及一个或多个对应产品：

```json
{
  "version": 1,
  "signatures": [
    {
      "process": "MsMpEng.exe",
      "products": ["Windows Defender"]
    }
  ]
}
```

默认规则文件按脚本自身所在目录定位，因此可在任意工作目录执行。可以用 `--rules <路径>` 替换为自定义规则库。规则仅依赖进程名，不能证明产品已启用或防护正在生效；进程改名、组件更新和同名程序都可能带来漏报或误报。

## 测试

```powershell
python -m unittest discover -s tests -v
```

测试覆盖规则读取、大小写无关匹配、去重、纯进程名 / tasklist / CSV 输入解析，以及常见失败退出码。

## 隐私与使用边界

进程列表可能暴露设备上安装的软件、远程管理工具或运行环境。请勿提交、上传或公开真实生产设备导出的进程清单；发布示例时应使用脱敏或虚构数据。

结果仅供资产盘点、实验环境确认或安全运维学习参考，不能代替专业安全产品或正式审计结论。

## 致谢

原项目：[wwl012345/AVCheck](https://github.com/wwl012345/AVCheck)。

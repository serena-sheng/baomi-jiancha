# 07 · 第二轮代码复核（v0.4.0）

结论：P0-1、P1-2 已修；P0-2、P1-1、P1-3 部分修；endSweep 分批改写引入新 P1。

1. 中断 sweep 删光索引 — 已修。Scanner.run 加 complete（main.swift:164），根枚举 nil（169-173）、触顶/停止（175-179）置 false；仅完整才 endSweep()，否则 abandonSweep()（213-217；Store.swift:110-113 只清 seen）。

2. endSweep 分批删 — 未修，且有新 bug。Store.lock 仍覆盖整段（Store.swift:115-134），分批只缩小事务。gone 循环内不递减，LIMIT 5000 每轮取同一批，第二次 changes==0 即 break（122-131）：单次 sweep 最多删 5000 条 files 与 5000 条 findings，幽灵记录永久残留 → P1。

3. 主线程阻塞 — 部分修。refresh() 挪到 readQueue（main.swift:781-798），扫描中复用旧 rows；但 updateStatusIcon（728）、rebuildMenu（737）仍在主线程调 counts()，与 endSweep 同锁，收尾仍卡。

4. Shell.run 超时 — 部分修。Engine.swift:19-54 已改：stderr→nullDevice、stdout 后台读、超时 terminate→SIGKILL。handler 装在 run() 之后（40-41），实测 Darwin 对已退出进程补装仍回调（200 次无遗漏），顺序无害。soffice 未动：convert()（1551-1559）两 Pipe 不读、waitUntilExit 无超时，脱密仍可能永不返回。

5. 跨卷回滚 — 已修。transfer() 用 copy+remove 兜底（1202-1209）；回滚失败先置 trashedTo 并报出回收路径（1703-1728）。

6. FSEvents 补扫命中被 sweep 删 — 已修。rescan 补 markScanned（main.swift:866-870）。隐患：rescanBusy 的 defer 在派发后立即执行（844-845），标志不覆盖工作期，flush 可叠加。

新 P1
- Store.swift:122-131：清理截断在 5000 行；应边删 gone 边推进，锁按批释放。
- Engine.swift:1362-1369：结构校验不生效。cleanOOXML 把「退出码」「成员不一致」当 actions 返回，produce()（1646-1659）只看 dst 是否存在；残包因「查不出命中」判 ok，原件进回收目录、坏包回原位。另 comments.xml 跳过不写（1316），成员集合相等对带批注文件必然不等。

P2 残留：OFD repack 仍 ?? Data()、不看退出码（552-562）；undo() 在主线程跨卷 transfer。

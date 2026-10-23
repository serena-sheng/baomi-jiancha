# 04 · 代码评审（Store / Scanner / DirWatcher / declass / Engine）

**结论**：P0-1、P0-2 必须改完才能发。原件不会被永久删除（`removeItem` 只碰临时目录与重打包目标），但有两条"原件离开原位／被坏副本顶替"的路径（P1-2、P1-3）。

## P0

**P0-1 `main.swift:164-206`＋`Store.swift:97-113`｜中断的 sweep 清空全库。** 枚举中点停止（167 break 只退当前根）、触顶 200 万（172）、某根 `enumerator` 为 nil（168 continue）时，`seen` 只含部分路径，`endSweep` 仍执行 `DELETE FROM files WHERE path NOT IN seen`，再 `DELETE FROM findings WHERE path NOT IN (SELECT path FROM files)` 删光命中。后果：清单与计数归零且不回滚，用户得到"机器干净了"的错误结论。改：加 `sweepComplete` 标志，`isStopped() || 触顶 || rootFailed` 时只 `DELETE FROM seen`；并补 `CREATE INDEX idx_find_path ON findings(path)`——现在每路径全表扫，200 万文件是平方级。

**P0-2 `main.swift:681-696`＋`Store.swift:109`｜主线程卡在 Store 锁。** `refresh()` 在 main 上取 `Store.lock` 跑 `counts()`+`findings(800)`，而 `endSweep` 持同一把锁删 200 万行；扫描中每 40 个文件 main.async 一次（198-203），`updateStatusIcon`/`rebuildMenu` 又各调一次 `counts()`（628、637）。后果：界面整秒冻结。改：DB 读放 `DispatchQueue(label:"store.read")`，回主线程只赋值；扫描期 refresh 节流 ≥1 s；endSweep 每 5000 行一事务。

## P1

**P1-1 `Engine.swift:21-33、882-886、1510-1517`｜外部进程无超时、stderr 管道不读。** `Shell.run` 先 `readDataToEndOfFile()` 再 `waitUntilExit()`，stderr 写满管道即死锁；soffice/zip/unzip 均无超时。后果：`declass`（main.swift:759-789）永不返回，`processing` 恒 true，脱密按钮全禁用且无取消，只能强退。改：5/10 s（zip、unzip）与 120 s（soffice）定时器 + `terminate()`；stderr 接 `FileHandle.nullDevice`；`terminationStatus != 0` 即失败。

**P1-2 `Engine.swift:1654-1683`｜跨卷 moveItem 失败，回滚也失败却报"已回滚"。** 回收目录在启动卷，扫描含 `/Volumes/*`；最后一次 `moveItem` + 回滚 `moveItem(target→u)` 都跨设备，`try?` 吞掉后仍写"已回滚"。后果：外置盘文件从原位消失（躺在回收目录），界面说原件没动。改：跨卷 `copyItem`+`removeItem`；失败路径也赋 `trashedTo` 并改文案"原件已移至 X"；返回前断言原位或回收目录必有一份。

**P1-3 `Engine.swift:1266-1328、532-542`｜重打包丢成员／写空成员却通过复检。** 读不出的成员 `continue`（1266）后 `zip -r` 只发警告且不查退出码（1328）；`repack` 用 `?? Data()` 写空成员（532）。复检只比对 findings，坏包反而"查不出命中"（1614-1626）→ 判 ok，原件进回收目录。改：成员失败即返回错误、去掉空 Data、查 `terminationStatus`、复检加结构断言（成员集合 ⊇ 原集合且 `document.xml` 非空）。

## P2

**P2-1 `main.swift:165-184`｜200 万 URL 全量常驻。** 先枚举再检查，每项约 250–400 B → 0.5–0.8 GB，与 spec「只留路径」冲突，内存压力下被 jetsam。改：边收边查；暂存改 `[String]`，每 5 万条 `autoreleasepool`。

**P2-2 `main.swift:719-741`｜补扫重复 OCR 且与 files 表不同步。** 每批对变更目录前 50 个文件全量 OCR，却不 `markScanned` → 无 `files` 行，下一次 `endSweep` 删掉这些命中（Store.swift:112），表现为命中行自己消失；无 in-flight 标志，5 s 批次可叠加。改：补 `markScanned`；加 `rescanBusy` 串行化；只处理事件里的路径。

**P2-3 `main.swift:862-869`｜FSEvents 无 stop/invalidate。** 无 `deinit`，`FSEventStreamStop/Invalidate/Release` 未调用；回调用 `passUnretained(self)`，靠 AppDelegate 强持有兜着，置 nil 即 UAF；重复 `start()` 覆盖 `stream` 泄漏旧流。改：deinit 里 Stop+Invalidate+Release，`guard stream == nil`，改 `passRetained` 配 release 回调。

## 直接回答

1. **丢数据／误删**：无永久删除，但 P0-1 丢整份检查结果，P1-2、P1-3 让原件离开原位或被坏副本顶替。
2. **主线程阻塞**：有，P0-2。

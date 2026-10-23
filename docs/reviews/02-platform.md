# 02 · macOS 平台评审

**结论**：不像系统自带工具。三项差距：① 32pt 标题栏是空条，窗口标题与内容 H1 重复；② 整窗 `.regularMaterial` + 自绘控件，读作 HUD 面板；③ 无主菜单与快捷键，⌘W/⌘Q/⌘A/Esc/Tab 全断。

**基线**：10 张预览均为 600×560 离屏视图（无窗框），不能证明标题栏。同配置复现（macOS 27）：窗口 600×592、标题栏 32、内容自 y=32 起；灰标题在 (82,18)，H1 在 y≈50，同一句两次，见 `window-probe.png`。未启动真实 app（会写库扫描）。

1. **标题栏**：`main.swift:535-540` 只设 `titlebarAppearsTransparent`，`titleVisibility` 仍 visible。改：`w.titleVisibility = .hidden`；加空 NSToolbar + `w.toolbarStyle = .unified`，「开始扫描/停止」移入，头部 16pt 内距不变。
2. **材质层级**：`main.swift:387` 把 `.regularMaterial` 铺满窗口，而窗口底色不透明（复现图整窗一色）。改：`w.backgroundColor = .windowBackgroundColor`，内容同色；材质只给 56pt 底栏（`.headerView`）；选中行用 `selectedContentBackgroundColor`。
3. **控件尺寸**：`Design.swift:36-37` ghost 28 / primary 32 同排两个高度，系统常规按钮 22；勾选框 14、行高 68 达标。改：ghostH 22、primary 28、底栏 52；14pt 方框保留，整行 `contentShape` 可点（单击选中、双击访达）。
4. **窗口行为**：`main.swift:535` 缺 `.resizable`，600×560 锁死；539 的 `isMovableByWindowBackground` 会吞行内拖拽。改：加 `.resizable`、`minSize 520×420`、`setFrameAutosaveName("Main")`，内容改 `minWidth/minHeight`（固定 600×560 会让缩放无效）；`activate(ignoringOtherApps:)` → `activate()`（13 需 `#available`）。
5. **键盘**：无 `mainMenu`、无 `keyboardShortcut`（grep 0 命中）；菜单里 `"r"` 仅展开时生效，不能替代窗口快捷键。改：建五项主菜单（⌘W/⌘Q/⌘A/⌘R）+ `.onExitCommand` + 按钮 `.focusable()`；Return 不得绑「脱密」（约束 1）。
6. **辅助功能**：`main.swift:296` 只报「选择/取消选择」；每行「脱密」重名；624 行三态共用「保密检查」，标题 ` 3` 无单位。改：行 `.accessibilityElement(children:.combine)` 并入文件名与等级；按钮 label「脱密 <文件名>」；图标 15pt→16pt，描述随状态变（「保密检查，正在扫描」）。

# -*- coding: utf-8 -*-
"""简体中文翻译：内存马取证（forensics）与处置（remediation）。

由 memory-shell 取证/处置特性的作者维护，``build/build_zh_catalog.py`` 会把这里的
``ZH_MAP_EXTRA_MEMSSHELL`` 合并进 zh 目录。与 ``zh_map.py`` 已有的条目保持同一用词
（例如 Forensics→取证、Actions→操作、On disk→磁盘存在），只补充本特性新增的文案。

不修改 ``build/zh_map_extra.py``，也不运行 catalog 重建。
"""

ZH_MAP_EXTRA_MEMSSHELL = {
    # ── 页面标题、导航与通用词 ───────────────────────────────────────
    "Memory Shell Forensics": "内存马取证",
    "Forensics": "取证",
    "Remediate": "处置",
    "Manifest": "清单",
    "Actions": "操作",
    "On disk": "磁盘存在",
    "Class": "类",
    "Component": "组件",
    "Artifact": "制品",
    "Artifacts": "制品",
    "Size": "大小",
    "Files": "文件",
    "Remediated": "已处置",
    "Removed": "已移除",
    "Heap": "堆",
    "Heap dump": "堆转储",
    "Heap failed": "堆转储失败",
    "Class bytes": "类字节码",
    "No class bytes": "无类字节码",
    "Stored": "已保存",
    "Not available": "不可用",
    "source unknown": "来源未知",
    "Reason not reported.": "未报告原因。",
    "bytes": "字节",
    "attempts": "次尝试",
    "file(s)": "个文件",
    "Declared methods": "声明的方法",
    "Declared fields": "声明的字段",
    "URL patterns": "URL 匹配",
    "Code source": "代码来源",
    "Protection domain": "保护域",
    "Context path": "上下文路径",
    "Probe URL": "探针 URL",
    "Loader identity": "类加载器标识",
    "JVM input arguments": "JVM 启动参数",
    "JVM self-attach": "JVM 自附着",
    "Container": "容器",
    "Raw manifest.json": "原始 manifest.json",
    "Site:": "站点：",
    "Component:": "组件：",
    "Class:": "类：",
    "Forensics:": "取证：",
    "Heap dump:": "堆转储：",
    "Index keeps:": "索引保留：",
    "Dump bound:": "转储上限：",
    "Artifacts:": "制品：",
    "Store:": "存储目录：",
    "Forensics running for": "正在取证：",
    "Forensics artifacts": "取证制品",
    "Run forensics": "运行取证",
    # ── 取证面板 ─────────────────────────────────────────────────────
    "Forensics stores what the JVM could still be asked about one component: its manifest, the class bytes when they really exist, and an optional heap dump. Artifacts live on disk under the data directory and survive a restart.": (
        "取证保存的是「JVM 还能被问到的、关于某个组件的全部信息」：清单、真实存在时的类字节码，"
        "以及可选的堆转储。制品以文件形式存放在数据目录下，进程重启后依然保留。"
    ),
    "Forensics unavailable": "取证不可用",
    "No forensics artifact has been stored yet.": "尚未保存任何取证制品。",
    "Run forensics for this component": "对该组件运行取证",
    "Dump live objects only (smaller, pauses the JVM)": "仅转储存活对象（文件更小，会暂停 JVM）",
    "The heap dump is written by the target JVM into the artifact directory; it can take minutes.": (
        "堆转储由目标 JVM 直接写入制品目录，可能耗时数分钟。"
    ),
    "Open forensics from a finding on the detection tab (取证) to choose the component to dump. Each run stores a manifest, the class bytes when they exist, and optionally a heap dump.": (
        "请先在「检测」页的检出结果上点击「取证」，选择要转储的组件。"
        "每次取证都会保存清单、真实存在时的类字节码，以及可选的堆转储。"
    ),
    "No stored manifest exists for this artifact: the index has no entry, or the manifest file is unreadable. The artifact directory may have been moved or deleted outside Anteumbra.": (
        "该制品没有已保存的清单：索引中没有对应条目，或清单文件无法读取。"
        "制品目录可能已被 Anteumbra 之外的操作移动或删除。"
    ),
    # ── 处置对话框 ───────────────────────────────────────────────────
    "Confirm remediation": "确认处置",
    "Remediation result": "处置结果",
    "Remediation unavailable": "处置不可用",
    "No forensics artifact": "没有取证文件",
    "This removes the component from the container memory and cannot be undone.": (
        "处置会移除容器内存中的该组件，且不可恢复。"
    ),
    "A forensics artifact exists for this component, so the evidence is already stored. No file is deleted and no other component is touched.": (
        "该组件已有取证文件，证据已经落盘。处置不会删除任何文件，也不会触碰其他组件。"
    ),
    "There is no forensics artifact for this component. Remediate the memory shell without taking forensics first?": (
        "没有对应的取证文件。确认要在不取证的情况下处置内存马吗？"
    ),
    "Removing it destroys the only copy of what was registered in memory: the class bytes, the manifest and any heap dump are gone for good.": (
        "直接移除会销毁「内存中注册内容」的唯一副本：类字节码、清单与堆转储将永久丢失。"
    ),
    "The server refused the removal for that reason and changed nothing.": (
        "服务端因此拒绝移除，未做任何改动。"
    ),
    "Removed from the container memory.": "已从容器内存中移除。",
    "Refused; nothing was changed.": "已拒绝，未做任何改动。",
    "The request failed.": "请求失败。",
    "The component is still registered.": "该组件仍然处于注册状态。",
    "The post-action component list is on the detection tab.": "处置后的组件列表见「检测」页。",
    "Go to forensics": "前往取证",
    "Remediate now": "立即处置",
    # ── blueprint 提示 ───────────────────────────────────────────────
    "The forensics store did not answer: %(error)s": "取证存储未响应：%(error)s",
    "The forensics store returned no usable state.": "取证存储未返回可用状态。",
    "The forensics store is not available: %(reason)s": "取证存储不可用：%(reason)s",
    "unknown reason": "原因未知",
    "The forensics panel failed to render: %(error)s": "取证面板渲染失败：%(error)s",
    "The remediation dialog failed to render: %(error)s": "处置对话框渲染失败：%(error)s",
    "The manifest could not be rendered: %(error)s": "清单渲染失败：%(error)s",
    "No such forensics artifact file.": "不存在该取证制品文件。",
    "No site was selected for forensics.": "未选择要取证的站点。",
    "No site was selected for remediation.": "未选择要处置的站点。",
    "No component kind was selected for remediation.": "未选择要处置的组件类型。",
    "No component was selected for remediation.": "未选择要处置的组件。",
    "Select a component in the detection tab (or open forensics from a finding) before running forensics.": (
        "请先在检测页选择组件（或从检出结果点进取证页），再运行取证。"
    ),
    "Forensics could not be started: %(error)s": "取证无法启动：%(error)s",
    "The remediation request failed: %(error)s": "处置请求失败：%(error)s",
    "The component is still registered: %(class_name)s": "该组件仍然处于注册状态：%(class_name)s",
}

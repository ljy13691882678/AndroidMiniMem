"""内存数值扫描与基址分析。

给 AI 助手用的搜索闭环：
    scan_start -> (目标数值变化) -> scan_next -> scan_results -> analyze_address

所有扫描状态都保存在设备端 engine 里，GUI 只是转发，所以多次调用之间
不需要重传候选集。
"""

from __future__ import annotations

from typing import Optional

from mcp.server.fastmcp import FastMCP

from ..ipc_client import IpcClient

_DATA_TYPES = {
    "byte": 1,
    "word": 2,
    "dword": 4,
    "qword": 8,
    "float": 100,
    "double": 101,
}

_FLOAT_TYPES = {100, 101}

_SCAN_TYPES = {
    "exact": 0,
    "bigger": 1,
    "smaller": 2,
    "unknown": 3,
    "unchanged": 4,
    "changed": 5,
    "increased": 6,
    "decreased": 7,
}

_SCAN_TYPE_NAMES = {
    0: "exact",
    1: "bigger",
    2: "smaller",
    3: "unknown",
    4: "unchanged",
    5: "changed",
    6: "increased",
    7: "decreased",
}


def _parse_data_type(name: str) -> int:
    key = (name or "").strip().lower()
    if key not in _DATA_TYPES:
        raise ValueError(
            f"unsupported data_type: {name!r}, "
            f"expected one of {sorted(_DATA_TYPES)}"
        )
    return _DATA_TYPES[key]


def _parse_scan_type(name: str) -> int:
    key = (name or "").strip().lower()
    if key not in _SCAN_TYPES:
        raise ValueError(
            f"unsupported scan_type: {name!r}, "
            f"expected one of {sorted(_SCAN_TYPES)}"
        )
    return _SCAN_TYPES[key]


def _format_entry(entry: dict, is_float: bool) -> str:
    addr = entry.get("address", "0x0")
    if is_float:
        return f"{addr} = {entry.get('float_value')}"
    return f"{addr} = {entry.get('int_value')}"


def register(mcp: FastMCP, ipc: IpcClient) -> None:

    @mcp.tool()
    def memory_scan_start(
        value: Optional[float] = None,
        data_type: str = "dword",
        scan_type: str = "exact",
        alignment: int = 4,
        region: str = "writable",
        max_results: int = 4000000,
        preview: int = 10,
    ) -> str:
        """首次扫描：在目标进程内存里搜索数值，建立候选地址集合。

        Args:
            value: 要搜索的数值。scan_type=unknown 时可省略。
            data_type: byte / word / dword / qword / float / double
            scan_type: exact / bigger / smaller / unknown
            alignment: 地址对齐 1/2/4/8，通常取数据类型宽度
            region: writable（只扫可写区域，快）/ readable（扫全部可读区域，慢）
            max_results: 候选上限，超过后停止记录
            preview: 返回结果里附带前多少条候选
        """
        type_code = _parse_data_type(data_type)
        mode = _parse_scan_type(scan_type)
        if mode not in (0, 1, 2, 3):
            raise ValueError("scan_type for the first scan must be exact/bigger/smaller/unknown")
        if mode != 3 and value is None:
            raise ValueError("value is required unless scan_type=unknown")

        params = {
            "value_type": type_code,
            "scan_mode": mode,
            "alignment": alignment,
            "region_filter": 0 if (region or "").lower() == "writable" else 1,
            "max_results": max_results,
        }
        if value is not None:
            params["value"] = value

        result = ipc.call_or_raise("scan_first", params)
        total = int(result.get("total", 0))

        lines = [f"首次扫描完成：候选 {total} 条"]
        if total and preview > 0:
            page = ipc.call_or_raise(
                "scan_results", {"offset": 0, "count": min(preview, 200)}
            )
            is_float = type_code in _FLOAT_TYPES
            for entry in page.get("items", []):
                lines.append("  " + _format_entry(entry, is_float))
        if total > preview:
            lines.append(f"  ... 其余 {total - preview} 条用 memory_scan_results 分页取")
        return "\n".join(lines)

    @mcp.tool()
    def memory_scan_next(
        scan_type: str = "unchanged",
        value: Optional[float] = None,
    ) -> str:
        """再次扫描：用当前内存值与上次结果比对，缩小候选集。

        Args:
            scan_type: unchanged / changed / increased / decreased /
                       exact / bigger / smaller / unknown
            value: exact/bigger/smaller 时必填，其余模式忽略
        """
        mode = _parse_scan_type(scan_type)
        needs_value = mode in (0, 1, 2)
        if needs_value and value is None:
            raise ValueError(f"value is required for scan_type={scan_type}")

        params = {"scan_mode": mode}
        if value is not None:
            params["value"] = value

        result = ipc.call_or_raise("scan_next", params)
        total = int(result.get("total", 0))
        return f"再次扫描完成（{scan_type}）：剩余候选 {total} 条"

    @mcp.tool()
    def memory_scan_results(offset: int = 0, count: int = 20) -> str:
        """分页读取当前候选地址及其数值。

        Args:
            offset: 起始下标
            count: 条数，上限 200
        """
        result = ipc.call_or_raise(
            "scan_results", {"offset": offset, "count": max(1, min(count, 200))}
        )
        items = result.get("items", [])
        total = int(result.get("total", 0))
        if not items:
            return f"没有更多结果（总数 {total}）"

        is_float = int(result.get("value_type", 4)) in _FLOAT_TYPES
        lines = [f"候选共 {total} 条，本页 {len(items)} 条："]
        for entry in items:
            lines.append("  " + _format_entry(entry, is_float))
        return "\n".join(lines)

    @mcp.tool()
    def memory_scan_clear() -> str:
        """清空当前扫描会话，释放候选集。"""
        ipc.call_or_raise("scan_clear")
        return "扫描会话已清空"

    @mcp.tool()
    def analyze_address(address: str) -> str:
        """地址反查：返回所属模块、模块基址、模块内偏移、所在内存区域的权限。

        这是「找基址」的核心操作：拿到绝对地址后，用它换算成
        模块名 + 偏移，就能得到重启后依然有效的表达方式。

        Args:
            address: 绝对地址，支持 0x 前缀
        """
        result = ipc.call_or_raise("address_info", {"address": address})
        module = result.get("module_name") or "(不属于任何模块，如堆/栈/匿名映射)"
        return "\n".join([
            f"地址: {result.get('address')}",
            f"模块: {module}",
            f"模块基址: {result.get('module_base')}",
            f"模块大小: {result.get('module_size')}",
            f"模块内偏移: {result.get('offset')}",
            f"区域: {result.get('region_base')} + {result.get('region_size')}",
            f"权限: {result.get('perms')}",
        ])
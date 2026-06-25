"""Main window UI for the port viewer."""

import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

import psutil
import ttkbootstrap as tb
from ttkbootstrap.constants import *

from models import PortEntry
from port_scanner import scan_ports
from process_resolver import ProcessResolver
from service_resolver import ServiceResolver

# Column definitions: (id, header, width, align)
COLUMNS = [
    ("#proto", "Protocol", 60, "center"),
    ("#local", "Local Address", 200, "w"),
    ("#remote", "Remote Address", 200, "w"),
    ("#state", "State", 110, "center"),
    ("#pid", "PID", 60, "e"),
    ("#name", "Process Name", 160, "w"),
    ("#services", "Service(s)", 220, "w"),
]

# TCP state → row tag name
STATE_TAGS = {
    "LISTEN": "listen",
    "ESTABLISHED": "established",
    "TIME_WAIT": "time_wait",
    "CLOSE_WAIT": "close_wait",
    "SYN_SENT": "syn_sent",
    "FIN_WAIT1": "closing",
    "FIN_WAIT2": "closing",
    "LAST_ACK": "closing",
    "CLOSING": "closing",
}

REFRESH_INTERVALS = [1, 2, 5, 10]


class MainWindow:
    """Port viewer main application window."""

    def __init__(self):
        self.root = tb.Window(themename="flatly")
        self.root.title("WinPortView — Windows 端口查看器")
        self.root.geometry("1100x650")

        # Services
        self.scanner = scan_ports
        self.proc_resolver = ProcessResolver()
        self.svc_resolver = ServiceResolver()

        # State
        self.all_entries: list[PortEntry] = []
        self.auto_refresh = True
        self.refresh_interval = 2  # seconds
        self._refresh_thread: threading.Thread | None = None
        self._debounce_id: str | None = None

        # Build UI
        self._build_toolbar()
        self._build_tree()
        self._build_statusbar()

        # Start background workers
        self.svc_resolver.refresh()  # Initial WMI load (sync — may take 1-2s)
        self.svc_resolver.start()
        self._start_refresh_thread()

        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI Construction ──────────────────────────────────────────

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(8, 6))
        bar.pack(fill=X)

        # Search
        ttk.Label(bar, text="搜索:").pack(side=LEFT, padx=(0, 4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._on_search_changed())
        self.search_entry = ttk.Entry(bar, textvariable=self.search_var, width=28)
        self.search_entry.pack(side=LEFT, padx=(0, 8))

        # Refresh button
        self.refresh_btn = ttk.Button(
            bar, text="🔄 刷新", command=self._manual_refresh, bootstyle="outline-secondary"
        )
        self.refresh_btn.pack(side=LEFT, padx=(0, 8))

        # Auto-refresh toggle
        self.auto_var = tk.BooleanVar(value=True)
        self.auto_cb = ttk.Checkbutton(
            bar, text="自动刷新", variable=self.auto_var, command=self._on_auto_toggle
        )
        self.auto_cb.pack(side=LEFT, padx=(0, 12))

        # Interval selector
        ttk.Label(bar, text="间隔:").pack(side=LEFT, padx=(0, 4))
        self.interval_var = tk.StringVar(value="2s")
        interval_combo = ttk.Combobox(
            bar, textvariable=self.interval_var,
            values=[f"{i}s" for i in REFRESH_INTERVALS],
            state="readonly", width=5
        )
        interval_combo.pack(side=LEFT, padx=(0, 12))
        interval_combo.bind("<<ComboboxSelected>>", self._on_interval_change)

        # Elevate button
        self.elevate_btn = ttk.Button(
            bar, text="🔒 管理员模式", command=self._elevate, bootstyle="warning-outline"
        )
        self.elevate_btn.pack(side=RIGHT, padx=(4, 0))

    def _build_tree(self):
        """Build the port list Treeview with scrollbar."""
        frame = ttk.Frame(self.root)
        frame.pack(fill=BOTH, expand=True, padx=8, pady=(0, 4))

        # Treeview
        self.tree = ttk.Treeview(
            frame,
            columns=[c[0] for c in COLUMNS],
            show="headings",
            selectmode="browse",
        )
        for col_id, header, width, align in COLUMNS:
            self.tree.heading(col_id, text=header, anchor=align,
                              command=lambda c=col_id: self._sort_by(c))
            self.tree.column(col_id, width=width, anchor=align, minwidth=40)

        # Scrollbar
        vsb = ttk.Scrollbar(frame, orient=VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient=HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Row color tags
        self.tree.tag_configure("listen", background="#e8f5e9")
        self.tree.tag_configure("established", background="#e3f2fd")
        self.tree.tag_configure("time_wait", background="#f5f5f5")
        self.tree.tag_configure("close_wait", background="#fff3e0")
        self.tree.tag_configure("syn_sent", background="#fff8e1")
        self.tree.tag_configure("closing", background="#eceff1")

        # Context menu (right-click)
        self._ctx_menu = tk.Menu(self.root, tearoff=0)
        self._ctx_menu.add_command(label="终止进程 (Kill Process)", command=self._kill_selected)
        self._ctx_menu.add_command(label="复制当前行", command=self._copy_selected)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<Button-2>", self._on_right_click)  # Some mice

    def _build_statusbar(self):
        self.status_var = tk.StringVar(value="就绪")
        self.count_var = tk.StringVar(value="连接数: 0")

        bar = ttk.Frame(self.root, padding=(8, 4))
        bar.pack(fill=X)

        self.count_label = ttk.Label(bar, textvariable=self.count_var, font=("Segoe UI", 9))
        self.count_label.pack(side=LEFT, padx=(0, 16))

        ttk.Label(bar, textvariable=self.status_var, font=("Segoe UI", 9)).pack(side=LEFT)

    # ── Refresh Logic ─────────────────────────────────────────────

    def _start_refresh_thread(self):
        self._refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self._refresh_thread.start()

    def _refresh_loop(self):
        while True:
            if self.auto_refresh:
                self._do_refresh()
            # Use sub-second sleep to respond quickly to interval/stop changes
            for _ in range(self.refresh_interval * 10):
                if not self.root.winfo_exists():
                    return
                time.sleep(0.1)

    def _do_refresh(self):
        try:
            entries = self.scanner()
        except Exception as e:
            self.root.after(0, lambda: self.status_var.set(f"扫描失败: {e}"))
            return

        # Resolve process names
        pids = {e.pid for e in entries if e.pid > 0}
        proc_names = self.proc_resolver.batch_resolve(pids)

        # Attach names & services
        for entry in entries:
            entry.process_name = proc_names.get(entry.pid, "")
            entry.services = self.svc_resolver.get(entry.pid)

        # Update UI on main thread
        self.root.after(0, lambda: self._update_treeview(entries))

    def _update_treeview(self, entries: list[PortEntry]):
        self.all_entries = entries
        self._apply_filter()

    def _manual_refresh(self):
        self.status_var.set("正在刷新...")
        self.refresh_btn.configure(state="disabled")
        threading.Thread(target=self._manual_refresh_bg, daemon=True).start()

    def _manual_refresh_bg(self):
        self._do_refresh()
        self.root.after(0, lambda: (
            self.status_var.set(f"刷新完成 — {time.strftime('%H:%M:%S')}"),
            self.refresh_btn.configure(state="normal")
        ))

    # ── Filtering ─────────────────────────────────────────────────

    def _on_search_changed(self):
        # Debounce: wait 150ms after last keystroke
        if self._debounce_id is not None:
            self.root.after_cancel(self._debounce_id)
        self._debounce_id = self.root.after(150, self._apply_filter)

    def _apply_filter(self):
        search = self.search_var.get().strip().lower()
        if not search:
            # Show all
            filtered = self.all_entries
        else:
            filtered = [
                e for e in self.all_entries
                if search in str(e.local_port)
                or search in e.process_name.lower()
                or search in e.service_display.lower()
                or search in str(e.pid)
            ]

        # Repopulate tree
        self.tree.delete(*self.tree.get_children())
        for entry in filtered:
            tag = STATE_TAGS.get(entry.state, "")
            self.tree.insert("", END, values=(
                entry.protocol,
                entry.local,
                entry.remote,
                entry.state,
                str(entry.pid) if entry.pid else "",
                entry.process_name,
                entry.service_display,
            ), tags=(tag,) if tag else ())

        self.count_var.set(f"连接数: {len(filtered)}")
        if search:
            self.status_var.set(f"过滤: \"{search}\" — 显示 {len(filtered)}/{len(self.all_entries)} 条")
        else:
            self.status_var.set(f"最后刷新 — {time.strftime('%H:%M:%S')}")

    # ── Kill Process ──────────────────────────────────────────────

    def _on_right_click(self, event):
        """Show context menu on right-click."""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self._ctx_menu.tk_popup(event.x_root, event.y_root)

    def _get_selected_pid(self) -> int | None:
        selection = self.tree.selection()
        if not selection:
            return None
        values = self.tree.item(selection[0], "values")
        pid_str = values[4]  # PID column index
        try:
            return int(pid_str)
        except ValueError:
            return None

    def _kill_selected(self):
        pid = self._get_selected_pid()
        if pid is None:
            return

        # Find entry for display
        proc_name = ""
        for item in self.tree.selection():
            proc_name = self.tree.item(item, "values")[5] or ""

        label = f"{proc_name} (PID {pid})" if proc_name else f"PID {pid}"

        if not messagebox.askyesno(
            "确认终止进程",
            f"确定要终止 {label} 吗？\n\n"
            "这会强制结束该进程及其所有网络连接。",
            parent=self.root,
        ):
            return

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
            self.status_var.set(f"已终止: {label}")
        except psutil.NoSuchProcess:
            self.status_var.set(f"进程 {label} 已不存在")
        except psutil.AccessDenied:
            self.status_var.set(f"权限不足: 无法终止 {label}。请以管理员身份运行。")
            messagebox.showerror(
                "权限不足",
                f"无法终止 {label}。\n\n"
                "该进程需要管理员权限才能终止。\n"
                "请点击工具栏的「管理员模式」按钮以提升权限。",
                parent=self.root,
            )
        except Exception as e:
            self.status_var.set(f"终止失败: {e}")

        # Refresh immediately
        self._do_refresh()

    def _copy_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        text = "\t".join(str(v) for v in values)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("已复制到剪贴板")

    # ── Sort ──────────────────────────────────────────────────────

    def _sort_by(self, col_id: str):
        """Sort tree by column (simple toggle)."""
        # Determine sort key from column id
        col_map = {
            "#proto": 0, "#local": 1, "#remote": 2, "#state": 3,
            "#pid": 4, "#name": 5, "#services": 6,
        }
        idx = col_map.get(col_id, 0)

        # Sort entries by that field
        reverse = getattr(self, "_sort_reverse", False)
        self.all_entries.sort(
            key=lambda e, i=idx: self._sort_key(e, i),
            reverse=reverse,
        )
        setattr(self, "_sort_reverse", not reverse)
        self._apply_filter()

    @staticmethod
    def _sort_key(entry: PortEntry, idx: int):
        """Extract sort key from a PortEntry by column index."""
        keys = [
            entry.protocol,
            (entry.local_port, entry.local_addr),
            entry.remote_addr or "",
            entry.state,
            entry.pid,
            entry.process_name.lower(),
            entry.service_display.lower(),
        ]
        return keys[idx] if idx < len(keys) else ""

    # ── Controls ──────────────────────────────────────────────────

    def _on_auto_toggle(self):
        self.auto_refresh = self.auto_var.get()
        self.status_var.set(f"自动刷新: {'开' if self.auto_refresh else '关'}")

    def _on_interval_change(self, event=None):
        val = self.interval_var.get().rstrip("s")
        try:
            self.refresh_interval = int(val)
        except ValueError:
            self.refresh_interval = 2
        self.status_var.set(f"刷新间隔: {self.refresh_interval}s")

    def _elevate(self):
        """Prompt to restart as administrator."""
        if messagebox.askyesno(
            "管理员模式",
            "需要以管理员身份重启应用才能终止系统进程。\n\n"
            "是否现在以管理员身份重新启动？",
            parent=self.root,
        ):
            import ctypes
            import sys
            try:
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable,
                    " ".join(sys.argv), None, 1
                )
            except Exception as e:
                messagebox.showerror("错误", f"无法提升权限: {e}", parent=self.root)

    def _on_close(self):
        self.auto_refresh = False
        self.svc_resolver.stop()
        self.root.destroy()

    def run(self):
        """Start the main loop."""
        self.root.mainloop()

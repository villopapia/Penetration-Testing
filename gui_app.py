#!/usr/bin/env python3
"""Standalone GUI front-end for run_modules.py.

Lets a non-technical user run the custom security testing modules and
produce a DORA-aligned report without touching a terminal. Intended to be
packaged into a single executable with PyInstaller (see build_exe.py).
"""

from __future__ import annotations

import datetime as dt
import getpass
import os
import pathlib
import queue
import sys
import threading
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

import run_modules as rm


class ScanAborted(Exception):
    """Raised when the user declines an in-scan active-test confirmation."""


# (cli name, display name, description, is_active)
MODULE_INFO = [
    ("auth", "Auth testing", "Login discovery, cleartext, CSRF, default creds", True),
    ("supply-chain", "Supply chain", "JS library CVEs, SRI, manifests", False),
    ("prompt-injection", "Prompt injection", "LLM/chatbot detection, prompt injection", True),
    ("ransomware", "Ransomware readiness", "Admin panels, security headers, directory listing", False),
    ("authenticated-scan", "Authenticated scan", "Auth crawl, broken access control, IDOR", True),
    ("tls", "TLS check", "Certs, protocol versions, ciphers, HSTS", False),
    ("api-discovery", "API discovery", "OpenAPI/Swagger, JS endpoints, GraphQL", False),
]


def _base_dir() -> pathlib.Path:
    if getattr(sys, "frozen", False):
        return pathlib.Path(sys.executable).resolve().parent
    return pathlib.Path(__file__).resolve().parent


class QueueWriter:
    """File-like object that funnels print() output into a thread-safe queue."""

    def __init__(self, q: "queue.Queue"):
        self._q = q

    def write(self, text: str) -> None:
        if text:
            self._q.put(text)

    def flush(self) -> None:
        pass


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("DORA Article 24 Assessment Tool")
        root.geometry("900x680")
        root.minsize(760, 560)

        self.log_queue: "queue.Queue" = queue.Queue()
        self.worker: threading.Thread | None = None

        self._patch_confirm_prompts()
        self._build_vars()
        self._build_ui()
        self.root.after(100, self._poll_log_queue)

    # ------------------------------------------------------------------
    # Active-test confirmation: replace the CLI's input()-based prompt
    # with a GUI dialog so the packaged app never needs a console.
    # ------------------------------------------------------------------
    def _patch_confirm_prompts(self) -> None:
        for mod in (rm.auth_test, rm.authenticated_scan, rm.ransomware_readiness, rm.prompt_injection):
            mod.interactive_confirm = self._gui_confirm

    def _gui_confirm(self, target: str, test_name: str, warning: str) -> None:
        result: dict[str, bool] = {}
        done = threading.Event()

        def ask() -> None:
            msg = f"Target: {target}\nTest: {test_name}\n\n{warning}\n\nProceed with this test?"
            result["ok"] = messagebox.askyesno("Confirm active testing", msg, icon="warning")
            done.set()

        self.root.after(0, ask)
        done.wait()
        if not result.get("ok"):
            raise ScanAborted(f"Aborted by user before '{test_name}'.")

    # ------------------------------------------------------------------
    # Tk variables
    # ------------------------------------------------------------------
    def _build_vars(self) -> None:
        self.target_var = tk.StringVar()
        self.output_dir_var = tk.StringVar(value=str(_base_dir()))
        self.format_var = tk.StringVar(value="md")
        self.confirm_var = tk.BooleanVar(value=False)
        self.dry_run_var = tk.BooleanVar(value=False)
        self.timeout_var = tk.StringVar(value="15")
        self.status_var = tk.StringVar(value="Idle")

        self.module_vars: dict[str, tk.BooleanVar] = {
            name: tk.BooleanVar(value=not is_active) for name, _, _, is_active in MODULE_INFO
        }

        self.entity_name_var = tk.StringVar()
        self.entity_lei_var = tk.StringVar()
        self.assessor_var = tk.StringVar(value=getpass.getuser())
        self.date_var = tk.StringVar(value=dt.date.today().isoformat())
        self.framework_var = tk.StringVar(value="dora")

        self.auth_attempts_var = tk.StringVar(value="10")
        self.login_path_var = tk.StringVar()
        self.test_username_var = tk.StringVar()
        self.check_manifests_var = tk.BooleanVar(value=False)
        self.chat_endpoint_var = tk.StringVar()
        self.network_scan_var = tk.BooleanVar(value=False)
        self.auth_login_url_var = tk.StringVar()
        self.auth_username_var = tk.StringVar()
        self.auth_password_var = tk.StringVar()
        self.session_cookie_var = tk.StringVar()
        self.auth_header_var = tk.StringVar()
        self.max_pages_var = tk.StringVar(value="50")
        self.probe_acl_var = tk.BooleanVar(value=False)

    # ------------------------------------------------------------------
    # UI layout
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="x", padx=10, pady=(10, 0))

        scan_tab = ttk.Frame(notebook, padding=10)
        info_tab = ttk.Frame(notebook, padding=10)
        advanced_tab = ttk.Frame(notebook, padding=10)
        notebook.add(scan_tab, text="Scan")
        notebook.add(info_tab, text="Report info")
        notebook.add(advanced_tab, text="Advanced")

        self._build_scan_tab(scan_tab)
        self._build_info_tab(info_tab)
        self._build_advanced_tab(advanced_tab)

        bottom = ttk.Frame(self.root, padding=10)
        bottom.pack(fill="both", expand=True)

        controls = ttk.Frame(bottom)
        controls.pack(fill="x")
        self.run_button = ttk.Button(controls, text="Run scan", command=self._on_run)
        self.run_button.pack(side="left")
        ttk.Label(controls, textvariable=self.status_var).pack(side="left", padx=10)

        ttk.Label(bottom, text="Log:").pack(anchor="w", pady=(10, 0))
        self.log_text = scrolledtext.ScrolledText(bottom, height=16, state="disabled", wrap="word")
        self.log_text.pack(fill="both", expand=True)

    def _build_scan_tab(self, parent: ttk.Frame) -> None:
        row = 0
        ttk.Label(parent, text="Target URL").grid(row=row, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.target_var, width=50).grid(
            row=row, column=1, columnspan=2, sticky="we", padx=5
        )
        row += 1

        ttk.Label(parent, text="Output folder").grid(row=row, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(parent, textvariable=self.output_dir_var, width=50).grid(
            row=row, column=1, sticky="we", padx=5, pady=(6, 0)
        )
        ttk.Button(parent, text="Browse...", command=self._browse_output_dir).grid(
            row=row, column=2, pady=(6, 0)
        )
        row += 1

        ttk.Label(parent, text="Report format").grid(row=row, column=0, sticky="w", pady=(6, 0))
        ttk.Combobox(
            parent, textvariable=self.format_var, values=["md", "html", "json"], state="readonly", width=10
        ).grid(row=row, column=1, sticky="w", padx=5, pady=(6, 0))
        row += 1

        ttk.Label(parent, text="Modules to run").grid(row=row, column=0, sticky="nw", pady=(10, 0))
        modules_frame = ttk.Frame(parent)
        modules_frame.grid(row=row, column=1, columnspan=2, sticky="we", pady=(10, 0))
        for i, (name, label, desc, is_active) in enumerate(MODULE_INFO):
            suffix = "  (active test)" if is_active else ""
            ttk.Checkbutton(
                modules_frame, text=f"{label}{suffix}", variable=self.module_vars[name]
            ).grid(row=i, column=0, sticky="w")
            ttk.Label(modules_frame, text=desc, foreground="#555").grid(row=i, column=1, sticky="w", padx=10)
        row += 1

        ttk.Checkbutton(
            parent,
            text="Authorise active tests (required for auth / prompt-injection / authenticated-scan)",
            variable=self.confirm_var,
        ).grid(row=row, column=0, columnspan=3, sticky="w", pady=(10, 0))
        row += 1

        ttk.Checkbutton(
            parent, text="Dry run (show planned checks only, no requests sent)", variable=self.dry_run_var
        ).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1

        ttk.Label(parent, text="Timeout (seconds)").grid(row=row, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(parent, textvariable=self.timeout_var, width=10).grid(
            row=row, column=1, sticky="w", padx=5, pady=(6, 0)
        )

        parent.columnconfigure(1, weight=1)

    def _build_info_tab(self, parent: ttk.Frame) -> None:
        fields = [
            ("Entity name", self.entity_name_var),
            ("Entity LEI", self.entity_lei_var),
            ("Assessor name", self.assessor_var),
            ("Assessment date (YYYY-MM-DD)", self.date_var),
        ]
        for i, (label, var) in enumerate(fields):
            ttk.Label(parent, text=label).grid(row=i, column=0, sticky="w", pady=4)
            ttk.Entry(parent, textvariable=var, width=40).grid(row=i, column=1, sticky="we", padx=5, pady=4)

        ttk.Label(parent, text="Regulatory framework").grid(row=len(fields), column=0, sticky="w", pady=4)
        ttk.Combobox(
            parent, textvariable=self.framework_var, values=["dora", "none"], state="readonly", width=10
        ).grid(row=len(fields), column=1, sticky="w", padx=5, pady=4)

        parent.columnconfigure(1, weight=1)

    def _build_advanced_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Auth module", font=("", 9, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        ttk.Label(parent, text="Brute-force attempts").grid(row=1, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.auth_attempts_var, width=10).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(parent, text="Login path (optional)").grid(row=2, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.login_path_var, width=30).grid(row=2, column=1, sticky="w", padx=5)
        ttk.Label(parent, text="Test username (optional)").grid(row=3, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.test_username_var, width=30).grid(row=3, column=1, sticky="w", padx=5)

        ttk.Separator(parent, orient="horizontal").grid(row=4, column=0, columnspan=2, sticky="we", pady=8)

        ttk.Label(parent, text="Supply-chain / Prompt-injection / Ransomware", font=("", 9, "bold")).grid(
            row=5, column=0, columnspan=2, sticky="w"
        )
        ttk.Checkbutton(parent, text="Check manifests (supply-chain)", variable=self.check_manifests_var).grid(
            row=6, column=0, columnspan=2, sticky="w"
        )
        ttk.Label(parent, text="Chat endpoint (prompt-injection, optional)").grid(row=7, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.chat_endpoint_var, width=30).grid(row=7, column=1, sticky="w", padx=5)
        ttk.Checkbutton(parent, text="Network port scan (ransomware, active)", variable=self.network_scan_var).grid(
            row=8, column=0, columnspan=2, sticky="w"
        )

        ttk.Separator(parent, orient="horizontal").grid(row=9, column=0, columnspan=2, sticky="we", pady=8)

        ttk.Label(parent, text="Authenticated scan", font=("", 9, "bold")).grid(
            row=10, column=0, columnspan=2, sticky="w"
        )
        ttk.Label(parent, text="Login URL").grid(row=11, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.auth_login_url_var, width=30).grid(row=11, column=1, sticky="w", padx=5)
        ttk.Label(parent, text="Username").grid(row=12, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.auth_username_var, width=30).grid(row=12, column=1, sticky="w", padx=5)
        ttk.Label(parent, text="Password").grid(row=13, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.auth_password_var, width=30, show="*").grid(
            row=13, column=1, sticky="w", padx=5
        )
        ttk.Label(parent, text="Session cookie (name=value)").grid(row=14, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.session_cookie_var, width=30).grid(row=14, column=1, sticky="w", padx=5)
        ttk.Label(parent, text="Auth header (Header-Name: value)").grid(row=15, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.auth_header_var, width=30).grid(row=15, column=1, sticky="w", padx=5)
        ttk.Label(parent, text="Max pages to crawl").grid(row=16, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.max_pages_var, width=10).grid(row=16, column=1, sticky="w", padx=5)
        ttk.Checkbutton(
            parent, text="Probe broken access control / IDOR", variable=self.probe_acl_var
        ).grid(row=17, column=0, columnspan=2, sticky="w")

    def _browse_output_dir(self) -> None:
        chosen = filedialog.askdirectory(initialdir=self.output_dir_var.get() or str(_base_dir()))
        if chosen:
            self.output_dir_var.set(chosen)

    # ------------------------------------------------------------------
    # Scan execution
    # ------------------------------------------------------------------
    def _on_run(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Busy", "A scan is already running.")
            return

        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Missing target", "Enter a target URL.")
            return

        selected = [name for name in self.module_vars if self.module_vars[name].get()]
        if not selected:
            messagebox.showerror("No modules selected", "Select at least one module to run.")
            return

        active_selected = [m for m in selected if m in rm._ACTIVE_MODULES]
        if (active_selected or self.network_scan_var.get()) and not self.confirm_var.get():
            names = list(active_selected)
            if self.network_scan_var.get():
                names.append("ransomware (network scan)")
            messagebox.showerror(
                "Confirmation required",
                f"Module(s) {', '.join(names)} perform active tests.\n"
                "Check \"Authorise active tests\" to proceed.",
            )
            return

        self._clear_log()
        self.run_button.config(state="disabled")
        self.status_var.set("Running...")
        self.worker = threading.Thread(target=self._scan_worker, args=(target, selected), daemon=True)
        self.worker.start()

    def _collect_extra_args(self) -> dict:
        return {
            "auth_attempts": self._safe_int(self.auth_attempts_var.get(), 10),
            "login_path": self.login_path_var.get().strip() or None,
            "test_username": self.test_username_var.get().strip() or None,
            "check_manifests": self.check_manifests_var.get(),
            "chat_endpoint": self.chat_endpoint_var.get().strip() or None,
            "network_scan": self.network_scan_var.get(),
            "auth_login_url": self.auth_login_url_var.get().strip() or None,
            "auth_username": self.auth_username_var.get().strip() or None,
            "auth_password": self.auth_password_var.get() or None,
            "session_cookie": self.session_cookie_var.get().strip() or None,
            "auth_header": self.auth_header_var.get().strip() or None,
            "max_pages": self._safe_int(self.max_pages_var.get(), 50),
            "probe_access_control": self.probe_acl_var.get(),
        }

    def _resolve_output_path(self) -> pathlib.Path:
        out_dir = pathlib.Path(self.output_dir_var.get().strip() or _base_dir())
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = {"md": "md", "html": "html", "json": "json"}[self.format_var.get()]
        return out_dir / f"dora_modules_report_{ts}.{ext}"

    def _scan_worker(self, target: str, selected: list[str]) -> None:
        old_stdout = sys.stdout
        sys.stdout = QueueWriter(self.log_queue)
        try:
            extra_args = self._collect_extra_args()
            confirm = self.confirm_var.get()
            timeout = self._safe_int(self.timeout_var.get(), 15)
            dry_run = self.dry_run_var.get()

            raw_alerts = rm.run_selected_modules(
                target,
                modules=selected,
                confirm=confirm,
                timeout=timeout,
                dry_run=dry_run,
                extra_args=extra_args,
            )

            if dry_run:
                print("\n[dry-run] No report generated.")
                self.log_queue.put(("__done__", None))
                return

            alerts = rm._parse_alerts(raw_alerts)
            scan_type = "modules"
            output_path = self._resolve_output_path()

            report_kwargs = dict(
                entity_name=self.entity_name_var.get().strip() or None,
                entity_lei=self.entity_lei_var.get().strip() or None,
                assessor_name=self.assessor_var.get().strip() or getpass.getuser(),
                assessment_date=self.date_var.get().strip() or dt.date.today().isoformat(),
                regulatory_framework=self.framework_var.get(),
                exclude_urls=None,
                manual_findings=None,
                business_context=None,
            )

            fmt = self.format_var.get()
            if fmt == "json":
                rm._report_json(
                    target, scan_type, alerts, output_path,
                    regulatory_framework=self.framework_var.get(),
                )
            elif fmt == "html":
                rm._report_html(target, scan_type, alerts, output_path, **report_kwargs)
            else:
                rm._report_md(target, scan_type, alerts, output_path, **report_kwargs)

            summary = rm._summary(target, scan_type, alerts)
            print(f"\nReport written to {output_path}")
            print(f"Total findings: {summary['total_alerts']}")
            for sev in ("Critical", "High", "Medium", "Low", "Informational"):
                count = summary["by_severity"].get(sev, 0)
                if count:
                    print(f"  {sev}: {count}")

            self.log_queue.put(("__done__", str(output_path)))
        except ScanAborted as exc:
            print(f"\n{exc}")
            self.log_queue.put(("__aborted__", None))
        except Exception:
            print("\nERROR:\n" + traceback.format_exc())
            self.log_queue.put(("__error__", None))
        finally:
            sys.stdout = old_stdout

    @staticmethod
    def _safe_int(value: str, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    # ------------------------------------------------------------------
    # Log widget / queue polling
    # ------------------------------------------------------------------
    def _clear_log(self) -> None:
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    def _append_log(self, text: str) -> None:
        self.log_text.config(state="normal")
        self.log_text.insert("end", text)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _poll_log_queue(self) -> None:
        try:
            while True:
                item = self.log_queue.get_nowait()
                if isinstance(item, tuple):
                    self._on_scan_finished(*item)
                else:
                    self._append_log(item)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_log_queue)

    def _on_scan_finished(self, kind: str, payload: str | None) -> None:
        self.run_button.config(state="normal")
        if kind == "__done__":
            if payload:
                self.status_var.set("Done")
                if messagebox.askyesno("Scan complete", f"Report written to:\n{payload}\n\nOpen it now?"):
                    self._open_path(payload)
            else:
                self.status_var.set("Dry run complete")
        elif kind == "__aborted__":
            self.status_var.set("Aborted")
        else:
            self.status_var.set("Error")
            messagebox.showerror("Scan failed", "An error occurred. See the log for details.")

    @staticmethod
    def _open_path(path: str) -> None:
        try:
            os.startfile(path)  # noqa: S606 - Windows-only GUI helper, user-chosen local file
        except OSError:
            pass


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()

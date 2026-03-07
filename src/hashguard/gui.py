"""HashGuard — Professional File Verification GUI.

Modern dark-themed interface built with Tkinter for cryptographic
hash computation, malware signature detection, and optional
VirusTotal threat intelligence lookups.
"""

import os
import re
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES

    _HAS_DND = True
except Exception:
    _HAS_DND = False

try:
    from PIL import Image, ImageTk
except Exception:
    Image = None
    ImageTk = None

try:
    from hashguard.scanner import analyze, analyze_url
except Exception:
    _pkg = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    if _pkg not in sys.path:
        sys.path.insert(0, _pkg)
    from hashguard.scanner import analyze, analyze_url

from hashguard.config import HashGuardConfig

try:
    from hashguard import __version__
except Exception:
    __version__ = "1.0.4"


# ---------------------------------------------------------------------------
# Design tokens
# ---------------------------------------------------------------------------

_BG_PRIMARY = "#0A0E17"  # deepest background
_BG_SURFACE = "#111827"  # card / panel surface
_BG_ELEVATED = "#1F2937"  # elevated elements (inputs, hover)
_BORDER = "#2D3748"  # subtle borders
_ACCENT = "#FF6600"  # primary orange accent
_ACCENT_HOVER = "#FF7A1A"
_TEXT_PRIMARY = "#F9FAFB"
_TEXT_SECONDARY = "#9CA3AF"
_TEXT_MUTED = "#6B7280"
_GREEN = "#10B981"
_RED = "#EF4444"
_BLUE = "#3B82F6"
_YELLOW = "#F59E0B"
_CYAN = "#06B6D4"
_MONO_FONT = ("Cascadia Code", 10)
_UI_FONT = ("Segoe UI", 10)
_UI_FONT_SM = ("Segoe UI", 9)
_UI_FONT_BOLD = ("Segoe UI Semibold", 10)
_HEADING_FONT = ("Segoe UI", 20, "bold")


class HashGuardGUI:
    """Main application window."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("HashGuard")
        self.root.geometry("960x720")
        self.root.minsize(760, 540)
        self.root.configure(bg=_BG_PRIMARY)
        self.root.option_add("*tearOff", False)

        self._logo_image: Optional[tk.PhotoImage] = None
        self._icon_image: Optional[tk.PhotoImage] = None
        self.current_result = None
        self._is_analyzing = False
        # Settings persistence
        self._config_path = os.path.join(
            os.environ.get("APPDATA", os.path.expanduser("~")),
            "HashGuard",
            "config.json",
        )
        self._config = HashGuardConfig.from_file(self._config_path)
        self._set_window_icon()
        self._setup_styles()
        self._build_ui()
        self._setup_dnd()

    # ------------------------------------------------------------------
    # Resource helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resource_path(*parts: str) -> str:
        base = getattr(sys, "_MEIPASS", None)
        if base:
            return os.path.join(base, *parts)
        here = os.path.abspath(os.path.dirname(__file__))
        # Package data (pip install): assets/ is inside the package
        if parts and parts[0] == "assets":
            # Map assets/branding/X → <pkg>/assets/X
            pkg_parts = ("assets",) + parts[2:] if len(parts) > 2 else ("assets",) + parts[1:]
            pkg_path = os.path.join(here, *pkg_parts)
            if os.path.exists(pkg_path):
                return pkg_path
        # Development fallback (project root)
        return os.path.abspath(os.path.join(here, "..", "..", *parts))

    def _set_window_icon(self) -> None:
        try:
            ico = self._resource_path("assets", "branding", "hashguard.ico")
            if os.path.exists(ico):
                # On Windows, iconbitmap sets both window and taskbar icon
                self.root.iconbitmap(ico)
                return
            # Fallback to PNG for non-Windows or missing ICO
            png = self._resource_path("assets", "branding", "icon.png")
            if os.path.exists(png):
                self._icon_image = tk.PhotoImage(file=png)
                self.root.iconphoto(True, self._icon_image)
        except Exception:
            pass

    def _load_logo(self, target_h: int = 48) -> Optional[tk.PhotoImage]:
        try:
            path = self._resource_path("assets", "branding", "icon+texto.png")
            if not os.path.exists(path):
                return None
            if Image and ImageTk:
                img = Image.open(path).convert("RGBA")
                ratio = target_h / img.height
                w = int(img.width * ratio)
                img = img.resize((w, target_h), Image.Resampling.LANCZOS)
                self._logo_image = ImageTk.PhotoImage(img)
            else:
                self._logo_image = tk.PhotoImage(file=path)
            return self._logo_image
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Theme / styles
    # ------------------------------------------------------------------

    def _setup_styles(self) -> None:
        s = ttk.Style(self.root)
        s.theme_use("clam")

        s.configure(".", background=_BG_PRIMARY, foreground=_TEXT_PRIMARY, font=_UI_FONT)

        s.configure("TFrame", background=_BG_PRIMARY)
        s.configure("Card.TFrame", background=_BG_SURFACE)

        s.configure("TLabel", background=_BG_PRIMARY, foreground=_TEXT_PRIMARY, font=_UI_FONT)
        s.configure("Card.TLabel", background=_BG_SURFACE, foreground=_TEXT_PRIMARY)
        s.configure(
            "Heading.TLabel", background=_BG_SURFACE, foreground=_TEXT_PRIMARY, font=_HEADING_FONT
        )
        s.configure(
            "Subtitle.TLabel", background=_BG_SURFACE, foreground=_TEXT_SECONDARY, font=_UI_FONT_SM
        )
        s.configure(
            "Muted.TLabel", background=_BG_PRIMARY, foreground=_TEXT_MUTED, font=_UI_FONT_SM
        )
        s.configure(
            "Path.TLabel", background=_BG_PRIMARY, foreground=_TEXT_SECONDARY, font=_UI_FONT_SM
        )
        s.configure(
            "Status.TLabel", background=_BG_PRIMARY, foreground=_TEXT_SECONDARY, font=_UI_FONT_BOLD
        )

        s.configure("TButton", padding=(16, 8), font=_UI_FONT_BOLD, relief="flat")
        s.configure("Accent.TButton", padding=(20, 10), font=_UI_FONT_BOLD)
        s.map(
            "Accent.TButton",
            background=[
                ("!disabled", _ACCENT),
                ("active", _ACCENT_HOVER),
                ("disabled", _BG_ELEVATED),
            ],
            foreground=[("!disabled", "#FFFFFF"), ("disabled", _TEXT_MUTED)],
        )
        s.configure("Secondary.TButton", padding=(16, 8), font=_UI_FONT)
        s.map(
            "Secondary.TButton",
            background=[("!disabled", _BG_ELEVATED), ("active", _BORDER)],
            foreground=[("!disabled", _TEXT_PRIMARY)],
        )

        s.configure("TCheckbutton", background=_BG_PRIMARY, foreground=_TEXT_PRIMARY, font=_UI_FONT)
        s.map("TCheckbutton", background=[("active", _BG_PRIMARY)])

        s.configure(
            "Accent.Horizontal.TProgressbar",
            troughcolor=_BG_ELEVATED,
            background=_ACCENT,
            thickness=4,
        )

        s.configure("TNotebook", background=_BG_PRIMARY, borderwidth=0, tabmargins=(0, 0, 0, 0))
        s.configure("TNotebook.Tab", padding=(20, 10), font=_UI_FONT_BOLD)
        s.map(
            "TNotebook.Tab",
            background=[
                ("selected", _BG_SURFACE),
                ("!selected", _BG_PRIMARY),
                ("active", _BG_ELEVATED),
            ],
            foreground=[("selected", _ACCENT), ("!selected", _TEXT_MUTED)],
        )

        s.configure(
            "TEntry",
            fieldbackground=_BG_ELEVATED,
            foreground=_TEXT_PRIMARY,
            insertcolor=_TEXT_PRIMARY,
            padding=8,
            font=_UI_FONT,
        )

        s.configure("TLabelframe", background=_BG_PRIMARY, foreground=_TEXT_PRIMARY)
        s.configure(
            "TLabelframe.Label",
            background=_BG_PRIMARY,
            foreground=_TEXT_SECONDARY,
            font=_UI_FONT_SM,
        )

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root)
        outer.pack(fill=tk.BOTH, expand=True)

        self._build_header(outer)
        self._build_toolbar(outer)

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 16))

        self._tab_results = ttk.Frame(self.notebook, style="Card.TFrame")
        self._tab_settings = ttk.Frame(self.notebook, style="Card.TFrame")
        self.notebook.add(self._tab_results, text="  Analysis  ")
        self.notebook.add(self._tab_settings, text="  Settings  ")

        self._build_results_tab()
        self._build_settings_tab()
        self._build_status_bar(outer)

    def _build_header(self, parent: ttk.Frame) -> None:
        hdr = tk.Frame(parent, bg=_BG_SURFACE, height=90)
        hdr.pack(fill=tk.X, padx=16, pady=(16, 0))
        hdr.pack_propagate(False)

        logo = self._load_logo(target_h=64)
        if logo:
            tk.Label(hdr, image=logo, bg=_BG_SURFACE).pack(side=tk.LEFT, padx=(20, 0), pady=13)
        else:
            wrap = tk.Frame(hdr, bg=_BG_SURFACE)
            wrap.pack(side=tk.LEFT, padx=(20, 0), pady=10)
            tk.Label(
                wrap,
                text="HashGuard",
                bg=_BG_SURFACE,
                fg=_TEXT_PRIMARY,
                font=("Segoe UI", 18, "bold"),
            ).pack(anchor="w")
            tk.Label(
                wrap,
                text="File Verification & Threat Intelligence",
                bg=_BG_SURFACE,
                fg=_TEXT_SECONDARY,
                font=_UI_FONT_SM,
            ).pack(anchor="w")

        tk.Label(
            hdr,
            text=f"v{__version__}",
            bg=_BG_ELEVATED,
            fg=_TEXT_MUTED,
            font=("Segoe UI", 8),
            padx=8,
            pady=2,
        ).pack(side=tk.RIGHT, padx=20, pady=24)

    def _build_toolbar(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill=tk.X, padx=16, pady=(12, 8))

        self._btn_browse = ttk.Button(
            bar, text="Select File", style="Accent.TButton", command=self._on_browse
        )
        self._btn_browse.pack(side=tk.LEFT)

        self.vt_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="VirusTotal lookup", variable=self.vt_var).pack(
            side=tk.LEFT, padx=(16, 0)
        )

        self._btn_export = ttk.Button(
            bar, text="Export", style="Secondary.TButton", command=self._on_export, state="disabled"
        )
        self._btn_export.pack(side=tk.RIGHT, padx=(8, 0))

        self._btn_copy = ttk.Button(
            bar, text="Copy", style="Secondary.TButton", command=self._on_copy, state="disabled"
        )
        self._btn_copy.pack(side=tk.RIGHT)

        # URL input row
        url_row = ttk.Frame(parent)
        url_row.pack(fill=tk.X, padx=16, pady=(4, 4))
        ttk.Label(url_row, text="URL:", style="TLabel", font=_UI_FONT_BOLD).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        self._var_url = tk.StringVar()
        self._entry_url = ttk.Entry(url_row, textvariable=self._var_url)
        self._entry_url.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self._entry_url.bind("<Return>", lambda e: self._on_analyze_url())
        self._btn_url = ttk.Button(
            url_row, text="Analyze URL", style="Accent.TButton", command=self._on_analyze_url
        )
        self._btn_url.pack(side=tk.LEFT)

        # Drop zone
        self._drop_zone = tk.Frame(
            parent,
            bg=_BG_ELEVATED,
            height=60,
            highlightthickness=2,
            highlightbackground=_BORDER,
            highlightcolor=_ACCENT,
        )
        self._drop_zone.pack(fill=tk.X, padx=16, pady=(4, 4))
        self._drop_zone.pack_propagate(False)
        self._lbl_drop = tk.Label(
            self._drop_zone,
            text="\u2193  Drop a file here or use Select File  \u2193",
            bg=_BG_ELEVATED,
            fg=_TEXT_MUTED,
            font=_UI_FONT,
        )
        self._lbl_drop.pack(expand=True)

        row2 = ttk.Frame(parent)
        row2.pack(fill=tk.X, padx=16, pady=(0, 4))
        self._lbl_path = ttk.Label(row2, text="No file selected", style="Path.TLabel")
        self._lbl_path.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._progress = ttk.Progressbar(
            parent, mode="indeterminate", style="Accent.Horizontal.TProgressbar"
        )
        self._progress.pack(fill=tk.X, padx=16, pady=(0, 4))

    def _build_results_tab(self) -> None:
        pad = ttk.Frame(self._tab_results, style="Card.TFrame")
        pad.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        self._status_frame = tk.Frame(pad, bg=_BG_ELEVATED, height=40)
        self._status_frame.pack(fill=tk.X, padx=12, pady=(12, 0))
        self._status_frame.pack_propagate(False)

        self._lbl_status = tk.Label(
            self._status_frame,
            text="Waiting for file...",
            bg=_BG_ELEVATED,
            fg=_TEXT_MUTED,
            font=_UI_FONT_BOLD,
            anchor="w",
        )
        self._lbl_status.pack(fill=tk.X, padx=16, pady=8)

        txt_frame = tk.Frame(pad, bg=_BG_SURFACE)
        txt_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        self._txt = tk.Text(
            txt_frame,
            wrap=tk.WORD,
            bg=_BG_PRIMARY,
            fg=_TEXT_PRIMARY,
            insertbackground=_TEXT_PRIMARY,
            font=_MONO_FONT,
            relief="flat",
            padx=16,
            pady=12,
            spacing1=2,
            spacing3=2,
            selectbackground=_ACCENT,
            selectforeground="#FFFFFF",
            highlightthickness=1,
            highlightbackground=_BORDER,
            highlightcolor=_ACCENT,
        )
        self._txt.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        sb = ttk.Scrollbar(txt_frame, command=self._txt.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._txt["yscrollcommand"] = sb.set

        self._txt.tag_configure(
            "section", font=("Segoe UI Semibold", 11), foreground=_ACCENT, spacing1=8, spacing3=4
        )
        self._txt.tag_configure("label", font=("Segoe UI Semibold", 10), foreground=_TEXT_SECONDARY)
        self._txt.tag_configure("value", font=_MONO_FONT, foreground=_TEXT_PRIMARY)
        self._txt.tag_configure("hash", font=_MONO_FONT, foreground=_CYAN)
        self._txt.tag_configure("sep", foreground=_BORDER)
        self._txt.tag_configure("clean", font=("Segoe UI Semibold", 11), foreground=_GREEN)
        self._txt.tag_configure("threat", font=("Segoe UI Semibold", 11), foreground=_RED)
        self._txt.tag_configure("info", font=_UI_FONT_SM, foreground=_TEXT_MUTED)
        self._txt.tag_configure("warning", font=_UI_FONT_BOLD, foreground=_YELLOW)

    def _build_settings_tab(self) -> None:
        pad = ttk.Frame(self._tab_settings, style="Card.TFrame")
        pad.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        inner = ttk.Frame(pad, style="Card.TFrame")
        inner.pack(fill=tk.X, padx=24, pady=24)

        ttk.Label(inner, text="VirusTotal API Key", style="Card.TLabel", font=_UI_FONT_BOLD).grid(
            row=0, column=0, sticky="w", pady=(0, 4)
        )
        self._var_apikey = tk.StringVar(value=self._config.vt_api_key or "")
        ttk.Entry(inner, textvariable=self._var_apikey, show="\u2022", width=50).grid(
            row=1, column=0, sticky="ew", pady=(0, 16)
        )

        ttk.Label(inner, text="Signatures Database", style="Card.TLabel", font=_UI_FONT_BOLD).grid(
            row=2, column=0, sticky="w", pady=(0, 4)
        )
        self._var_sigfile = tk.StringVar(value=self._config.signatures_file or "")
        ttk.Entry(inner, textvariable=self._var_sigfile, width=50).grid(
            row=3, column=0, sticky="ew", pady=(0, 16)
        )

        btn_frame = ttk.Frame(inner, style="Card.TFrame")
        btn_frame.grid(row=4, column=0, sticky="w", pady=(8, 0))

        ttk.Button(
            btn_frame, text="Save Settings", style="Accent.TButton", command=self._on_save_settings
        ).pack(side=tk.LEFT)
        self._lbl_settings_status = ttk.Label(btn_frame, text="", style="Subtitle.TLabel")
        self._lbl_settings_status.pack(side=tk.LEFT, padx=(16, 0))

        inner.columnconfigure(0, weight=1)

    def _on_save_settings(self) -> None:
        key = self._var_apikey.get().strip()
        self._config.vt_api_key = key if key else None
        sig = self._var_sigfile.get().strip()
        if sig:
            self._config.signatures_file = sig
        self._config.save(self._config_path)
        self._lbl_settings_status.config(text="Settings saved \u2713")

    def _build_status_bar(self, parent: ttk.Frame) -> None:
        bar = tk.Frame(parent, bg=_BG_SURFACE, height=28)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)

        self._lbl_statusbar = tk.Label(
            bar,
            text="Ready",
            bg=_BG_SURFACE,
            fg=_TEXT_MUTED,
            font=("Segoe UI", 8),
            anchor="w",
            padx=16,
        )
        self._lbl_statusbar.pack(fill=tk.X, pady=4)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    _URL_RE = re.compile(r"^https?://", re.IGNORECASE)

    def _setup_dnd(self) -> None:
        """Register drag-and-drop handlers if tkinterdnd2 is available."""
        if not _HAS_DND:
            return
        try:
            for widget in (self._drop_zone, self._lbl_drop):
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<DropEnter>>", self._on_dnd_enter)
                widget.dnd_bind("<<DropLeave>>", self._on_dnd_leave)
                widget.dnd_bind("<<Drop>>", self._on_dnd_drop)
        except Exception:
            pass

    def _on_dnd_enter(self, event) -> None:
        self._drop_zone.config(highlightbackground=_ACCENT)
        self._lbl_drop.config(fg=_ACCENT, text="\u2193  Release to analyze  \u2193")

    def _on_dnd_leave(self, event) -> None:
        self._drop_zone.config(highlightbackground=_BORDER)
        self._lbl_drop.config(
            fg=_TEXT_MUTED, text="\u2193  Drop a file here or use Select File  \u2193"
        )

    def _on_dnd_drop(self, event) -> None:
        self._on_dnd_leave(event)
        if self._is_analyzing:
            return
        raw = event.data
        # tkdnd wraps paths with spaces in braces: {C:/path with spaces/file.exe}
        if raw.startswith("{"):
            path = raw.strip("{}").strip()
        else:
            path = raw.strip()
        if not os.path.isfile(path):
            self._show_error(f"Not a valid file: {path}")
            return
        self._lbl_path.config(text=path, style="TLabel")
        threading.Thread(target=self._run_analysis, args=(path,), daemon=True).start()

    def _on_browse(self) -> None:
        if self._is_analyzing:
            return
        path = filedialog.askopenfilename(
            title="Select a file to analyze",
            filetypes=[
                ("All files", "*.*"),
                ("Executables", "*.exe *.dll *.msi"),
                ("Archives", "*.zip *.rar *.7z"),
                ("Documents", "*.pdf *.docx"),
            ],
        )
        if not path:
            return
        self._lbl_path.config(text=path, style="TLabel")
        threading.Thread(target=self._run_analysis, args=(path,), daemon=True).start()

    def _on_analyze_url(self) -> None:
        if self._is_analyzing:
            return
        url = self._var_url.get().strip()
        if not url:
            return
        if not self._URL_RE.match(url):
            messagebox.showwarning("Invalid URL", "Please enter a valid HTTP or HTTPS URL.")
            return
        self._lbl_path.config(text=url, style="TLabel")
        threading.Thread(target=self._run_url_analysis, args=(url,), daemon=True).start()

    def _begin_analysis(self, label: str) -> None:
        self._is_analyzing = True
        self.root.after(0, lambda: self._btn_browse.config(state="disabled"))
        self.root.after(0, lambda: self._btn_url.config(state="disabled"))
        self.root.after(0, lambda: self._btn_export.config(state="disabled"))
        self.root.after(0, lambda: self._btn_copy.config(state="disabled"))
        self.root.after(0, lambda: self._progress.start(12))
        self.root.after(0, lambda: self._lbl_statusbar.config(text=f"Analyzing {label}..."))
        self.root.after(
            0, lambda: self._lbl_status.config(text="Analyzing...", fg=_YELLOW, bg=_BG_ELEVATED)
        )

    def _run_analysis(self, path: str) -> None:
        self._begin_analysis(os.path.basename(path))
        try:
            result = analyze(path, vt=self.vt_var.get(), config=self._config)
            self.current_result = result
            self.root.after(0, lambda: self._show_result(result))
        except Exception as exc:
            self.root.after(0, lambda e=str(exc): self._show_error(e))
        finally:
            self.root.after(0, self._analysis_done)

    def _run_url_analysis(self, url: str) -> None:
        self._begin_analysis(url)
        try:
            result = analyze_url(url, vt=self.vt_var.get(), config=self._config)
            self.current_result = result
            self.root.after(0, lambda: self._show_result(result))
        except Exception as exc:
            self.root.after(0, lambda e=str(exc): self._show_error(e))
        finally:
            self.root.after(0, self._analysis_done)

    def _analysis_done(self) -> None:
        self._is_analyzing = False
        self._progress.stop()
        self._btn_browse.config(state="normal")
        self._btn_url.config(state="normal")
        if self.current_result:
            self._btn_export.config(state="normal")
            self._btn_copy.config(state="normal")

    def _show_error(self, msg: str) -> None:
        self._lbl_status.config(text=f"Error: {msg}", fg=_RED, bg=_BG_ELEVATED)
        self._lbl_statusbar.config(text="Analysis failed")
        messagebox.showerror("Analysis Error", msg)

    # ------------------------------------------------------------------
    # Display results
    # ------------------------------------------------------------------

    def _show_result(self, r) -> None:
        t = self._txt
        t.config(state="normal")
        t.delete("1.0", tk.END)

        # Determine verdict from risk score
        risk = r.risk_score or {}
        score = risk.get("score", 0)
        verdict = risk.get("verdict", "clean" if not r.malicious else "malicious")

        if verdict == "malicious" or r.malicious:
            self._lbl_status.config(
                text=f"\u26a0  THREAT DETECTED  \u2014  Risk {score}/100", fg="#FFFFFF", bg=_RED
            )
            self._status_frame.config(bg=_RED)
            self._lbl_statusbar.config(text=f"Threat detected — risk score {score}/100")
        elif verdict == "suspicious":
            self._lbl_status.config(
                text=f"\u26a0  SUSPICIOUS  \u2014  Risk {score}/100", fg="#FFFFFF", bg=_YELLOW
            )
            self._status_frame.config(bg=_YELLOW)
            self._lbl_statusbar.config(text=f"Suspicious — risk score {score}/100")
        else:
            self._lbl_status.config(
                text=f"\u2713  FILE IS CLEAN  \u2014  Risk {score}/100", fg="#FFFFFF", bg=_GREEN
            )
            self._status_frame.config(bg=_GREEN)
            self._lbl_statusbar.config(text=f"Analysis complete — risk score {score}/100")

        # Risk Score section
        if risk:
            t.insert(tk.END, "RISK ASSESSMENT\n", "section")
            t.insert(tk.END, "\u2500" * 60 + "\n", "sep")
            # Visual bar
            filled = max(0, min(20, score // 5))
            bar = "\u2588" * filled + "\u2591" * (20 - filled)
            score_tag = "threat" if score > 50 else ("warning" if score > 20 else "clean")
            t.insert(tk.END, f"  Score     ", "label")
            t.insert(tk.END, f"{bar} {score}/100\n", score_tag)
            t.insert(tk.END, f"  Verdict   ", "label")
            t.insert(tk.END, f"{verdict.upper()}\n", score_tag)
            # Factors / threat indicators
            factors = risk.get("factors", [])
            if factors:
                t.insert(tk.END, "\n  Threat Indicators:\n", "label")
                for f in factors:
                    pts = f.get("points", 0)
                    tag = "threat" if pts >= 30 else ("warning" if pts >= 10 else "info")
                    t.insert(tk.END, f"    \u2714 {f['name']}", tag)
                    if f.get("detail"):
                        t.insert(tk.END, f"  ({f['detail']})", "info")
                    t.insert(tk.END, f"  +{pts}pts\n", "info")
            t.insert(tk.END, "\n")

        t.insert(tk.END, "FILE INFORMATION\n", "section")
        t.insert(tk.END, "\u2500" * 60 + "\n", "sep")
        self._kv(t, "Path", r.path)
        self._kv(t, "Size", f"{r.file_size:,} bytes")
        t.insert(tk.END, "\n")

        t.insert(tk.END, "CRYPTOGRAPHIC HASHES\n", "section")
        t.insert(tk.END, "\u2500" * 60 + "\n", "sep")
        for algo, val in r.hashes.items():
            t.insert(tk.END, f"  {algo.upper():8s}", "label")
            t.insert(tk.END, f"  {val}\n", "hash")
        t.insert(tk.END, "\n")

        t.insert(tk.END, "THREAT ANALYSIS\n", "section")
        t.insert(tk.END, "\u2500" * 60 + "\n", "sep")
        if r.malicious:
            t.insert(tk.END, "  Status    ", "label")
            t.insert(tk.END, "MALICIOUS\n", "threat")
            t.insert(tk.END, "  Detail    ", "label")
            t.insert(tk.END, f"{r.description}\n", "warning")
        else:
            t.insert(tk.END, "  Status    ", "label")
            t.insert(tk.END, "CLEAN\n", "clean")
        t.insert(tk.END, "\n")

        if r.vt_result:
            t.insert(tk.END, "VIRUSTOTAL INTELLIGENCE\n", "section")
            t.insert(tk.END, "\u2500" * 60 + "\n", "sep")
            data = r.vt_result.get("data", {})
            if data:
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                pos = stats.get("malicious", 0)
                total = sum(stats.values())
                t.insert(tk.END, "  Detections  ", "label")
                tag = "threat" if pos > 0 else "clean"
                t.insert(tk.END, f"{pos}/{total} engines\n", tag)
            else:
                t.insert(tk.END, "  No report available for this file\n", "info")
            t.insert(tk.END, "\n")

        # Threat Intelligence (MalwareBazaar, URLhaus)
        if r.threat_intel:
            t.insert(tk.END, "THREAT INTELLIGENCE\n", "section")
            t.insert(tk.END, "\u2500" * 60 + "\n", "sep")
            for hit in r.threat_intel.get("hits", []):
                src = hit.get("source", "Unknown")
                if hit.get("found"):
                    t.insert(tk.END, f"  {src:16s}", "label")
                    family = hit.get("malware_family", "Detected")
                    t.insert(tk.END, f"FOUND — {family}\n", "threat")
                    tags = hit.get("tags", [])
                    if tags:
                        t.insert(tk.END, f"  {'Tags':16s}", "label")
                        t.insert(tk.END, f"{', '.join(tags)}\n", "warning")
                else:
                    t.insert(tk.END, f"  {src:16s}", "label")
                    t.insert(tk.END, "Not found\n", "clean")
            t.insert(tk.END, "\n")

        # PE Analysis
        if r.pe_info and r.pe_info.get("is_pe"):
            pe = r.pe_info
            t.insert(tk.END, "PE EXECUTABLE ANALYSIS\n", "section")
            t.insert(tk.END, "\u2500" * 60 + "\n", "sep")
            self._kv(t, "Machine", pe.get("machine", ""))
            self._kv(t, "Compiled", pe.get("compile_time", ""))
            self._kv(t, "Entry", pe.get("entry_point", ""))
            entropy = pe.get("overall_entropy", 0)
            t.insert(tk.END, f"  {'Entropy':8s}", "label")
            ent_tag = "threat" if entropy > 7.0 else ("warning" if entropy > 6.5 else "clean")
            t.insert(tk.END, f"  {entropy:.4f} / 8.0\n", ent_tag)
            if pe.get("packed"):
                t.insert(tk.END, f"  {'Packer':8s}", "label")
                t.insert(tk.END, f"  {pe.get('packer_hint', 'Unknown')}\n", "threat")
            t.insert(tk.END, "\n")

            # Sections
            sections = pe.get("sections", [])
            if sections:
                t.insert(tk.END, "  Sections:\n", "label")
                for sec in sections:
                    ent = sec.get("entropy", 0)
                    ent_tag = "threat" if ent > 7.0 else ("warning" if ent > 6.5 else "value")
                    t.insert(tk.END, f"    {sec['name']:10s}", "value")
                    t.insert(tk.END, f"  entropy={ent:.2f}", ent_tag)
                    t.insert(
                        tk.END, f"  size={sec['raw_size']:>8,}  {sec['characteristics']}\n", "info"
                    )
                t.insert(tk.END, "\n")

            # Suspicious imports
            suspicious = pe.get("suspicious_imports", [])
            if suspicious:
                t.insert(tk.END, "  Suspicious API Imports:\n", "label")
                for imp in suspicious[:15]:
                    t.insert(tk.END, f"    {imp}\n", "warning")
                if len(suspicious) > 15:
                    t.insert(tk.END, f"    ... and {len(suspicious) - 15} more\n", "info")
                t.insert(tk.END, "\n")

            # Warnings
            warnings = pe.get("warnings", [])
            if warnings:
                for w in warnings:
                    t.insert(tk.END, f"  \u26a0 {w}\n", "warning")
                t.insert(tk.END, "\n")

        # YARA matches
        if r.yara_matches:
            t.insert(tk.END, "YARA RULE MATCHES\n", "section")
            t.insert(tk.END, "\u2500" * 60 + "\n", "sep")
            matches = r.yara_matches.get("matches", [])
            if matches:
                for m in matches:
                    t.insert(tk.END, f"  Rule      ", "label")
                    t.insert(tk.END, f"{m['rule']}\n", "threat")
                    meta = m.get("meta", {})
                    if meta.get("description"):
                        t.insert(tk.END, f"  Detail    ", "label")
                        t.insert(tk.END, f"{meta['description']}\n", "warning")
                    if meta.get("severity"):
                        t.insert(tk.END, f"  Severity  ", "label")
                        sev = meta["severity"]
                        sev_tag = "threat" if sev in ("critical", "high") else "warning"
                        t.insert(tk.END, f"{sev}\n", sev_tag)
                    strings = m.get("strings", [])
                    if strings:
                        for s in strings[:5]:
                            t.insert(tk.END, f"    {s}\n", "info")
                    t.insert(tk.END, "\n")
            loaded = r.yara_matches.get("rules_loaded", 0)
            t.insert(tk.END, f"  {loaded} rule file(s) loaded\n", "info")
            t.insert(tk.END, "\n")

        # Strings / IOC extraction
        si = r.strings_info
        if si and si.get("has_iocs"):
            t.insert(tk.END, "EXTRACTED IOCs & STRINGS\n", "section")
            t.insert(tk.END, "\u2500" * 60 + "\n", "sep")
            _ioc_cats = [
                ("urls", "URLs"),
                ("ips", "IP Addresses"),
                ("domains", "Domains"),
                ("emails", "Email Addresses"),
                ("powershell_commands", "PowerShell Commands"),
                ("suspicious_paths", "Suspicious Paths"),
                ("crypto_wallets", "Crypto Wallets"),
                ("user_agents", "User-Agents"),
                ("registry_keys", "Registry Keys"),
            ]
            for key, label in _ioc_cats:
                items = si.get(key, [])
                if items:
                    t.insert(tk.END, f"  {label} ({len(items)}):\n", "label")
                    for item in items[:10]:
                        t.insert(tk.END, f"    {item}\n", "warning")
                    if len(items) > 10:
                        t.insert(tk.END, f"    ... and {len(items) - 10} more\n", "info")
            t.insert(tk.END, "\n")

        t.insert(tk.END, f"  Completed in {r.analysis_time * 1000:.1f} ms\n", "info")

        t.config(state="disabled")
        self.notebook.select(self._tab_results)

    @staticmethod
    def _kv(t: tk.Text, key: str, val: str) -> None:
        t.insert(tk.END, f"  {key:8s}", "label")
        t.insert(tk.END, f"  {val}\n", "value")

    # ------------------------------------------------------------------
    # Export / Copy
    # ------------------------------------------------------------------

    def _on_export(self) -> None:
        if not self.current_result:
            return
        path = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("HTML", "*.html"), ("CSV", "*.csv")],
        )
        if not path:
            return
        try:
            from hashguard.reports import ReportGenerator

            if path.endswith(".html"):
                content = ReportGenerator.to_html([self.current_result])
            elif path.endswith(".csv"):
                content = ReportGenerator.to_csv([self.current_result])
            else:
                content = ReportGenerator.to_json([self.current_result])
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self._lbl_statusbar.config(text=f"Report saved to {path}")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    def _on_copy(self) -> None:
        if not self.current_result:
            return
        self._txt.config(state="normal")
        text = self._txt.get("1.0", tk.END).strip()
        self._txt.config(state="disabled")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._lbl_statusbar.config(text="Copied to clipboard")


def main() -> None:
    # Give HashGuard its own taskbar identity so Windows uses our icon
    # instead of python.exe's default icon.
    if sys.platform == "win32":
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("hashguard.gui")

    if _HAS_DND:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    HashGuardGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

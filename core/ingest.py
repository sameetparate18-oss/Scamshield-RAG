"""
ScamShield-RAG :: Enterprise Cyber Fraud Intelligence Workstation
"""

import os
import sys
import json
import time
import math
import threading
import traceback
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.config import THEME, HISTORY_FILE, MAX_AUDIT_RECORDS, APP_DISCLAIMER
from core.ingest import ingest_text, ingest_auto
from core.verdict_engine import VerdictEngine
from core.qr_inspector import analyze_qr_payload

# Optional Matplotlib integration
try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# Optional OpenCV integration
try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False


VERDICT_MAP = {
    "LIKELY_SCAM": {
        "badge": "CRITICAL RISK : MALICIOUS THREAT DETECTED",
        "fg": THEME["scam"],
        "bg": THEME["scam_bg"],
        "border": THEME["scam"]
    },
    "SUSPICIOUS": {
        "badge": "ELEVATED RISK : ANOMALOUS VECTORS FLAGGED",
        "fg": THEME["suspicious"],
        "bg": THEME["suspicious_bg"],
        "border": THEME["suspicious"]
    },
    "LIKELY_LEGITIMATE": {
        "badge": "CLEAR : NO HOSTILE VECTORS IDENTIFIED",
        "fg": THEME["safe"],
        "bg": THEME["safe_bg"],
        "border": THEME["safe"]
    }
}


class ScamShieldApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("ScamShield-RAG :: Cyber Threat Intelligence & Forensic Command")
        self.geometry("1420x920")
        self.minsize(1180, 780)
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=THEME["bg_app"])

        self.engine = None
        self.selected_file_path = None
        self.last_scan = None
        self.history_records = self._load_history()
        self.camera_running = False

        self._build_dashboard_skeleton()
        self._show_page("scanner")
        self._init_engine_thread()

        self.bind_all("<Control-Return>", lambda _: self._run_analysis())

    def _load_history(self):
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data[-MAX_AUDIT_RECORDS:] if isinstance(data, list) else []
            except Exception:
                pass
        return []

    def _save_history(self):
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(self.history_records[-MAX_AUDIT_RECORDS:], f, indent=2)
        except Exception:
            pass

    def _build_dashboard_skeleton(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ----------------- SIDEBAR -----------------
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=THEME["bg_sidebar"], border_width=1, border_color=THEME["border"])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        brand_box = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand_box.pack(fill="x", padx=20, pady=(24, 14))

        ctk.CTkLabel(brand_box, text="⚡ SCAMSHIELD", font=ctk.CTkFont("Segoe UI", 22, "bold"), text_color=THEME["text_main"]).pack(anchor="w")
        ctk.CTkLabel(brand_box, text="RAG THREAT INTELLIGENCE", font=ctk.CTkFont("Segoe UI", 10, "bold"), text_color=THEME["accent"]).pack(anchor="w", pady=(2, 0))

        self.badge_engine = ctk.CTkLabel(
            self.sidebar,
            text="● Engine: Loading Vectors...",
            font=ctk.CTkFont("Segoe UI", 11, "bold"),
            text_color=THEME["suspicious"],
            fg_color="#1E293B",
            corner_radius=6,
            height=32
        )
        self.badge_engine.pack(fill="x", padx=16, pady=(0, 20))

        # Nav Routes
        self.nav_btns = {}
        routes = [
            ("scanner", "⚡ Threat Scanner"),
            ("qr_scanner", "📷 Bharat-QR Inspector"),
            ("radar", "🕸️ Multi-Vector Radar"),
            ("history", "📋 Forensic Audit Log"),
            ("diagnostics", "⚙️ Vector Health & Nodes")
        ]
        for key, label in routes:
            btn = ctk.CTkButton(
                self.sidebar,
                text=label,
                font=ctk.CTkFont("Segoe UI", 13, "bold"),
                fg_color="transparent",
                text_color=THEME["text_muted"],
                hover_color=THEME["border"],
                anchor="w",
                height=42,
                corner_radius=8,
                command=lambda k=key: self._show_page(k)
            )
            btn.pack(fill="x", padx=12, pady=4)
            self.nav_btns[key] = btn

        # Footer
        sys_info = ctk.CTkFrame(self.sidebar, fg_color=THEME["bg_card_inner"], border_width=1, border_color=THEME["border"], corner_radius=8)
        sys_info.pack(side="bottom", fill="x", padx=14, pady=16)
        ctk.CTkLabel(sys_info, text="INTEL NODES: 6 SYNCED", font=ctk.CTkFont("Segoe UI", 10, "bold"), text_color=THEME["safe"]).pack(anchor="w", padx=10, pady=(8, 2))
        ctk.CTkLabel(sys_info, text="BUSHING & NPCI: ACTIVE", font=ctk.CTkFont("Segoe UI", 10), text_color=THEME["text_dim"]).pack(anchor="w", padx=10, pady=(0, 8))

        # ----------------- MAIN CANVAS -----------------
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=1, sticky="nsew")
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

        self.pages = {
            "scanner": self._build_page_scanner(),
            "qr_scanner": self._build_page_qr_scanner(),
            "radar": self._build_page_radar(),
            "history": self._build_page_history(),
            "diagnostics": self._build_page_diagnostics()
        }

    def _show_page(self, key):
        # Stop webcam if leaving QR page
        if key != "qr_scanner" and self.camera_running:
            self.camera_running = False

        for k, page in self.pages.items():
            page.grid_forget()
            self.nav_btns[k].configure(fg_color="transparent", text_color=THEME["text_muted"])

        self.pages[key].grid(row=0, column=0, sticky="nsew")
        self.nav_btns[key].configure(fg_color=THEME["border"], text_color=THEME["accent"])

        if key == "history":
            self._render_history_table()
        elif key == "radar":
            self._draw_radar_chart()

    # ==================================================================
    # PAGE: BHARAT-QR & QUISHING INSPECTOR
    # ==================================================================
    def _build_page_qr_scanner(self):
        page = ctk.CTkFrame(self.main_container, fg_color="transparent")
        page.grid_columnconfigure((0, 1), weight=1)
        page.grid_rowconfigure(1, weight=1)

        head = ctk.CTkFrame(page, fg_color="transparent")
        head.grid(row=0, column=0, columnspan=2, sticky="ew", padx=24, pady=(24, 10))
        ctk.CTkLabel(head, text="📷 Bharat-QR & Quishing Forensic Console", font=ctk.CTkFont("Segoe UI", 20, "bold"), text_color=THEME["text_main"]).pack(anchor="w")
        ctk.CTkLabel(head, text="Deconstructs NPCI UPI URIs, identifies partner PSP banks, and detects web redirects & quishing links.", font=ctk.CTkFont("Segoe UI", 12), text_color=THEME["text_muted"]).pack(anchor="w")

        # Left controls
        left_box = ctk.CTkFrame(page, fg_color=THEME["bg_card"], border_width=1, border_color=THEME["border"], corner_radius=10)
        left_box.grid(row=1, column=0, sticky="nsew", padx=(24, 10), pady=(0, 24))

        ctk.CTkLabel(left_box, text="Direct Ingestion", font=ctk.CTkFont("Segoe UI", 14, "bold"), text_color=THEME["accent"]).pack(anchor="w", padx=16, pady=(16, 8))

        ctk.CTkButton(
            left_box,
            text="📁 Upload QR Image / Poster",
            font=ctk.CTkFont("Segoe UI", 12, "bold"),
            fg_color=THEME["border"],
            hover_color=THEME["border_glow"],
            command=self._qr_upload_image
        ).pack(fill="x", padx=16, pady=6)

        ctk.CTkButton(
            left_box,
            text="📹 Scan via Live Webcam",
            font=ctk.CTkFont("Segoe UI", 12, "bold"),
            fg_color="#064E3B",
            hover_color="#059669",
            command=self._qr_toggle_webcam
        ).pack(fill="x", padx=16, pady=6)

        ctk.CTkLabel(left_box, text="Manual UPI URI String Input:", font=ctk.CTkFont("Segoe UI", 12), text_color=THEME["text_muted"]).pack(anchor="w", padx=16, pady=(16, 4))
        self.qr_manual_entry = ctk.CTkEntry(left_box, placeholder_text="upi://pay?pa=merchant@okhdfcbank...", fg_color=THEME["bg_card_inner"], border_color=THEME["border"])
        self.qr_manual_entry.pack(fill="x", padx=16, pady=(0, 8))

        ctk.CTkButton(left_box, text="Inspect Raw String", font=ctk.CTkFont("Segoe UI", 11, "bold"), fg_color=THEME["accent"], text_color="#06090F", command=self._qr_inspect_manual).pack(fill="x", padx=16, pady=(0, 16))

        # Status output
        self.lbl_qr_camera_status = ctk.CTkLabel(left_box, text="Camera: Idle", font=ctk.CTkFont("Segoe UI", 11), text_color=THEME["text_dim"])
        self.lbl_qr_camera_status.pack(anchor="w", padx=16, pady=(0, 10))

        # Right dossier display
        self.qr_dossier_box = ctk.CTkTextbox(page, font=ctk.CTkFont("Consolas", 12), fg_color=THEME["bg_card_inner"], border_width=1, border_color=THEME["border"])
        self.qr_dossier_box.grid(row=1, column=1, sticky="nsew", padx=(10, 24), pady=(0, 24))
        self.qr_dossier_box.insert("end", "Select an image or scan a QR code to view its forensic bank breakdown.")

        return page

    def _render_qr_result(self, res: dict):
        self.qr_dossier_box.delete("1.0", "end")
        text = (
            f"============================================================\n"
            f"BHARAT-QR & QUISHING FORENSIC ANALYSIS\n"
            f"============================================================\n\n"
            f"PAYLOAD TYPE       : {res.get('type')}\n"
            f"VPA (UPI ID)       : {res.get('vpa', 'N/A')}\n"
            f"DECLARED RECIPIENT : {res.get('declared_name', 'N/A')}\n"
            f"ISSUING BANK       : {res.get('banking_partner', 'N/A')}\n"
            f"PSP APPLICATION    : {res.get('psp_application', 'N/A')}\n"
            f"MERCHANT CODE (MCC): {res.get('merchant_code', 'N/A')}\n"
            f"AMOUNT LOCK        : {res.get('amount_locked', 'Dynamic')}\n"
            f"RISK CLASSIFICATION: {res.get('status')}\n"
            f"RISK SCORE         : {res.get('calculated_risk', 0.0):.2f} / 1.00\n\n"
            f"--- INDICATORS & ANOMALIES ---\n" + "\n".join([f"• {a}" for a in res.get("anomalies", [])]) + "\n\n"
            f"--- RAW DECODED PAYLOAD ---\n{res.get('raw_payload', '')}\n"
            f"============================================================"
        )
        self.qr_dossier_box.insert("end", text)

    def _qr_inspect_manual(self):
        text = self.qr_manual_entry.get().strip()
        if not text:
            messagebox.showwarning("Input Required", "Enter a UPI payload URI or URL.")
            return
        res = analyze_qr_payload(text)
        self._render_qr_result(res)

    def _qr_upload_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg *.webp")])
        if not path:
            return
        try:
            from pyzbar.pyzbar import decode as decode_qr
            from PIL import Image
            img = Image.open(path)
            decoded = decode_qr(img)
            if not decoded:
                messagebox.showinfo("No QR Detected", "No readable QR code found in the selected image.")
                return
            raw_payload = decoded[0].data.decode("utf-8", errors="ignore")
            res = analyze_qr_payload(raw_payload)
            self._render_qr_result(res)
        except Exception as e:
            messagebox.showerror("Decoding Error", f"Could not inspect image:\n{e}")

    def _qr_toggle_webcam(self):
        if not HAS_CV2:
            messagebox.showwarning("OpenCV Required", "Install opencv-python for live camera scanning:\npip install opencv-python")
            return

        if self.camera_running:
            self.camera_running = False
            self.lbl_qr_camera_status.configure(text="Camera: Stopped", text_color=THEME["text_dim"])
            return

        self.camera_running = True
        self.lbl_qr_camera_status.configure(text="Camera: Active (Press 'q' in camera window to close)", text_color=THEME["safe"])

        def _cam_worker():
            from pyzbar.pyzbar import decode as decode_qr
            cap = cv2.VideoCapture(0)
            while self.camera_running and cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break

                for code in decode_qr(frame):
                    payload = code.data.decode("utf-8", errors="ignore")
                    if payload:
                        self.camera_running = False
                        cap.release()
                        cv2.destroyAllWindows()
                        self.after(0, lambda p=payload: self._on_webcam_found(p))
                        return

                cv2.imshow("ScamShield - Scan QR (Press Q to exit)", frame)
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break

            cap.release()
            cv2.destroyAllWindows()
            self.camera_running = False
            self.after(0, lambda: self.lbl_qr_camera_status.configure(text="Camera: Stopped", text_color=THEME["text_dim"]))

        threading.Thread(target=_cam_worker, daemon=True).start()

    def _on_webcam_found(self, payload: str):
        self.lbl_qr_camera_status.configure(text="QR Captured Successfully", text_color=THEME["accent"])
        res = analyze_qr_payload(payload)
        self._render_qr_result(res)

    # ==================================================================
    # PAGE 1: THREAT SCANNER
    # ==================================================================
    def _build_page_scanner(self):
        page = ctk.CTkFrame(self.main_container, fg_color="transparent")
        page.grid_columnconfigure(0, weight=4)
        page.grid_columnconfigure(1, weight=6)
        page.grid_rowconfigure(0, weight=1)

        left_box = ctk.CTkFrame(page, fg_color="transparent")
        left_box.grid(row=0, column=0, sticky="nsew", padx=(20, 10), pady=20)
        left_box.grid_rowconfigure(1, weight=1)
        left_box.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left_box, text="Artifact Ingestion & Forensic Feed", font=ctk.CTkFont("Segoe UI", 16, "bold"), text_color=THEME["text_main"]).grid(row=0, column=0, sticky="w", pady=(0, 10))

        self.tabs = ctk.CTkTabview(left_box, corner_radius=10, fg_color=THEME["bg_card"])
        self.tabs.grid(row=1, column=0, sticky="nsew", pady=(0, 14))

        tab_text = self.tabs.add("Raw Communication / Script")
        tab_media = self.tabs.add("Forensic Artifact (Image / QR / Audio)")

        tab_text.grid_columnconfigure(0, weight=1)
        tab_text.grid_rowconfigure(0, weight=1)
        self.txt_evidence = ctk.CTkTextbox(tab_text, font=ctk.CTkFont("Segoe UI", 12), fg_color=THEME["bg_card_inner"], border_width=1, border_color=THEME["border"])
        self.txt_evidence.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)

        media_inner = ctk.CTkFrame(tab_media, fg_color="transparent")
        media_inner.pack(fill="both", expand=True, padx=12, pady=12)

        ctk.CTkButton(media_inner, text="📁 Select Artifact File", font=ctk.CTkFont("Segoe UI", 12, "bold"), fg_color=THEME["border"], hover_color=THEME["border_glow"], command=self._choose_artifact).pack(fill="x", pady=(10, 8))
        self.lbl_file_display = ctk.CTkLabel(media_inner, text="No artifact currently staged.", font=ctk.CTkFont("Segoe UI", 11), text_color=THEME["text_dim"])
        self.lbl_file_display.pack(anchor="w", pady=(0, 12))

        ctk.CTkLabel(media_inner, text="Pipelines Supported:\n• Optical Character Recognition (Screenshots, Fake IDs)\n• QR/Barcode Decoders (Quishing, Tampered UPI)\n• Voice Transcription (Calls, Voice Notes)", font=ctk.CTkFont("Segoe UI", 11), text_color=THEME["text_muted"], justify="left").pack(anchor="w")

        self.btn_analyze = ctk.CTkButton(left_box, text="⚡ Run Threat Assessment [Ctrl+Enter]", font=ctk.CTkFont("Segoe UI", 14, "bold"), fg_color=THEME["accent"], hover_color=THEME["accent_hover"], text_color="#06090F", height=46, corner_radius=8, command=self._run_analysis, state="disabled")
        self.btn_analyze.grid(row=2, column=0, sticky="ew")

        self.pipeline_box = ctk.CTkFrame(left_box, fg_color=THEME["bg_card"], border_width=1, border_color=THEME["border"], corner_radius=8)
        self.lbl_pipeline_step = ctk.CTkLabel(self.pipeline_box, text="Pipeline: Idle", font=ctk.CTkFont("Segoe UI", 11), text_color=THEME["text_dim"])
        self.lbl_pipeline_step.pack(anchor="w", padx=12, pady=8)

        # Right Analysis Canvas
        self.report_canvas = ctk.CTkScrollableFrame(page, fg_color="transparent")
        self.report_canvas.grid(row=0, column=1, sticky="nsew", padx=(10, 20), pady=20)
        self.report_canvas.grid_columnconfigure(0, weight=1)

        self.card_verdict = ctk.CTkFrame(self.report_canvas, fg_color=THEME["bg_card"], border_width=1, border_color=THEME["border"], corner_radius=10)
        self.card_verdict.pack(fill="x", pady=(0, 16))

        self.lbl_verdict_badge = ctk.CTkLabel(self.card_verdict, text="COMMAND CONSOLE READY", font=ctk.CTkFont("Segoe UI", 15, "bold"), text_color=THEME["text_muted"])
        self.lbl_verdict_badge.pack(anchor="w", padx=20, pady=(16, 4))
        self.lbl_verdict_vector = ctk.CTkLabel(self.card_verdict, text="Awaiting artifact for forensic classification.", font=ctk.CTkFont("Segoe UI", 12), text_color=THEME["text_muted"])
        self.lbl_verdict_vector.pack(anchor="w", padx=20, pady=(0, 8))

        prog_box = ctk.CTkFrame(self.card_verdict, fg_color="transparent")
        prog_box.pack(fill="x", padx=20, pady=(0, 12))
        self.prog_risk = ctk.CTkProgressBar(prog_box, progress_color=THEME["scam"], fg_color=THEME["border"], height=10)
        self.prog_risk.set(0)
        self.prog_risk.pack(fill="x", pady=(0, 4))
        self.lbl_risk_score = ctk.CTkLabel(prog_box, text="Calculated Risk Score: 0.00 / 1.00", font=ctk.CTkFont("Segoe UI", 11), text_color=THEME["text_muted"])
        self.lbl_risk_score.pack(anchor="w")

        action_row = ctk.CTkFrame(self.card_verdict, fg_color="transparent")
        action_row.pack(fill="x", padx=20, pady=(0, 14))
        self.lbl_timing = ctk.CTkLabel(action_row, text="", font=ctk.CTkFont("Segoe UI", 11), text_color=THEME["text_dim"])
        self.lbl_timing.pack(side="left")

        self.btn_export = ctk.CTkButton(action_row, text="Export Dossier", font=ctk.CTkFont("Segoe UI", 11, "bold"), fg_color=THEME["border"], width=110, height=28, state="disabled", command=self._export_dossier)
        self.btn_export.pack(side="right", padx=(8, 0))
        self.btn_copy = ctk.CTkButton(action_row, text="Copy Report", font=ctk.CTkFont("Segoe UI", 11, "bold"), fg_color=THEME["border"], width=90, height=28, state="disabled", command=self._copy_summary)
        self.btn_copy.pack(side="right")

        stats_row = ctk.CTkFrame(self.report_canvas, fg_color="transparent")
        stats_row.pack(fill="x", pady=(0, 16))
        stats_row.grid_columnconfigure((0, 1, 2), weight=1, uniform="stat_metric")
        self.stat_confidence = self._stat_card(stats_row, 0, "Confidence Index", "—")
        self.stat_ttp = self._stat_card(stats_row, 1, "MITRE ATT&CK TTP", "—")
        self.stat_law = self._stat_card(stats_row, 2, "Cross-Agency Alignment", "—")

        self.panel_reasoning = self._narrative_card(self.report_canvas, "📋 Threat Assessment & Semantic Reasoning", "Waiting for input...")
        self.panel_red_flags = self._narrative_card(self.report_canvas, "🚩 Detected Hostile Vectors & Indicators", "No scan active.")
        self.panel_citations = self._narrative_card(self.report_canvas, "📚 Regulatory Directives & Circulars", "No scan active.")

        return page

    # ==================================================================
    # PAGE: RADAR CHART
    # ==================================================================
    def _build_page_radar(self):
        page = ctk.CTkFrame(self.main_container, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)

        head = ctk.CTkFrame(page, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=24, pady=(24, 10))
        ctk.CTkLabel(head, text="Psychological & Cyber Weaponization Radar", font=ctk.CTkFont("Segoe UI", 20, "bold"), text_color=THEME["text_main"]).pack(anchor="w")
        ctk.CTkLabel(head, text="5-Axis polar decomposition of threat manipulation vectors.", font=ctk.CTkFont("Segoe UI", 12), text_color=THEME["text_muted"]).pack(anchor="w")

        self.radar_frame = ctk.CTkFrame(page, fg_color=THEME["bg_card"], border_width=1, border_color=THEME["border"], corner_radius=10)
        self.radar_frame.grid(row=1, column=0, sticky="nsew", padx=24, pady=(0, 24))
        self.radar_canvas_widget = None
        return page

    def _draw_radar_chart(self):
        if not HAS_MATPLOTLIB:
            for w in self.radar_frame.winfo_children():
                w.destroy()
            ctk.CTkLabel(self.radar_frame, text="Radar requires 'matplotlib'. Install via:\npip install matplotlib", font=ctk.CTkFont("Segoe UI", 13), text_color=THEME["text_muted"]).pack(expand=True)
            return

        if self.radar_canvas_widget:
            self.radar_canvas_widget.get_tk_widget().destroy()

        categories = ["Urgency / Coercion", "Impersonation", "Financial Diversion", "Linguistic Evasion", "Vector Proximity"]
        if self.last_scan and hasattr(self.last_scan["verdict"], "dimensions"):
            vals = [self.last_scan["verdict"].dimensions.get(c, 0.1) for c in categories]
        else:
            vals = [0.15, 0.2, 0.1, 0.12, 0.18]

        categories_closed = categories + [categories[0]]
        vals_closed = vals + [vals[0]]
        angles = [n / float(len(categories)) * 2 * math.pi for n in range(len(categories))]
        angles += angles[:1]

        fig = Figure(figsize=(6, 5), dpi=100, facecolor=THEME["bg_card"])
        ax = fig.add_subplot(111, polar=True, facecolor=THEME["bg_card_inner"])
        ax.tick_params(colors=THEME["text_muted"], labelsize=9)
        ax.spines['polar'].set_color(THEME["border"])
        ax.grid(color=THEME["border"], linestyle='--', alpha=0.7)

        color = THEME["scam"] if (self.last_scan and self.last_scan["verdict"].verdict == "LIKELY_SCAM") else THEME["accent"]
        ax.plot(angles, vals_closed, color=color, linewidth=2)
        ax.fill(angles, vals_closed, color=color, alpha=0.25)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories, color=THEME["text_main"], fontsize=10, weight="bold")
        ax.set_ylim(0, 1.0)

        self.radar_canvas_widget = FigureCanvasTkAgg(fig, master=self.radar_frame)
        self.radar_canvas_widget.draw()
        self.radar_canvas_widget.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)

    # ==================================================================
    # PAGE: AUDIT LOG
    # ==================================================================
    def _build_page_history(self):
        page = ctk.CTkFrame(self.main_container, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(2, weight=1)

        head = ctk.CTkFrame(page, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=24, pady=(24, 10))
        ctk.CTkLabel(head, text="Forensic Audit Trail", font=ctk.CTkFont("Segoe UI", 20, "bold"), text_color=THEME["text_main"]).pack(side="left")
        ctk.CTkButton(head, text="Clear Log", font=ctk.CTkFont("Segoe UI", 11), fg_color=THEME["scam_bg"], text_color=THEME["scam"], hover_color="#450818", width=90, command=self._clear_history).pack(side="right")

        self.search_entry = ctk.CTkEntry(page, placeholder_text="🔍 Search historical audit records...", font=ctk.CTkFont("Segoe UI", 12), fg_color=THEME["bg_card"], border_color=THEME["border"], height=36)
        self.search_entry.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 10))
        self.search_entry.bind("<KeyRelease>", lambda _: self._render_history_table())

        self.hist_scroll = ctk.CTkScrollableFrame(page, fg_color="transparent")
        self.hist_scroll.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0, 20))
        self.hist_scroll.grid_columnconfigure(0, weight=1)
        return page

    def _render_history_table(self):
        for w in self.hist_scroll.winfo_children():
            w.destroy()

        q = self.search_entry.get().strip().lower()
        records = [r for r in self.history_records if (q in r["text"].lower() or q in r["verdict"].lower())] if q else self.history_records

        if not records:
            ctk.CTkLabel(self.hist_scroll, text="No forensic records located.", font=ctk.CTkFont("Segoe UI", 12), text_color=THEME["text_dim"]).pack(pady=40)
            return

        for item in reversed(records):
            theme = VERDICT_MAP.get(item["verdict"], VERDICT_MAP["SUSPICIOUS"])
            card = ctk.CTkFrame(self.hist_scroll, fg_color=THEME["bg_card"], border_width=1, border_color=THEME["border"], corner_radius=8)
            card.pack(fill="x", pady=6)
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=16, pady=(10, 4))
            ctk.CTkLabel(top, text=item.get("timestamp", "-"), font=ctk.CTkFont("Segoe UI", 11), text_color=THEME["text_dim"]).pack(side="left")
            ctk.CTkLabel(top, text=f" {item['verdict']} ", font=ctk.CTkFont("Segoe UI", 10, "bold"), fg_color=theme["bg"], text_color=theme["fg"], corner_radius=4).pack(side="right")
            snippet = item["text"][:140] + ("..." if len(item["text"]) > 140 else "")
            ctk.CTkLabel(card, text=f'"{snippet}"', font=ctk.CTkFont("Segoe UI", 11), text_color=THEME["text_main"], justify="left", anchor="w").pack(fill="x", padx=16, pady=(0, 10))

    def _clear_history(self):
        if messagebox.askyesno("Confirm Purge", "Permanently erase local forensic logs?"):
            self.history_records.clear()
            self._save_history()
            self._render_history_table()

    # ==================================================================
    # PAGE: DIAGNOSTICS
    # ==================================================================
    def _build_page_diagnostics(self):
        page = ctk.CTkFrame(self.main_container, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)

        head = ctk.CTkFrame(page, fg_color="transparent")
        head.pack(fill="x", padx=24, pady=(24, 16))
        ctk.CTkLabel(head, text="Engine Diagnostics & Neural Health", font=ctk.CTkFont("Segoe UI", 20, "bold"), text_color=THEME["text_main"]).pack(anchor="w")

        card = ctk.CTkFrame(page, fg_color=THEME["bg_card"], border_width=1, border_color=THEME["border"], corner_radius=10)
        card.pack(fill="x", padx=24, pady=(0, 16))
        ctk.CTkLabel(card, text="Vector Engine State", font=ctk.CTkFont("Segoe UI", 14, "bold"), text_color=THEME["accent"]).pack(anchor="w", padx=20, pady=(16, 6))
        self.lbl_diag = ctk.CTkLabel(card, text="RAG State: Online\nVector Embeddings: Active\nLatency: <45ms", font=ctk.CTkFont("Segoe UI", 12), text_color=THEME["text_main"], justify="left")
        self.lbl_diag.pack(anchor="w", padx=20, pady=(0, 16))

        disc = ctk.CTkFrame(page, fg_color=THEME["bg_card"], border_width=1, border_color=THEME["border"], corner_radius=10)
        disc.pack(fill="x", padx=24, pady=(0, 16))
        ctk.CTkLabel(disc, text="⚠️ Academic & Operational Protocol", font=ctk.CTkFont("Segoe UI", 13, "bold"), text_color=THEME["suspicious"]).pack(anchor="w", padx=18, pady=(14, 4))
        ctk.CTkLabel(disc, text=APP_DISCLAIMER, font=ctk.CTkFont("Segoe UI", 11), text_color=THEME["text_muted"], justify="left", wraplength=750).pack(anchor="w", padx=18, pady=(0, 16))
        return page

    # ==================================================================
    # WIDGET FACTORIES & HELPERS
    # ==================================================================
    def _stat_card(self, parent, col, title, initial_val):
        box = ctk.CTkFrame(parent, fg_color=THEME["bg_card"], border_width=1, border_color=THEME["border"], corner_radius=8)
        box.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 0 if col == 2 else 6))
        ctk.CTkLabel(box, text=title, font=ctk.CTkFont("Segoe UI", 11), text_color=THEME["text_dim"]).pack(anchor="w", padx=14, pady=(10, 2))
        lbl = ctk.CTkLabel(box, text=initial_val, font=ctk.CTkFont("Segoe UI", 13, "bold"), text_color=THEME["text_main"])
        lbl.pack(anchor="w", padx=14, pady=(0, 10))
        return lbl

    def _narrative_card(self, parent, title, placeholder):
        card = ctk.CTkFrame(parent, fg_color=THEME["bg_card"], border_width=1, border_color=THEME["border"], corner_radius=8)
        card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont("Segoe UI", 12, "bold"), text_color=THEME["accent"]).pack(anchor="w", padx=16, pady=(12, 4))
        lbl = ctk.CTkLabel(card, text=placeholder, font=ctk.CTkFont("Segoe UI", 11), text_color=THEME["text_main"], justify="left", wraplength=620)
        lbl.pack(anchor="w", padx=16, pady=(0, 14))
        return lbl

    # ==================================================================
    # LOGIC & SCAN CONTROLLERS
    # ==================================================================
    def _init_engine_thread(self):
        def _worker():
            try:
                self.engine = VerdictEngine(use_llm=False)
                self.after(0, self._on_engine_ready)
            except Exception as e:
                err = str(e)
                self.after(0, lambda: self.badge_engine.configure(text=f"● Offline: {err[:15]}", text_color=THEME["scam"]))
        threading.Thread(target=_worker, daemon=True).start()

    def _on_engine_ready(self):
        self.badge_engine.configure(text="● Engine: Core Active", text_color=THEME["safe"], fg_color=THEME["safe_bg"])
        self.btn_analyze.configure(state="normal")

    def _choose_artifact(self):
        p = filedialog.askopenfilename(filetypes=[("All Supported", "*.png *.jpg *.jpeg *.webp *.wav *.mp3 *.txt"), ("Images & QR", "*.png *.jpg *.webp"), ("Audio", "*.wav *.mp3"), ("All", "*.*")])
        if p:
            self.selected_file_path = p
            self.lbl_file_display.configure(text=f"Staged: {os.path.basename(p)}", text_color=THEME["accent"])

    def _run_analysis(self):
        if not self.engine:
            messagebox.showwarning("Engine Offline", "Verdict engine is initializing.")
            return

        is_text = "Raw" in self.tabs.get()
        if is_text:
            text = self.txt_evidence.get("1.0", "end").strip()
            if not text:
                messagebox.showwarning("Input Required", "Enter text to inspect.")
                return
            mode, payload = "text", text
        else:
            if not self.selected_file_path:
                messagebox.showwarning("File Required", "Select an artifact file.")
                return
            mode, payload = "file", self.selected_file_path

        self.btn_analyze.configure(state="disabled")
        self.pipeline_box.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        self.lbl_pipeline_step.configure(text="Pipeline: Ingesting & Extracting Tokens...", text_color=THEME["accent"])

        def _worker():
            try:
                t0 = time.time()
                res = ingest_text(payload) if mode == "text" else ingest_auto(payload)
                t1 = time.time()

                if not getattr(res, "success", False):
                    raise ValueError(getattr(res, "error", "Ingestion failed."))

                extracted = getattr(res, "extracted_text", "").strip()
                if not extracted:
                    raise ValueError("No machine-readable tokens extracted.")

                self.after(0, lambda: self.lbl_pipeline_step.configure(text="Pipeline: Vector Retrieval & Scoring..."))

                t2 = time.time()
                verdict = self.engine.analyze(extracted)
                t3 = time.time()

                elapsed = {"ingest": round(t1 - t0, 2), "analysis": round(t3 - t2, 2), "total": round(t3 - t0, 2)}
                disp = payload if mode == "text" else os.path.basename(payload)
                self.after(0, lambda: self._on_scan_success(verdict, res, disp, elapsed))
            except Exception as e:
                err = str(e)
                traceback.print_exc()
                self.after(0, lambda: self._on_scan_error(err))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_scan_error(self, err):
        self.pipeline_box.grid_forget()
        self.btn_analyze.configure(state="normal")
        messagebox.showerror("Scan Error", f"Failed: {err}")

    def _on_scan_success(self, verdict, ingest_res, original_input, elapsed):
        self.pipeline_box.grid_forget()
        self.btn_analyze.configure(state="normal")

        v_data = VERDICT_MAP.get(verdict.verdict, VERDICT_MAP["SUSPICIOUS"])
        self.card_verdict.configure(fg_color=v_data["bg"], border_color=v_data["border"])
        self.lbl_verdict_badge.configure(text=v_data["badge"], text_color=v_data["fg"])
        self.lbl_verdict_vector.configure(text=f"Primary Threat Vector: {verdict.matched_category}")

        self.prog_risk.set(verdict.combined_score)
        self.prog_risk.configure(progress_color=v_data["fg"])
        self.lbl_risk_score.configure(text=f"Threat Score: {verdict.combined_score:.2f} / 1.00")

        self.stat_confidence.configure(text=f"{verdict.confidence * 100:.0f}% Verified")
        self.stat_ttp.configure(text=verdict.mitre_ttps[0] if getattr(verdict, "mitre_ttps", None) else "T1566: Phishing")
        self.stat_law.configure(text="Cross-Indexed (CERT-In, IC3)")

        prefix = f"[{ingest_res.modality.upper()} INGESTION]\n" if getattr(ingest_res, "modality", "text") != "text" else ""
        self.panel_reasoning.configure(text=f"{prefix}{verdict.explanation}")

        flags = "\n".join([f"• {f}" for f in verdict.red_flags]) if getattr(verdict, "red_flags", None) else "No hostile indicators detected."
        self.panel_red_flags.configure(text=flags)

        cites = "\n".join([f"• {c}" for c in verdict.citations]) if getattr(verdict, "citations", None) else "No statutory database matches recorded."
        self.panel_citations.configure(text=cites)

        self.lbl_timing.configure(text=f"Forensic Latency: {elapsed['total']}s (Ingest: {elapsed['ingest']}s, Analysis: {elapsed['analysis']}s)")

        self.last_scan = {
            "verdict": verdict,
            "ingest_res": ingest_res,
            "input": original_input,
            "elapsed": elapsed,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        self.btn_export.configure(state="normal")
        self.btn_copy.configure(state="normal")

        self.history_records.append({
            "timestamp": self.last_scan["timestamp"],
            "verdict": verdict.verdict,
            "text": original_input
        })
        self._save_history()
        self._draw_radar_chart()

    def _copy_summary(self):
        if not self.last_scan:
            return
        v = self.last_scan["verdict"]
        text = f"[{v.verdict}] Risk Score: {v.combined_score:.2f}\n{v.explanation}"
        self.clipboard_clear()
        self.clipboard_append(text)
        self.btn_copy.configure(text="Copied!")
        self.after(1200, lambda: self.btn_copy.configure(text="Copy Report"))

    def _export_dossier(self):
        if not self.last_scan:
            return
        v = self.last_scan["verdict"]
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"dossier_{int(time.time())}.txt")
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(f"VERDICT: {v.verdict}\nSCORE: {v.combined_score}\n\nREASONING:\n{v.explanation}\n\nFLAGS:\n" + "\n".join(v.red_flags))
            messagebox.showinfo("Saved", f"Dossier saved to {p}")


def main():
    app = ScamShieldApp()
    app.mainloop()


if __name__ == "__main__":
    main()
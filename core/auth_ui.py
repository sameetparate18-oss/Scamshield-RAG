"""
ScamShield-RAG :: Enterprise Investigator Authentication & Gate UI
Full-screen widescreen command portal with dual-panel SOC layout and seamless controls.
"""

import customtkinter as ctk
from tkinter import messagebox
from core.auth_manager import (
    authenticate_investigator,
    register_investigator,
    generate_simulated_otp
)

THEME = {
    "bg_app": "#06090F",
    "bg_card": "#0D1322",
    "bg_input": "#070B14",
    "border": "#1E293B",
    "border_glow": "#38BDF8",
    "accent": "#00F0FF",
    "accent_hover": "#0EA5E9",
    "text_main": "#F8FAFC",
    "text_muted": "#94A3B8",
    "text_dim": "#475569",
    "scam": "#FF3366",
    "suspicious": "#FBBF24",
    "safe": "#10B981"
}


class InvestigatorLoginWindow(ctk.CTk):
    def __init__(self, on_auth_success):
        super().__init__()
        self.on_auth_success = on_auth_success

        self.title("ScamShield-RAG — SOC Investigator Access Gate")
        
        # Maximize to full page / window
        try:
            self.state("zoomed")  # Native Windows maximize
        except Exception:
            self.attributes("-zoomed", True)  # Linux / X11 fallback

        self.geometry("1280x800")
        self.minsize(1024, 700)
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=THEME["bg_app"])

        self.current_mode = "login"
        self.show_login_pin = False
        self.show_reg_pin = False

        self._build_full_page_ui()

    def _build_full_page_ui(self):
        # Master Grid Configuration
        self.grid_columnconfigure(0, weight=5)  # Left telemetry / info panel
        self.grid_columnconfigure(1, weight=5)  # Right authentication terminal
        self.grid_rowconfigure(0, weight=1)

        # ==============================================================
        # LEFT PANEL: SOC INTELLIGENCE & TELEMETRY HUB
        # ==============================================================
        left_panel = ctk.CTkFrame(self, fg_color="transparent")
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(60, 30), pady=60)
        left_panel.grid_columnconfigure(0, weight=1)

        # Brand header
        ctk.CTkLabel(
            left_panel,
            text="⚡ SCAMSHIELD-RAG",
            font=ctk.CTkFont("Segoe UI", 32, "bold"),
            text_color=THEME["text_main"]
        ).pack(anchor="w")

        ctk.CTkLabel(
            left_panel,
            text="ENTERPRISE CYBER THREAT INTELLIGENCE & FORENSIC SUITE",
            font=ctk.CTkFont("Segoe UI", 12, "bold"),
            text_color=THEME["accent"]
        ).pack(anchor="w", pady=(2, 24))

        # Core Info Box
        info_card = ctk.CTkFrame(
            left_panel,
            fg_color=THEME["bg_card"],
            border_width=1,
            border_color=THEME["border"],
            corner_radius=12
        )
        info_card.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            info_card,
            text="COMMAND WORKSTATION SECURITY STANDARDS",
            font=ctk.CTkFont("Segoe UI", 11, "bold"),
            text_color=THEME["accent"]
        ).pack(anchor="w", padx=24, pady=(20, 8))

        specs = [
            ("🔐 Cryptographic Custody", "Every uploaded artifact generates a SHA-256 seal signed with the active examiner ID."),
            ("⚖️ Statutory Requisitions", "Pre-formatted legal requisition notices mapped to Section 94 BNSS & IT Act 2000."),
            ("🛡️ Multi-Vector Analysis", "Automated heuristics for Digital Arrest, Bharat-QR fraud, and APK infostealers."),
            ("🌐 Law Enforcement Feeds", "Synced indices with Interpol, CERT-In, FBI IC3, and URLhaus live feeds.")
        ]

        for title, desc in specs:
            box = ctk.CTkFrame(info_card, fg_color="transparent")
            box.pack(fill="x", padx=24, pady=6)
            ctk.CTkLabel(box, text=f"• {title}:", font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=THEME["text_main"]).pack(anchor="w")
            ctk.CTkLabel(box, text=f"  {desc}", font=ctk.CTkFont("Segoe UI", 10), text_color=THEME["text_muted"], wraplength=480, justify="left").pack(anchor="w")

        # Bottom System Nodes Strip
        node_strip = ctk.CTkFrame(
            left_panel,
            fg_color=THEME["bg_card"],
            border_width=1,
            border_color=THEME["border"],
            corner_radius=10
        )
        node_strip.pack(fill="x", side="bottom")

        node_inner = ctk.CTkFrame(node_strip, fg_color="transparent")
        node_inner.pack(fill="x", padx=20, pady=14)

        ctk.CTkLabel(
            node_inner,
            text="● SYSTEM STATUS: ALL ENGINES OPERATIONAL",
            font=ctk.CTkFont("Segoe UI", 10, "bold"),
            text_color=THEME["safe"]
        ).pack(side="left")

        ctk.CTkLabel(
            node_inner,
            text="LATENCY: <45ms",
            font=ctk.CTkFont("Segoe UI", 10),
            text_color=THEME["text_dim"]
        ).pack(side="right")

        # ==============================================================
        # RIGHT PANEL: EXAMINER ACCESS TERMINAL
        # ==============================================================
        right_container = ctk.CTkFrame(
            self,
            fg_color=THEME["bg_card"],
            border_width=1,
            border_color=THEME["border"],
            corner_radius=16
        )
        right_container.grid(row=0, column=1, sticky="nsew", padx=(30, 60), pady=60)
        right_container.grid_columnconfigure(0, weight=1)

        # Top Selector Row
        tab_bar = ctk.CTkFrame(
            right_container,
            fg_color=THEME["bg_input"],
            corner_radius=10,
            border_width=1,
            border_color=THEME["border"],
            height=48
        )
        tab_bar.pack(fill="x", padx=40, pady=(36, 20))
        tab_bar.pack_propagate(False)

        self.btn_tab_login = ctk.CTkButton(
            tab_bar,
            text="Examiner Login",
            font=ctk.CTkFont("Segoe UI", 13, "bold"),
            fg_color=THEME["accent"],
            text_color="#06090F",
            hover_color=THEME["accent_hover"],
            corner_radius=8,
            command=lambda: self._switch_tab("login")
        )
        self.btn_tab_login.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        self.btn_tab_reg = ctk.CTkButton(
            tab_bar,
            text="Enlist New Examiner",
            font=ctk.CTkFont("Segoe UI", 13, "bold"),
            fg_color="transparent",
            text_color=THEME["text_muted"],
            hover_color=THEME["border"],
            corner_radius=8,
            command=lambda: self._switch_tab("register")
        )
        self.btn_tab_reg.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # Views
        self.frame_login = ctk.CTkFrame(right_container, fg_color="transparent")
        self.frame_reg = ctk.CTkFrame(right_container, fg_color="transparent")

        self._build_login_view(self.frame_login)
        self._build_register_view(self.frame_reg)

        self.frame_login.pack(fill="both", expand=True, padx=40, pady=(0, 30))

    def _switch_tab(self, mode: str):
        if mode == self.current_mode:
            return
        self.current_mode = mode

        if mode == "login":
            self.frame_reg.pack_forget()
            self.frame_login.pack(fill="both", expand=True, padx=40, pady=(0, 30))
            self.btn_tab_login.configure(fg_color=THEME["accent"], text_color="#06090F")
            self.btn_tab_reg.configure(fg_color="transparent", text_color=THEME["text_muted"])
        else:
            self.frame_login.pack_forget()
            self.frame_reg.pack(fill="both", expand=True, padx=40, pady=(0, 30))
            self.btn_tab_reg.configure(fg_color=THEME["accent"], text_color="#06090F")
            self.btn_tab_login.configure(fg_color="transparent", text_color=THEME["text_muted"])

    # ---------------- LOGIN VIEW ----------------
    def _build_login_view(self, parent):
        ctk.CTkLabel(
            parent,
            text="Officer Badge / Identifier",
            font=ctk.CTkFont("Segoe UI", 12, "bold"),
            text_color=THEME["text_muted"]
        ).pack(anchor="w", pady=(14, 4))

        self.entry_login_badge = ctk.CTkEntry(
            parent,
            placeholder_text="e.g. OFFICER-701",
            font=ctk.CTkFont("Segoe UI", 13),
            fg_color=THEME["bg_input"],
            border_color=THEME["border"],
            height=44,
            corner_radius=8
        )
        self.entry_login_badge.pack(fill="x", pady=(0, 16))
        self.entry_login_badge.insert(0, "OFFICER-701")

        ctk.CTkLabel(
            parent,
            text="Forensic Security PIN",
            font=ctk.CTkFont("Segoe UI", 12, "bold"),
            text_color=THEME["text_muted"]
        ).pack(anchor="w", pady=(0, 4))

        pin_row = ctk.CTkFrame(parent, fg_color="transparent")
        pin_row.pack(fill="x", pady=(0, 12))

        self.entry_login_pin = ctk.CTkEntry(
            pin_row,
            placeholder_text="••••",
            show="•",
            font=ctk.CTkFont("Consolas", 16),
            fg_color=THEME["bg_input"],
            border_color=THEME["border"],
            height=44,
            corner_radius=8
        )
        self.entry_login_pin.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.entry_login_pin.insert(0, "1234")
        self.entry_login_pin.bind("<Return>", lambda _: self._handle_login())

        self.btn_eye_login = ctk.CTkButton(
            pin_row,
            text="👁",
            width=44,
            height=44,
            font=ctk.CTkFont("Segoe UI", 14),
            fg_color=THEME["bg_input"],
            border_width=1,
            border_color=THEME["border"],
            hover_color=THEME["border"],
            corner_radius=8,
            command=self._toggle_login_pin
        )
        self.btn_eye_login.pack(side="right")

        self.lbl_login_status = ctk.CTkLabel(
            parent,
            text="",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=THEME["scam"],
            wraplength=460,
            justify="left"
        )
        self.lbl_login_status.pack(anchor="w", pady=(0, 14))

        self.btn_login = ctk.CTkButton(
            parent,
            text="🔓 Authorize Session & Launch Workstation",
            font=ctk.CTkFont("Segoe UI", 13, "bold"),
            fg_color=THEME["accent"],
            hover_color=THEME["accent_hover"],
            text_color="#06090F",
            height=48,
            corner_radius=8,
            command=self._handle_login
        )
        self.btn_login.pack(fill="x", pady=(0, 20))

        # Integrated Advisory Box
        advisory_box = ctk.CTkFrame(
            parent,
            fg_color=THEME["bg_input"],
            border_width=1,
            border_color=THEME["border"],
            corner_radius=8
        )
        advisory_box.pack(fill="x", pady=(10, 0))

        ctk.CTkLabel(
            advisory_box,
            text="🔒 CUSTODIAL INTEGRITY NOTICE",
            font=ctk.CTkFont("Segoe UI", 10, "bold"),
            text_color=THEME["accent"]
        ).pack(anchor="w", padx=16, pady=(12, 2))

        ctk.CTkLabel(
            advisory_box,
            text="Authorized forensic personnel only. All neural queries, evidence custody logs, and requisition orders are legally bound to the active examiner's badge ID.",
            font=ctk.CTkFont("Segoe UI", 10),
            text_color=THEME["text_dim"],
            justify="left",
            wraplength=460
        ).pack(anchor="w", padx=16, pady=(0, 12))

    # ---------------- REGISTER VIEW ----------------
    def _build_register_view(self, parent):
        fields = [
            ("Full Officer Name", "e.g. Insp. Sameet Parate", "reg_name"),
            ("Assigned Badge Identifier", "e.g. CYBER-PUN-402", "reg_badge"),
            ("Unit / Police Station / Lab", "e.g. Pune Cyber Crime Cell", "reg_agency"),
            ("Official Mobile (for 2FA)", "+91 98765 43210", "reg_phone")
        ]

        self.reg_entries = {}
        for label, placeholder, key in fields:
            ctk.CTkLabel(
                parent,
                text=label,
                font=ctk.CTkFont("Segoe UI", 11, "bold"),
                text_color=THEME["text_muted"]
            ).pack(anchor="w", pady=(3, 2))

            ent = ctk.CTkEntry(
                parent,
                placeholder_text=placeholder,
                font=ctk.CTkFont("Segoe UI", 12),
                height=38,
                fg_color=THEME["bg_input"],
                border_color=THEME["border"],
                corner_radius=8
            )
            ent.pack(fill="x", pady=(0, 6))
            self.reg_entries[key] = ent

        ctk.CTkLabel(
            parent,
            text="Forensic Access PIN (4-8 Digits)",
            font=ctk.CTkFont("Segoe UI", 11, "bold"),
            text_color=THEME["text_muted"]
        ).pack(anchor="w", pady=(2, 2))

        reg_pin_row = ctk.CTkFrame(parent, fg_color="transparent")
        reg_pin_row.pack(fill="x", pady=(0, 4))

        self.reg_pin = ctk.CTkEntry(
            reg_pin_row,
            placeholder_text="••••",
            show="•",
            font=ctk.CTkFont("Consolas", 14),
            height=38,
            fg_color=THEME["bg_input"],
            border_color=THEME["border"],
            corner_radius=8
        )
        self.reg_pin.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.reg_pin.bind("<KeyRelease>", self._audit_pin_complexity)

        self.btn_eye_reg = ctk.CTkButton(
            reg_pin_row,
            text="👁",
            width=38,
            height=38,
            font=ctk.CTkFont("Segoe UI", 13),
            fg_color=THEME["bg_input"],
            border_width=1,
            border_color=THEME["border"],
            hover_color=THEME["border"],
            corner_radius=8,
            command=self._toggle_reg_pin
        )
        self.btn_eye_reg.pack(side="right")

        self.lbl_pin_strength = ctk.CTkLabel(
            parent,
            text="Complexity: Enter at least 4 digits",
            font=ctk.CTkFont("Segoe UI", 9),
            text_color=THEME["text_dim"]
        )
        self.lbl_pin_strength.pack(anchor="w", pady=(0, 6))

        self.lbl_reg_status = ctk.CTkLabel(
            parent,
            text="",
            font=ctk.CTkFont("Segoe UI", 10),
            text_color=THEME["scam"]
        )
        self.lbl_reg_status.pack(anchor="w", pady=(0, 6))

        ctk.CTkButton(
            parent,
            text="📲 Proceed to 2FA Verification",
            font=ctk.CTkFont("Segoe UI", 12, "bold"),
            fg_color=THEME["accent"],
            hover_color=THEME["accent_hover"],
            text_color="#06090F",
            height=42,
            corner_radius=8,
            command=self._initiate_registration_flow
        ).pack(fill="x", pady=(0, 8))

    def _toggle_login_pin(self):
        self.show_login_pin = not self.show_login_pin
        self.entry_login_pin.configure(show="" if self.show_login_pin else "•")
        self.btn_eye_login.configure(text="🔒" if self.show_login_pin else "👁")

    def _toggle_reg_pin(self):
        self.show_reg_pin = not self.show_reg_pin
        self.reg_pin.configure(show="" if self.show_reg_pin else "•")
        self.btn_eye_reg.configure(text="🔒" if self.show_reg_pin else "👁")

    def _audit_pin_complexity(self, _event=None):
        val = self.reg_pin.get().strip()
        if len(val) < 4:
            self.lbl_pin_strength.configure(text="Complexity: Too short (Minimum 4 digits)", text_color=THEME["scam"])
        elif val.isdigit() and len(set(val)) == 1:
            self.lbl_pin_strength.configure(text="Complexity: Weak (Repeated digits)", text_color=THEME["suspicious"])
        elif len(val) >= 4 and val.isdigit():
            self.lbl_pin_strength.configure(text="Complexity: Strong & Valid", text_color=THEME["safe"])
        else:
            self.lbl_pin_strength.configure(text="Complexity: Only numeric digits permitted", text_color=THEME["suspicious"])

    def _handle_login(self):
        badge = self.entry_login_badge.get().strip()
        pin = self.entry_login_pin.get().strip()

        if not badge or not pin:
            self.lbl_login_status.configure(text="Badge identifier and PIN are required.", text_color=THEME["scam"])
            return

        ok, session, msg = authenticate_investigator(badge, pin)
        if not ok:
            self.lbl_login_status.configure(text=msg, text_color=THEME["scam"])
            return

        self.lbl_login_status.configure(text="Access Granted. Launching Workstation...", text_color=THEME["safe"])
        self.btn_login.configure(state="disabled")
        self.after(350, lambda: self._complete_launch(session))

    def _complete_launch(self, session):
        self.destroy()
        self.on_auth_success(session)

    def _initiate_registration_flow(self):
        name = self.reg_entries["reg_name"].get().strip()
        badge = self.reg_entries["reg_badge"].get().strip()
        agency = self.reg_entries["reg_agency"].get().strip()
        pin = self.reg_pin.get().strip()

        if not all([name, badge, agency, pin]):
            self.lbl_reg_status.configure(text="Please fill in all profile fields.", text_color=THEME["scam"])
            return

        if len(pin) < 4 or not pin.isdigit():
            self.lbl_reg_status.configure(text="PIN must be at least 4 numeric digits.", text_color=THEME["scam"])
            return

        otp_code = generate_simulated_otp()
        self._spawn_otp_dialog(otp_code, badge, name, agency, pin)

    def _spawn_otp_dialog(self, correct_otp: str, badge: str, name: str, agency: str, pin: str):
        otp_modal = ctk.CTkToplevel(self)
        otp_modal.title("2FA Security Verification")
        otp_modal.geometry("450x370")
        otp_modal.resizable(False, False)
        otp_modal.configure(fg_color=THEME["bg_app"])
        otp_modal.transient(self)
        otp_modal.grab_set()

        card = ctk.CTkFrame(otp_modal, fg_color=THEME["bg_card"], border_width=1, border_color=THEME["border"], corner_radius=12)
        card.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            card,
            text="📱 Two-Factor Authentication",
            font=ctk.CTkFont("Segoe UI", 16, "bold"),
            text_color=THEME["text_main"]
        ).pack(anchor="w", padx=20, pady=(18, 4))

        ctk.CTkLabel(
            card,
            text="Enter the dispatch code below to authorize your credentials:",
            font=ctk.CTkFont("Segoe UI", 10),
            text_color=THEME["text_muted"]
        ).pack(anchor="w", padx=20, pady=(0, 10))

        toast_box = ctk.CTkFrame(card, fg_color="#03251A", corner_radius=6, border_width=1, border_color=THEME["safe"])
        toast_box.pack(fill="x", padx=20, pady=(0, 14))

        ctk.CTkLabel(
            toast_box,
            text=f"🔑 [MHA-CYBER 2FA] Code: {correct_otp} (Valid 3 mins)",
            font=ctk.CTkFont("Consolas", 11, "bold"),
            text_color=THEME["safe"]
        ).pack(padx=12, pady=8)

        entry_otp = ctk.CTkEntry(
            card,
            font=ctk.CTkFont("Consolas", 18, "bold"),
            justify="center",
            height=42,
            fg_color=THEME["bg_input"],
            border_color=THEME["border"],
            corner_radius=8
        )
        entry_otp.pack(fill="x", padx=20, pady=(0, 8))
        entry_otp.focus_set()

        lbl_otp_err = ctk.CTkLabel(card, text="", font=ctk.CTkFont("Segoe UI", 10), text_color=THEME["scam"])
        lbl_otp_err.pack(anchor="w", padx=20, pady=(0, 10))

        def _verify():
            entered = entry_otp.get().strip()
            if entered != correct_otp:
                lbl_otp_err.configure(text="Invalid OTP. Please check the code and retry.")
                return

            ok, msg = register_investigator(badge, name, agency, "Forensic Cyber Analyst", pin)
            if ok:
                otp_modal.destroy()
                messagebox.showinfo("Enlisted", f"Officer Profile {badge} enlisted successfully.\nYou may now log in.")
                self._switch_tab("login")
                self.entry_login_badge.delete(0, "end")
                self.entry_login_badge.insert(0, badge)
                self.entry_login_pin.delete(0, "end")
            else:
                lbl_otp_err.configure(text=msg)

        ctk.CTkButton(
            card,
            text="Confirm & Commit Enlistment",
            font=ctk.CTkFont("Segoe UI", 12, "bold"),
            fg_color=THEME["accent"],
            hover_color=THEME["accent_hover"],
            text_color="#06090F",
            height=38,
            corner_radius=8,
            command=_verify
        ).pack(fill="x", padx=20, pady=(0, 12))
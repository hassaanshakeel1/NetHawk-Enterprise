import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import csv


class NetHawkEnterprise:
    def __init__(self, root):
        self.root = root
        self.root.title("NetHawk Enterprise | Advanced Port Scanner")
        self.root.geometry("950x750")
        self.root.minsize(850, 650)

        # Configure modern, clean color scheme
        self.style = ttk.Style()
        if 'clam' in self.style.theme_names():
            self.style.theme_use('clam')

        self.bg_color = "#f4f6f9"
        self.root.configure(bg=self.bg_color)

        # Style Configurations
        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure("TLabel", background=self.bg_color, font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", font=("Segoe UI", 20, "bold"), foreground="#1e293b")
        self.style.configure("SubHeader.TLabel", font=("Segoe UI", 10), foreground="#64748b")
        self.style.configure("TLabelframe", background=self.bg_color)
        self.style.configure("TLabelframe.Label", font=("Segoe UI", 11, "bold"), foreground="#0f172a",
                             background=self.bg_color)

        # Button Styles
        self.style.configure("TButton", font=("Segoe UI", 10), padding=6)
        self.style.configure("Primary.TButton", background="#0ea5e9", foreground="white", font=("Segoe UI", 10, "bold"))
        self.style.map("Primary.TButton", background=[("active", "#0284c7")])

        # State Variables
        self.is_scanning = False
        self.total_ports = 0
        self.scanned_ports = 0
        self.discovered_ports = []

        self.setup_ui()

    def setup_ui(self):
        # --- HEADER ---
        header_frame = ttk.Frame(self.root, padding=(25, 20, 25, 10))
        header_frame.pack(fill="x")

        ttk.Label(header_frame, text="NetHawk Enterprise", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header_frame, text="Developed by Hassaan Shakeel  •  Network Intelligence Tool",
                  style="SubHeader.TLabel").pack(anchor="w")

        # --- CONTROL PANEL ---
        control_frame = ttk.LabelFrame(self.root, text="Scan Configuration", padding=(20, 15))
        control_frame.pack(fill="x", padx=25, pady=10)

        # Row 0: Target & Profile
        ttk.Label(control_frame, text="Target (IP/URL):").grid(row=0, column=0, padx=5, pady=10, sticky="e")
        self.target_entry = ttk.Entry(control_frame, width=30, font=("Segoe UI", 10))
        self.target_entry.insert(0, "scanme.nmap.org")
        self.target_entry.grid(row=0, column=1, padx=5, pady=10, sticky="w")

        ttk.Label(control_frame, text="Scan Profile:").grid(row=0, column=2, padx=(30, 5), pady=10, sticky="e")
        self.profile_var = tk.StringVar()
        self.profile_cb = ttk.Combobox(control_frame, textvariable=self.profile_var, state="readonly", width=25,
                                       font=("Segoe UI", 10))
        self.profile_cb['values'] = (
            "Well-Known Ports (1-1024)",
            "Registered Ports (1024-49151)",
            "Full Scan (1-65535)",
            "Custom Range"
        )
        self.profile_cb.current(0)
        self.profile_cb.grid(row=0, column=3, padx=5, pady=10, sticky="w")
        self.profile_cb.bind("<<ComboboxSelected>>", self.on_profile_change)

        # Row 1: Custom Ports & Threads
        ttk.Label(control_frame, text="Start Port:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.start_port = ttk.Entry(control_frame, width=10, font=("Segoe UI", 10))
        self.start_port.insert(0, "1")
        self.start_port.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.start_port.config(state="disabled")

        ttk.Label(control_frame, text="End Port:").grid(row=1, column=2, padx=(30, 5), pady=5, sticky="e")

        port_thread_frame = ttk.Frame(control_frame)
        port_thread_frame.grid(row=1, column=3, sticky="w")

        self.end_port = ttk.Entry(port_thread_frame, width=10, font=("Segoe UI", 10))
        self.end_port.insert(0, "1024")
        self.end_port.pack(side="left", padx=(5, 20))
        self.end_port.config(state="disabled")

        ttk.Label(port_thread_frame, text="Threads:").pack(side="left", padx=5)
        self.threads_entry = ttk.Entry(port_thread_frame, width=8, font=("Segoe UI", 10))
        self.threads_entry.insert(0, "300")
        self.threads_entry.pack(side="left")

        # Row 2: Action Buttons
        btn_frame = ttk.Frame(control_frame)
        btn_frame.grid(row=2, column=0, columnspan=4, pady=(15, 5))

        self.scan_btn = ttk.Button(btn_frame, text="▶ Start Scan", style="Primary.TButton", command=self.start_scan,
                                   width=15)
        self.scan_btn.pack(side="left", padx=10)

        self.stop_btn = ttk.Button(btn_frame, text="⏹ Stop", command=self.stop_scan, state="disabled", width=10)
        self.stop_btn.pack(side="left", padx=10)

        self.export_btn = ttk.Button(btn_frame, text="💾 Export CSV", command=self.export_csv, state="disabled",
                                     width=15)
        self.export_btn.pack(side="left", padx=10)

        # --- DATA TABLE (TREEVIEW) ---
        table_frame = ttk.Frame(self.root, padding=(25, 10))
        table_frame.pack(fill="both", expand=True)

        tree_scroll = ttk.Scrollbar(table_frame)
        tree_scroll.pack(side="right", fill="y")

        self.tree = ttk.Treeview(table_frame, columns=("Port", "Status", "Service"), show="headings",
                                 yscrollcommand=tree_scroll.set)
        self.tree.heading("Port", text="Port Number", anchor="w")
        self.tree.heading("Status", text="Status", anchor="w")
        self.tree.heading("Service", text="Service Protocol", anchor="w")

        self.tree.column("Port", width=150, anchor="w")
        self.tree.column("Status", width=150, anchor="w")
        self.tree.column("Service", width=450, anchor="w")

        # Add visual tag for OPEN status
        self.tree.tag_configure('open_port', foreground='#16a34a', font=("Segoe UI", 10, "bold"))

        self.tree.pack(fill="both", expand=True)
        tree_scroll.config(command=self.tree.yview)

        # --- STATUS BAR ---
        status_frame = ttk.Frame(self.root, padding=(25, 10, 25, 15))
        status_frame.pack(fill="x", side="bottom")

        self.status_var = tk.StringVar()
        self.status_var.set("Ready to scan.")
        ttk.Label(status_frame, textvariable=self.status_var, font=("Segoe UI", 10, "bold"), foreground="#475569").pack(
            side="left")

        self.progress = ttk.Progressbar(status_frame, orient="horizontal", mode="determinate", length=350)
        self.progress.pack(side="right", fill="x", expand=True, padx=(30, 0))

    def on_profile_change(self, event=None):
        """Automatically sets ports based on selected profile and locks inputs"""
        profile = self.profile_var.get()

        self.start_port.config(state="normal")
        self.end_port.config(state="normal")
        self.start_port.delete(0, tk.END)
        self.end_port.delete(0, tk.END)

        if "1-1024" in profile:
            self.start_port.insert(0, "1")
            self.end_port.insert(0, "1024")
            self.start_port.config(state="disabled")
            self.end_port.config(state="disabled")
        elif "1024-49151" in profile:
            self.start_port.insert(0, "1024")
            self.end_port.insert(0, "49151")
            self.start_port.config(state="disabled")
            self.end_port.config(state="disabled")
        elif "1-65535" in profile:
            self.start_port.insert(0, "1")
            self.end_port.insert(0, "65535")
            self.start_port.config(state="disabled")
            self.end_port.config(state="disabled")
        # If "Custom Range", leave them normal and blank

    def update_table(self, port, status, service):
        """Thread-safe update to the Treeview data table"""
        self.root.after(0, self._insert_row, port, status, service)

    def _insert_row(self, port, status, service):
        self.tree.insert("", tk.END, values=(port, status, service), tags=('open_port',))
        self.discovered_ports.append((port, status, service))

    def update_progress(self):
        """Thread-safe update for progress bar and status text"""
        if self.total_ports > 0:
            percent = (self.scanned_ports / self.total_ports) * 100
            self.root.after(0, self._set_progress, percent)

    def _set_progress(self, percent):
        self.progress["value"] = percent
        self.status_var.set(
            f"Scanning in progress... {percent:.1f}%  |  Open Ports Found: {len(self.discovered_ports)}")

    def scan_port(self, target_ip, port):
        if not self.is_scanning:
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                if sock.connect_ex((target_ip, port)) == 0:
                    try:
                        service = socket.getservbyport(port, 'tcp').upper()
                    except OSError:
                        service = "Unknown"
                    self.update_table(port, "OPEN", service)
        except Exception:
            pass
        finally:
            self.scanned_ports += 1
            if self.scanned_ports % 10 == 0:  # Update UI smoothly
                self.update_progress()

    def start_scan(self):
        target = self.target_entry.get().strip()
        try:
            start_p = int(self.start_port.get())
            end_p = int(self.end_port.get())
            thread_count = int(self.threads_entry.get())
        except ValueError:
            messagebox.showerror("Input Error", "Please ensure Start Port, End Port, and Threads are valid numbers.")
            return

        # UI Reset
        self.tree.delete(*self.tree.get_children())
        self.discovered_ports.clear()
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.export_btn.config(state="disabled")
        self.progress["value"] = 0

        self.is_scanning = True
        self.total_ports = (end_p - start_p) + 1
        self.scanned_ports = 0

        # Run engine in background
        threading.Thread(target=self.scan_engine, args=(target, start_p, end_p, thread_count), daemon=True).start()

    def stop_scan(self):
        self.is_scanning = False
        self.status_var.set("Scan aborted by user.")

    def scan_engine(self, target, start_p, end_p, thread_count):
        self.root.after(0, lambda: self.status_var.set(f"Resolving IP for {target}..."))
        start_time = datetime.now()

        try:
            target_ip = socket.gethostbyname(target)

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                for port in range(start_p, end_p + 1):
                    if not self.is_scanning:
                        break
                    executor.submit(self.scan_port, target_ip, port)

        except socket.gaierror:
            self.root.after(0, lambda: messagebox.showerror("Network Error", f"Could not resolve host: {target}"))
            self.is_scanning = False

        # Scan Finished Cleanup
        if self.is_scanning:  # Only show complete if not stopped manually
            duration = (datetime.now() - start_time).total_seconds()
            self.root.after(0, lambda: self._scan_finished_ui(duration))
        else:
            self.root.after(0, lambda: self._scan_stopped_ui())

    def _scan_finished_ui(self, duration):
        self.progress["value"] = 100
        self.status_var.set(f"Scan complete in {duration:.2f}s  |  Total Open Ports: {len(self.discovered_ports)}")
        self._reset_buttons()

    def _scan_stopped_ui(self):
        self._reset_buttons()

    def _reset_buttons(self):
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if self.discovered_ports:
            self.export_btn.config(state="normal")

    def export_csv(self):
        if not self.discovered_ports:
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Export Scan Results"
        )

        if filepath:
            try:
                with open(filepath, mode='w', newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    writer.writerow(["Port", "Status", "Service Protocol"])
                    writer.writerows(self.discovered_ports)
                messagebox.showinfo("Export Successful", f"Results successfully saved to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save file:\n{e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetHawkEnterprise(root)
    root.mainloop()
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
import threading
from scanner import PortScanner


class FastScanGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("FastScan Pro")
        self.root.geometry("800x600")

        # ==== TOP FRAME ====
        top_frame = ttk.Frame(root, padding=10)
        top_frame.pack(fill=X)

        ttk.Label(top_frame, text="Target IP").grid(row=0, column=0, padx=5)
        self.target_entry = ttk.Entry(top_frame, width=15)
        self.target_entry.grid(row=0, column=1)

        ttk.Label(top_frame, text="Start Port").grid(row=0, column=2, padx=5)
        self.start_entry = ttk.Entry(top_frame, width=8)
        self.start_entry.grid(row=0, column=3)

        ttk.Label(top_frame, text="End Port").grid(row=0, column=4, padx=5)
        self.end_entry = ttk.Entry(top_frame, width=8)
        self.end_entry.grid(row=0, column=5)

        ttk.Label(top_frame, text="Threads").grid(row=0, column=6, padx=5)
        self.thread_entry = ttk.Entry(top_frame, width=5)
        self.thread_entry.insert(0, "200")
        self.thread_entry.grid(row=0, column=7)

        self.scan_type = ttk.Combobox(top_frame, values=["TCP"], width=8)
        self.scan_type.current(0)
        self.scan_type.grid(row=0, column=8, padx=10)

        ttk.Button(top_frame, text="Scan", bootstyle=SUCCESS, command=self.start_scan)\
            .grid(row=0, column=9, padx=5)

        # ==== PROGRESS BAR ====
        self.progress = ttk.Progressbar(root, bootstyle=INFO, mode='determinate')
        self.progress.pack(fill=X, padx=10, pady=5)

        # ==== OUTPUT AREA ====
        self.output = ScrolledText(root, height=25)
        self.output.pack(fill=BOTH, expand=True, padx=10, pady=10)

    def start_scan(self):
        thread = threading.Thread(target=self.run_scan)
        thread.start()

    def run_scan(self):
        target = self.target_entry.get().strip()
        start = self.start_entry.get().strip()
        end = self.end_entry.get().strip()
        threads = self.thread_entry.get().strip()

        if not target or not start or not end:
            messagebox.showerror("Input Error", "All fields required")
            return

        if not start.isdigit() or not end.isdigit() or not threads.isdigit():
            messagebox.showerror("Input Error", "Ports and threads must be numbers")
            return

        start = int(start)
        end = int(end)
        threads = int(threads)

        if start < 1 or end > 65535 or start > end:
            messagebox.showerror("Input Error", "Invalid port range")
            return

        self.output.delete("1.0", "end")
        self.progress["value"] = 0
        total_ports = end - start + 1

        scanner = PortScanner(target, start, end, threads)

        results = []

        def update_progress(port_count):
            progress_percent = (port_count / total_ports) * 100
            self.progress["value"] = progress_percent

        for count, result in enumerate(scanner.run_live()):
            update_progress(count + 1)

            if result:
                results.append(result)
                risk = self.get_risk_level(result["port"])

                self.output.insert("end",
                    f"[OPEN] Port {result['port']} | Risk: {risk}\n")

                if risk == "HIGH":
                    self.output.tag_add("high", "end-2l", "end-1l")
                    self.output.tag_config("high", foreground="red")

        self.progress["value"] = 100
        messagebox.showinfo("Complete", "Scan Finished")

    def get_risk_level(self, port):
        high_risk = [21, 22, 23, 445, 3389]
        if port in high_risk:
            return "HIGH"
        return "LOW"


if __name__ == "__main__":
    app = ttk.Window(themename="darkly")
    FastScanGUI(app)
    app.mainloop()

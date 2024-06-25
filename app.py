import psutil
import tkinter as tk
from tkinter import ttk, font
import customtkinter as ctk
import os
import json

class Window:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Software")
        self.root.geometry("1280x720")

        # Dictionary to keep track of sort order for each column
        self.sort_reverse = {} 
        # Variable to track the state of the checkbox
        self.hide_trusted = tk.BooleanVar()
        self.trusted_paths_file = "trusted_paths.json"
        self.system_paths = self.get_windows_system_paths()
        self.trusted_paths = self.load_trusted_paths() + self.system_paths

        self.setup_ui()
        self.populate_connections()
        self.auto_refresh()

    def setup_ui(self):
        top_frame = tk.Frame(self.root)
        top_frame.pack(fill=tk.X)

        self.label = tk.Label(top_frame, text="Total Connections: 0 | TCP: 0 | UDP: 0", font=('Roboto', 12))
        self.label.pack(side=tk.LEFT, padx=10, pady=10)

        refresh_button = ctk.CTkButton(top_frame, text="Refresh", command=self.populate_connections, font=('Roboto', 14))
        refresh_button.pack(side=tk.RIGHT, padx=10, pady=10)

        configure_button = ctk.CTkButton(top_frame, text="Configure", command=self.configure_dialog, font=('Roboto', 14))
        configure_button.pack(side=tk.RIGHT, padx=10, pady=10)

        hide_checkbox = ctk.CTkCheckBox(top_frame, text="Hide Trusted Connections", text_color="black", variable=self.hide_trusted, command=self.update_hide_trusted, font=('Roboto', 14))
        hide_checkbox.pack(side=tk.RIGHT, padx=10, pady=10)

        frame = tk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(frame, columns=("Process Name", "PID", "Path", "Local Address", "Remote Address", "Status", "Type"), show='headings')
        self.tree.heading("Process Name", text="Process Name", command=lambda: self.sort_column("Process Name"))
        self.tree.heading("PID", text="PID", command=lambda: self.sort_column("PID"))
        self.tree.heading("Path", text="Path", command=lambda: self.sort_column("Path"))
        self.tree.heading("Local Address", text="Local Address", command=lambda: self.sort_column("Local Address"))
        self.tree.heading("Remote Address", text="Remote Address", command=lambda: self.sort_column("Remote Address"))
        self.tree.heading("Status", text="Status", command=lambda: self.sort_column("Status"))
        self.tree.heading("Type", text="Type", command=lambda: self.sort_column("Type"))

        self.tree.column("Process Name", width=150)
        self.tree.column("PID", width=50)
        self.tree.column("Path", width=250)
        self.tree.column("Local Address", width=150)
        self.tree.column("Remote Address", width=150)
        self.tree.column("Status", width=100)
        self.tree.column("Type", width=50)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=vsb.set)

        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.configure(xscrollcommand=hsb.set)

        self.tree.pack(fill=tk.BOTH, expand=True)

    def get_windows_system_paths(self):
        system_paths = [
            os.path.join(os.getenv('SystemRoot', 'C:\\Windows'), 'System32'),
            os.path.join(os.getenv('SystemRoot', 'C:\\Windows'), 'SysWOW64'),
        ]
        return system_paths

    def load_trusted_paths(self):
        if os.path.exists(self.trusted_paths_file):
            with open(self.trusted_paths_file, 'r') as file:
                return [path for path in json.load(file).get('trusted_paths', []) if path]
        return []

    def save_trusted_paths(self, paths):
        with open(self.trusted_paths_file, 'w') as file:
            json.dump({'trusted_paths': paths}, file)

    def is_trusted_process(self, process):
        try:
            process_path = process.exe()
            if not process_path:
                return True
            for trusted_path in self.trusted_paths + self.system_paths:
                if trusted_path and process_path.startswith(trusted_path):
                    return True
            return False
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def get_active_connections(self):
        tcp_connections = psutil.net_connections(kind='tcp')
        udp_connections = psutil.net_connections(kind='udp')
        return tcp_connections, udp_connections

    def populate_connections(self):
        # Clear existing connections
        for item in self.tree.get_children():
            self.tree.delete(item)

        tcp_conns, udp_conns = self.get_active_connections()
        total_conns = len(tcp_conns) + len(udp_conns)

        # Update the label with connection counts
        self.label.config(text=f"Total Connections: {total_conns} | TCP: {len(tcp_conns)} | UDP: {len(udp_conns)}")

        for conn in tcp_conns:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            pid = conn.pid if conn.pid else "N/A"
            ctype = "TCP"
            try:
                process = psutil.Process(conn.pid)
                pname = process.name()
                ppath = process.exe()
                if self.hide_trusted.get() and (self.is_trusted_process(process) or not raddr):
                    continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "N/A"
                ppath = "N/A"

            self.tree.insert("", "end", values=(pname, pid, ppath, laddr, raddr, conn.status, ctype))

        for conn in udp_conns:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            pid = conn.pid if conn.pid else "N/A"
            ctype = "UDP"
            try:
                process = psutil.Process(conn.pid)
                pname = process.name()
                ppath = process.exe()
                if self.hide_trusted.get() and (self.is_trusted_process(process) or not raddr):
                    continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "N/A"
                ppath = "N/A"

            self.tree.insert("", "end", values=(pname, pid, ppath, laddr, raddr, conn.status, ctype))

    def sort_column(self, col):
        # Gets the current sorting order for this column
        reverse = self.sort_reverse.get(col, False)
        
        # Gets the data to be sorted
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children('')]
        
        # Sorts the data based on the current order
        data.sort(reverse=reverse)

        # Rearranges the items in the treeview
        for index, (val, child) in enumerate(data):
            self.tree.move(child, '', index)
        
        # Toggles the sort order for next time
        self.sort_reverse[col] = not reverse

        # Updates the column header to indicate sort direction (optional)
        self.tree.heading(col, command=lambda: self.sort_column(col))

    def update_hide_trusted(self):
        # Re-populates connections with the updated hide_trusted state
        self.populate_connections()

    def auto_refresh(self):
        self.populate_connections()
        self.root.after(5000, self.auto_refresh)

    def configure_dialog(self):
        dialog = ctk.CTkToplevel(self.root)
        dialog.configure(bg="#FFFFFF")
        dialog.title("Configuration")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Settings Options", font=('Roboto', 12), bg="#FFFFFF").pack(pady=10)

        tk.Label(dialog, text="Trusted Paths:", font=('Roboto', 10), bg="#FFFFFF").pack(pady=5)
        tk.Label(dialog, text="(For example C:\\Program Files\\Spotify)", font=('Roboto', 8), bg="#FFFFFF").pack(pady=5)

        self.trusted_paths_entry = tk.Text(dialog, height=5, width=40, bg="#F0F0F0", fg="black")
        self.trusted_paths_entry.pack(pady=5)
        self.trusted_paths_entry.insert(tk.END, "\n".join(self.load_trusted_paths()))

        save_button = ctk.CTkButton(dialog, text="Save", command=self.save_trusted_paths)
        save_button.pack(pady=10)

    def save_trusted_paths(self):
        paths = self.trusted_paths_entry.get("1.0", tk.END).strip().split("\n")
        paths = [path for path in paths if path]  # Filter out empty strings
        self.save_trusted_paths(paths)
        self.trusted_paths = paths + self.system_paths
        self.update_hide_trusted()

if __name__ == "__main__":
    ctk.set_default_color_theme("green")
    ctk.set_appearance_mode("light")
    root = ctk.CTk()
    app = Window(root)

    root.mainloop()

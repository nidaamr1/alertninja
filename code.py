
"""
GUI Network Scanner for Kali Linux
"""
import tkinter as tk
import nmap
from tkinter import ttk, messagebox

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AlertNinja")
        self.root.geometry("800x600")
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('classic')
        
        self.create_widgets()
        
    def create_widgets(self):
        # Header Frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(header_frame, text="Network & Vulnerability Scanner", 
                 font=('Helvetica', 16, 'bold')).pack()
        
        # Input Frame
        input_frame = ttk.LabelFrame(self.root, text="Scan Parameters")
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Target IP/Network:").grid(row=0, column=0, padx=5, pady=5)
        self.target_entry = ttk.Entry(input_frame, width=40)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Scan Type:").grid(row=1, column=0, padx=5, pady=5)
        self.scan_type = ttk.Combobox(input_frame, 
                                     values=["Ping Scan", "Quick Scan", 
                                             "Full Port Scan", "Vulnerability Scan"],
                                     state="readonly")
        self.scan_type.grid(row=1, column=1, padx=5, pady=5)
        self.scan_type.current(0)
        
        # Button Frame
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)
        
        self.scan_btn = ttk.Button(button_frame, text="Start Scan", command=self.run_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Results Frame
        results_frame = ttk.LabelFrame(self.root, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.results_text = tk.Text(results_frame, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status Bar
        self.status = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status.pack(fill=tk.X, padx=10, pady=5)
    
    def run_scan(self):
        target = self.target_entry.get()
        scan_type = self.scan_type.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or network")
            return
            
        self.status.config(text=f"Running {scan_type} on {target}...")
        self.root.update()
        
        try:
            nm = nmap.PortScanner()
            
            if scan_type == "Ping Scan":
                nm.scan(hosts=target, arguments='-sn')
            elif scan_type == "Quick Scan":
                nm.scan(hosts=target, arguments='-T4 -F')
            elif scan_type == "Full Port Scan":
                nm.scan(hosts=target, arguments='-p 1-65535 -T4')
            elif scan_type == "Vulnerability Scan":
                nm.scan(hosts=target, arguments='-sV --script vulners')
                
            self.display_results(nm)
            self.status.config(text=f"Scan completed for {target}")
            
        except Exception as e:
            messagebox.showerror("Scan Error", str(e))
            self.status.config(text="Scan failed")
    
    def display_results(self, scanner):
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Scan Results:\n\n")
        
        for host in scanner.all_hosts():
            self.results_text.insert(tk.END, f"Host: {host} ({scanner[host].hostname()})\n")
            self.results_text.insert(tk.END, f"State: {scanner[host].state()}\n")
            
            for proto in scanner[host].all_protocols():
                self.results_text.insert(tk.END, f"\nProtocol: {proto}\n")
                
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    self.results_text.insert(tk.END, 
                        f"Port: {port}\tState: {scanner[host][proto][port]['state']}\n")
    
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.status.config(text="Ready")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()


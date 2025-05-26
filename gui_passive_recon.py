import socket
import whois
import requests
import csv
import re
import tkinter as tk
from tkinter import messagebox, filedialog
from bs4 import BeautifulSoup

# ==== OSINT Functions ====

def passive_dns_lookup(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "DNS resolution failed"

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return {
            "Registrar": w.registrar,
            "Creation Date": str(w.creation_date),
            "Expiration Date": str(w.expiration_date),
            "Name Servers": ", ".join(w.name_servers) if w.name_servers else "None"
        }
    except Exception as e:
        return {"Whois Error": str(e)}

def web_scrape_data(domain):
    try:
        url = f"http://{domain}"
        headers = {'User-Agent': 'Mozilla/5.0'}
        res = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')

        title = soup.title.string.strip() if soup.title else "No Title"
        meta_desc = soup.find("meta", attrs={"name": "description"})
        meta_keywords = soup.find("meta", attrs={"name": "keywords"})
        description = meta_desc["content"].strip() if meta_desc and meta_desc.get("content") else "None"
        keywords = meta_keywords["content"].strip() if meta_keywords and meta_keywords.get("content") else "None"

        text = soup.get_text()
        
        headings = []
        for tag in ['h1', 'h2', 'h3']:
            headings.extend([h.get_text(strip=True) for h in soup.find_all(tag)])
            heading_preview = headings[:5] if headings else ["None"]

        emails = list(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)))
        phones = list(set(re.findall(r"\+?\d[\d\s\-]{7,15}", text)))

        return {
            "Page Title": title,
            "Meta Description": description,
            "Meta Keywords": keywords,
            "Top Headings (H1-H3)": "; ".join(heading_preview),
            "Emails Found": ", ".join(emails) if emails else "None",
            "Phones Found": ", ".join(phones) if phones else "None",
        }
    except Exception as e:
        return {"Scrape Error": str(e)}

# ==== GUI Functions ====

def run_scan():
    domain = entry_target.get().strip()
    if not domain:
        messagebox.showwarning("Missing Input", "Please enter a domain or target.")
        return

    text_output.delete("1.0", tk.END)
    output = {"Domain": domain}
    ip = passive_dns_lookup(domain)
    output["IP Address"] = ip

    whois_data = whois_lookup(domain)
    output.update(whois_data)

    scrape_data = web_scrape_data(domain)
    output.update(scrape_data)

    for k, v in output.items():
        text_output.insert(tk.END, f"{k}: {v}\n")

    global final_result
    final_result = output

def save_to_csv():
    if not final_result:
        messagebox.showwarning("No Data", "Please scan a target first.")
        return

    filepath = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV files", "*.csv")])
    if filepath:
        try:
            with open(filepath, "w", newline='', encoding="utf-8") as f:
                writer = csv.writer(f)
                for key, value in final_result.items():
                    writer.writerow([key, value])
            messagebox.showinfo("Success", "Results saved to CSV.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

# ==== GUI Layout ====

final_result = {}
root = tk.Tk()
root.title("OSINT Recon Tool (Simple)")
root.geometry("650x550")

tk.Label(root, text="Enter Domain or Target:", font=("Arial", 12)).pack(pady=5)
entry_target = tk.Entry(root, font=("Arial", 12), width=40)
entry_target.pack(pady=5)

tk.Button(root, text="Run OSINT Scan", command=run_scan, bg="green", fg="white", font=("Arial", 12)).pack(pady=10)

text_output = tk.Text(root, wrap="word", height=20, width=80, font=("Courier", 10))
text_output.pack(pady=10)

tk.Button(root, text="Save as CSV", command=save_to_csv, bg="blue", fg="white", font=("Arial", 12)).pack(pady=5)

tk.Label(root, text="Ochemic OSINT Tool | DNS, WHOIS, Email/Phone Scraping", font=("Arial", 10)).pack(pady=5)

root.mainloop()

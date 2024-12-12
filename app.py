from flask import Flask, render_template, request, send_file, jsonify
from PyPDF2 import PdfReader
from fpdf import FPDF
from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
import os
import unicodedata
import threading
import tempfile

# Initialize Flask app
app = Flask(__name__)

# Load LLM model and tokenizer
model_name = "gpt2"
tokenizer = AutoTokenizer.from_pretrained(model_name)
tokenizer.pad_token = tokenizer.eos_token
model = AutoModelForCausalLM.from_pretrained(model_name)
generator = pipeline("text-generation", model=model, tokenizer=tokenizer, device=-1)

# Path to save temporary PDFs
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Extract URLs from PDF
def extract_urls_from_pdf(pdf_path):
    """Extract crawling URLs from the PDF."""
    urls = []
    reader = PdfReader(pdf_path)
    for page in reader.pages:
        text = page.extract_text()
        if "Crawling Information" in text:
            lines = text.split("\n")
            start_index = lines.index("Crawling Information") + 1
            for line in lines[start_index:]:
                if line.startswith("http://") or line.startswith("https://"):
                    urls.append(line.strip())
    return urls

# Sanitize text
def sanitize_text(text):
    """Replace unsupported characters with closest equivalents."""
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")

# Write response to PDF
def write_response_to_pdf(response, output_pdf_path):
    """Save the sanitized response to a new PDF."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    sanitized_response = sanitize_text(response)
    pdf.multi_cell(0, 10, sanitized_response)
    pdf.output(output_pdf_path)

# Process with LLM
def process_with_llm(selected_url, output_pdf_path, callback):
    """Run LLM processing in a separate thread."""
    try:
        prompt = (
            f"Analyze the URL {selected_url} for malware type, attack vectors, system vulnerabilities, mitigation strategies, incident response, and long-term security best practices, providing a comprehensive security assessment report with technical depth and real-world example. Also, give the mitigation steps in points in the end."
        )
        responses = generator(prompt, max_length=1000, truncation=True, num_return_sequences=1)
        response_text = responses[0]["generated_text"].strip()
        write_response_to_pdf(response_text, output_pdf_path)
        callback(output_pdf_path)
    except Exception as e:
        callback(str(e))

# Flask route to render the homepage
@app.route('/')
def index():
    return render_template('index.html')

# Flask route to handle PDF upload and URL extraction
@app.route('/upload', methods=['POST'])
def upload_pdf():
    file = request.files['file']
    if not file:
        return jsonify({"error": "No file uploaded!"}), 400

    # Save the uploaded PDF file
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(pdf_path)

    # Extract URLs from PDF
    try:
        urls = extract_urls_from_pdf(pdf_path)
        if not urls:
            return jsonify({"error": "No URLs found in the PDF!"}), 400
        return jsonify({"urls": urls})
    except Exception as e:
        return jsonify({"error": f"Error processing PDF: {str(e)}"}), 500

# Flask route to process selected URL
@app.route('/process', methods=['POST'])
def process_url():
    selected_url = request.form.get('url')
    if not selected_url:
        return jsonify({"error": "No URL selected!"}), 400

    # Create a temporary PDF file to save the response
    output_pdf = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf', dir=UPLOAD_FOLDER)
    output_pdf_path = output_pdf.name

    def callback(result):
        if result.endswith('.pdf'):
            return send_file(result, as_attachment=True)
        else:
            return jsonify({"error": result}), 500

    threading.Thread(target=process_with_llm, args=(selected_url, output_pdf_path, callback)).start()

    return jsonify({"message": "Processing started, please wait..."})

if __name__ == '__main__':
    app.run(debug=True)

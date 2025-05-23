﻿# Steganography Tool

This is a simple LSB (Least Significant Bit) steganography tool for encoding and decoding secret messages inside images. It supports both a **command-line interface** and a **Flask-based web interface**.

---

## 🔧 Features

- Embed (encode) text messages inside images (.png, .bmp)
- Extract (decode) hidden messages from images
- Optional password-based encryption (XOR + SHA-256 hash)
- Flask web interface for uploading, encoding, and decoding via browser
- End-of-message marker for precise extraction
- Only supports lossless image formats to avoid data loss

---

## 📁 Project Structure

```
steganography_tool/
│
├── static/
│   ├── index.html           
│
├── app.py                
├── stego_core.py          
└── README.md                
```

---

## 🚀 How to Run

### 1. Install Dependencies

```bash
pip install pillow flask numpy
```

### 2. Run the Flask App

```bash
python app.py
```

Then visit `http://127.0.0.1:5000` in your browser.

---

## ✅ Supported Image Formats

- PNG ✅
- BMP ✅
- JPEG ❌ (Not supported — causes data loss)

Always use **lossless formats** like `.png` to prevent corruption of hidden data.

---

## 🔒 Encryption (Optional)

- XOR encryption using a **SHA-256 hash** of the provided password
- Adds a layer of security to hidden messages

---

## 📤 Output

- Encoded image with hidden data saved as a new PNG
- Extracted message shown on console or webpage

---

## 💡 Notes

- Do **not** use `.jpg` or `.jpeg` — they compress data and destroy hidden messages
- The tool uses a binary end marker (`00000000`) to terminate extraction
- Best used for short, text-only messages


import os
from flask import Flask, request, jsonify, send_from_directory
from PIL import Image
import numpy as np
import hashlib
import io
import base64
import re

# Create Flask app
app = Flask(__name__, static_folder='static')

# Constants
END_MARKER = '00000000'  # Binary marker indicating the end of the hidden message

# Steganography core functions
def hash_password(password: str) -> str:
    """Generate a SHA-256 binary hash from the password."""
    return ''.join(format(byte, '08b') for byte in hashlib.sha256(password.encode()).digest())


def xor_data(data: str, key: str) -> str:
    """XOR the binary data using the given key."""
    key_cycle = (key * ((len(data) // len(key)) + 1))[:len(data)]
    return ''.join(str(int(b) ^ int(k)) for b, k in zip(data, key_cycle))


def message_to_binary(message: str, password: str = None) -> str:
    """Convert message to binary string, optionally encrypting it."""
    binary = ''.join(format(ord(char), '08b') for char in message)
    if password:
        binary = xor_data(binary, hash_password(password))
    return binary + END_MARKER


def binary_to_message(binary: str, password: str = None) -> str:
    """Convert binary string back to a readable message, with optional decryption."""
    if password:
        binary = xor_data(binary, hash_password(password))

    chars = []
    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]
        if byte == END_MARKER:
            break
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)


def embed_message(image_data, message: str, password: str = None):
    """Embed a secret message inside an image using LSB steganography."""
    # Convert data URL to image
    image_data = re.sub('^data:image/.+;base64,', '', image_data)
    image_bytes = base64.b64decode(image_data)
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    
    pixels = np.array(image)
    height, width, _ = pixels.shape
    flat_pixels = pixels.reshape(-1, 3)

    binary_message = message_to_binary(message, password)
    total_bits = len(binary_message)

    if total_bits > len(flat_pixels) * 3:
        raise ValueError("Message too large to fit in the selected image.")

    bit_idx = 0
    for i in range(len(flat_pixels)):
        for j in range(3):
            if bit_idx < total_bits:
                flat_pixels[i][j] = (flat_pixels[i][j] & 0xFE) | int(binary_message[bit_idx])
                bit_idx += 1

    stego_pixels = flat_pixels.reshape((height, width, 3))
    stego_image = Image.fromarray(stego_pixels.astype(np.uint8))

    # Save the image to a bytes buffer
    buffer = io.BytesIO()
    stego_image.save(buffer, format="PNG")
    
    # Convert to base64 for return
    img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{img_str}"


def extract_message(image_data, password: str = None) -> str:
    """Extract a hidden message from an image."""
    # Convert data URL to image
    image_data = re.sub('^data:image/.+;base64,', '', image_data)
    image_bytes = base64.b64decode(image_data)
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    
    pixels = np.array(image)
    flat_pixels = pixels.reshape(-1, 3)

    binary_data = ''
    for pixel in flat_pixels:
        for color in pixel:
            binary_data += str(color & 1)
            
            # Check if we've reached the end marker
            if len(binary_data) >= 8 and binary_data[-8:] == END_MARKER:
                # Remove the end marker
                binary_data = binary_data[:-8]
                return binary_to_message(binary_data, password)
    
    # If we get here, no end marker was found
    raise ValueError("No hidden message found or incorrect password.")


# Routes
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/api/encode', methods=['POST'])
def encode():
    try:
        data = request.json
        image_data = data.get('image')
        message = data.get('message')
        password = data.get('password')
        
        if not image_data or not message:
            return jsonify({'error': 'Missing image or message'}), 400
        
        result_image = embed_message(image_data, message, password if password else None)
        return jsonify({'image': result_image})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/decode', methods=['POST'])
def decode():
    try:
        data = request.json
        image_data = data.get('image')
        password = data.get('password')
        
        if not image_data:
            return jsonify({'error': 'Missing image'}), 400
        
        message = extract_message(image_data, password if password else None)
        return jsonify({'message': message})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Command-line interface for direct use
def cli_interface():
    """Command-line interface for steganography tool."""
    print("\n🔐 PixelCrypt - Advanced LSB Steganography Tool\n")
    choice = input("Choose an option (encode / decode): ").strip().lower()

    try:
        if choice == "encode":
            input_image = input("📁 Enter image path: ").strip()
            output_image = input("💾 Output image name: ").strip()
            secret_message = input("✉️  Enter message to hide: ").strip()
            password = input("🔑 Optional password (leave blank for none): ").strip() or None

            # Load image
            if not os.path.exists(input_image):
                raise FileNotFoundError("❌ Input image not found.")
                
            with open(input_image, "rb") as f:
                img_bytes = f.read()
                
            img_base64 = base64.b64encode(img_bytes).decode('utf-8')
            img_data_url = f"data:image/png;base64,{img_base64}"
            
            # Embed message
            result_image = embed_message(img_data_url, secret_message, password)
            
            # Save result
            if not output_image.lower().endswith(('.png', '.bmp')):
                output_image += ".png"  # Always save in lossless format
                print("ℹ️ Saving as PNG to prevent data loss.")
                
            # Extract the base64 image data
            img_data = re.sub('^data:image/.+;base64,', '', result_image)
            img_bytes = base64.b64decode(img_data)
            
            with open(output_image, "wb") as f:
                f.write(img_bytes)
                
            print(f"✅ Message successfully embedded in '{output_image}'.")

        elif choice == "decode":
            stego_image = input("📁 Enter stego image path: ").strip()
            password = input("🔑 Password (if used during encoding): ").strip() or None

            # Load image
            if not os.path.exists(stego_image):
                raise FileNotFoundError("❌ Stego image not found.")
                
            with open(stego_image, "rb") as f:
                img_bytes = f.read()
                
            img_base64 = base64.b64encode(img_bytes).decode('utf-8')
            img_data_url = f"data:image/png;base64,{img_base64}"
            
            # Extract message
            message = extract_message(img_data_url, password)
            print(f"\n🕵️ Hidden Message:\n{message}\n")

        else:
            print("❗ Invalid option. Please choose 'encode' or 'decode'.")

    except Exception as e:
        print(f"⚠️ Error: {e}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        cli_interface()
    else:
        # Ensure static folder exists
        os.makedirs('static', exist_ok=True)
        
        # Check if index.html exists, if not, create a simple placeholder
        if not os.path.exists(os.path.join('static', 'index.html')):
            print("⚠️ Warning: index.html not found in static folder. Please place the HTML interface there.")
            with open(os.path.join('static', 'index.html'), 'w') as f:
                f.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>PixelCrypt - Please add the full interface</title>
                </head>
                <body>
                    <h1>Missing Interface</h1>
                    <p>Please add the complete PixelCrypt interface HTML to this file.</p>
                </body>
                </html>
                """)
        
        # Run the Flask app
        print("🚀 Starting PixelCrypt web server...")
        app.run(debug=True)
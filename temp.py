from PIL import Image
import os

class Stegno:

    @staticmethod
    def gen_data(data):
        """Generate binary data from the input string."""
        return [format(ord(i), '08b') for i in data]

    @staticmethod
    def mod_pix(pix, data):
        """Modify pixel values to encode binary data."""
        data_list = Stegno.gen_data(data)
        data_len = len(data_list)
        img_data = iter(pix)

        for i in range(data_len):
            pix = [value for value in next(img_data)[:3] +
                   next(img_data)[:3] +
                   next(img_data)[:3]]
            for j in range(8):
                if (data_list[i][j] == '0' and pix[j] % 2 != 0):
                    pix[j] -= 1
                elif (data_list[i][j] == '1' and pix[j] % 2 == 0):
                    pix[j] -= 1

            if i == data_len - 1:
                if pix[-1] % 2 == 0:
                    pix[-1] -= 1
            else:
                if pix[-1] % 2 != 0:
                    pix[-1] -= 1

            yield tuple(pix[:3])
            yield tuple(pix[3:6])
            yield tuple(pix[6:9])

    @staticmethod
    def encode(image_path, output_path, secret_data):
        """Encode a secret message into an image."""
        if not secret_data:
            raise ValueError("Data is empty")

        image = Image.open(image_path)
        
        # Ensure the image is in RGB mode
        if image.mode != "RGB":
            image = image.convert("RGB")
        
        new_img = image.copy()
        width, height = new_img.size
        pixels = new_img.getdata()

        new_pixels = []
        for modified_pixel in Stegno.mod_pix(pixels, secret_data):
            new_pixels.append(modified_pixel)

        new_img.putdata(new_pixels)
        new_img.save(output_path, str(output_path.split(".")[1].upper()))
        print("Data encoded and saved successfully!")


    @staticmethod
    def decode(image_path):
        """Decode the secret message from an image."""
        image = Image.open(image_path)
        pixels = iter(image.getdata())
        binary_data = ""

        while True:
            pixels_values = [value for value in next(pixels)[:3] +
                             next(pixels)[:3] +
                             next(pixels)[:3]]
            binary_data += ''.join(['0' if value % 2 == 0 else '1' for value in pixels_values[:8]])
            if pixels_values[-1] % 2 != 0:
                break

        decoded_data = ""
        for i in range(0, len(binary_data), 8):
            char = chr(int(binary_data[i:i + 8], 2))
            decoded_data += char
        return decoded_data

# Example Usage:
if __name__ == "__main__":
    stegno = Stegno()
    mode = input("Enter 'encode' to hide a message or 'decode' to reveal a message: ").strip().lower()

    if mode == "encode":
        image_path = input("Enter the path to the image: ").strip()
        output_path = input("Enter the output path for the encoded image: ").strip()
        secret_data = input("Enter the secret message to encode: ").strip()
        stegno.encode(image_path, output_path, secret_data)
    elif mode == "decode":
        image_path = input("Enter the path to the image to decode: ").strip()
        hidden_message = stegno.decode(image_path)
        print("Hidden Message:", hidden_message)
    else:
        print("Invalid option. Please choose 'encode' or 'decode'.")

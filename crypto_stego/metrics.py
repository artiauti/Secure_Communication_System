"""
Image Quality and Steganalysis Metrics
--------------------------------------
Calculates Peak Signal-to-Noise Ratio (PSNR), Mean Squared Error (MSE),
Bit Error Rate (BER), and generates amplified visual difference maps
to evaluate the imperceptibility of the steganographic embedding.
"""

import math
from typing import Dict, Any, Tuple
from PIL import Image, ImageChops


def calculate_mse(cover_img: Image.Image, stego_img: Image.Image) -> float:
    """
    Calculate the Mean Squared Error (MSE) between cover and stego images.
    MSE = (1 / (3 * M * N)) * sum((Cover - Stego)^2)
    """
    c_img = cover_img.convert("RGB")
    s_img = stego_img.convert("RGB")

    if c_img.size != s_img.size:
        raise ValueError(
            f"Images have different dimensions: {c_img.size} vs {s_img.size}"
        )

    c_bytes = c_img.tobytes()
    s_bytes = s_img.tobytes()

    total_samples = len(c_bytes)
    if total_samples == 0:
        return 0.0

    total_sq_diff = 0
    for cb, sb in zip(c_bytes, s_bytes):
        diff = cb - sb
        if diff != 0:
            total_sq_diff += diff * diff

    return total_sq_diff / total_samples


def calculate_psnr(cover_img: Image.Image, stego_img: Image.Image) -> float:
    """
    Calculate the Peak Signal-to-Noise Ratio (PSNR) in decibels (dB).
    PSNR = 10 * log10(255^2 / MSE)
    """
    mse = calculate_mse(cover_img, stego_img)
    if mse == 0.0:
        return 99.99  # Effectively infinite; images are identical

    max_val = 255.0
    return 10.0 * math.log10((max_val * max_val) / mse)


def calculate_ber(cover_img: Image.Image, stego_img: Image.Image) -> float:
    """
    Calculate the percentage of pixels modified between cover and stego images.
    """
    c_img = cover_img.convert("RGB")
    s_img = stego_img.convert("RGB")

    c_bytes = c_img.tobytes()
    s_bytes = s_img.tobytes()

    total_pixels = len(c_bytes) // 3
    if total_pixels == 0:
        return 0.0

    modified_pixels = 0
    for i in range(0, len(c_bytes), 3):
        if (
            c_bytes[i] != s_bytes[i]
            or c_bytes[i + 1] != s_bytes[i + 1]
            or c_bytes[i + 2] != s_bytes[i + 2]
        ):
            modified_pixels += 1

    return (modified_pixels / total_pixels) * 100.0


def calculate_image_metrics(cover_img: Image.Image, stego_img: Image.Image) -> Dict[str, Any]:
    """
    Comprehensive metric evaluation for steganography audit:
    - MSE
    - PSNR (dB)
    - Modified pixel count and percentage
    - Channel-specific MSE/PSNR (Red, Green, Blue)
    - Quality assessment rating
    """
    c_img = cover_img.convert("RGB")
    s_img = stego_img.convert("RGB")

    if c_img.size != s_img.size:
        raise ValueError(f"Image sizes do not match: {c_img.size} vs {s_img.size}")

    c_bytes = c_img.tobytes()
    s_bytes = s_img.tobytes()
    num_pixels = len(c_bytes) // 3

    sq_diff_r = 0
    sq_diff_g = 0
    sq_diff_b = 0
    modified_pixels = 0
    max_pixel_diff = 0

    for i in range(0, len(c_bytes), 3):
        dr = abs(c_bytes[i] - s_bytes[i])
        dg = abs(c_bytes[i + 1] - s_bytes[i + 1])
        db = abs(c_bytes[i + 2] - s_bytes[i + 2])

        if dr != 0 or dg != 0 or db != 0:
            modified_pixels += 1
            cur_max = max(dr, dg, db)
            if cur_max > max_pixel_diff:
                max_pixel_diff = cur_max

            sq_diff_r += dr * dr
            sq_diff_g += dg * dg
            sq_diff_b += db * db

    mse_r = sq_diff_r / num_pixels if num_pixels else 0
    mse_g = sq_diff_g / num_pixels if num_pixels else 0
    mse_b = sq_diff_b / num_pixels if num_pixels else 0
    overall_mse = (sq_diff_r + sq_diff_g + sq_diff_b) / (num_pixels * 3) if num_pixels else 0

    max_val_sq = 255.0 * 255.0

    psnr_r = 99.99 if mse_r == 0 else 10.0 * math.log10(max_val_sq / mse_r)
    psnr_g = 99.99 if mse_g == 0 else 10.0 * math.log10(max_val_sq / mse_g)
    psnr_b = 99.99 if mse_b == 0 else 10.0 * math.log10(max_val_sq / mse_b)
    overall_psnr = 99.99 if overall_mse == 0 else 10.0 * math.log10(max_val_sq / overall_mse)

    pct_modified = (modified_pixels / num_pixels) * 100.0 if num_pixels else 0.0

    # Steganographic Imperceptibility Rating
    if overall_psnr >= 55.0:
        imperceptibility = "Exceptional (Completely Invisible to Human Eye)"
        grade = "A+"
    elif overall_psnr >= 45.0:
        imperceptibility = "High (Imperceptible under Normal Viewing)"
        grade = "A"
    elif overall_psnr >= 35.0:
        imperceptibility = "Good (Slight Visual Discrepancy under Micro-analysis)"
        grade = "B"
    else:
        imperceptibility = "Noticeable Distortion"
        grade = "C"

    return {
        "width": c_img.width,
        "height": c_img.height,
        "total_pixels": num_pixels,
        "modified_pixels": modified_pixels,
        "percent_modified": round(pct_modified, 3),
        "max_pixel_difference": max_pixel_diff,
        "overall_mse": round(overall_mse, 6),
        "overall_psnr_db": round(overall_psnr, 2),
        "psnr_rating": imperceptibility,
        "security_grade": grade,
        "channels": {
            "red": {"mse": round(mse_r, 6), "psnr_db": round(psnr_r, 2)},
            "green": {"mse": round(mse_g, 6), "psnr_db": round(psnr_g, 2)},
            "blue": {"mse": round(mse_b, 6), "psnr_db": round(psnr_b, 2)},
        }
    }


def generate_difference_image(
    cover_img: Image.Image,
    stego_img: Image.Image,
    amplification: int = 100
) -> Image.Image:
    """
    Generate an amplified visual difference map highlighting altered LSB pixels.
    Difference is scaled by `amplification` factor (e.g. 100x) so 1-bit changes
    are distinctly visible to reviewers and researchers.
    """
    c_img = cover_img.convert("RGB")
    s_img = stego_img.convert("RGB")

    diff = ImageChops.difference(c_img, s_img)
    # RGB LUT requires 256 * 3 entries in Pillow
    lut = [min(255, i * amplification) for i in range(256)] * 3
    diff_amplified = diff.point(lut)
    return diff_amplified

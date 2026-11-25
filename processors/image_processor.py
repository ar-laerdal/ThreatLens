"""Image validation and normalisation for architecture diagrams.

Images are decoded with Pillow (which never executes content), downscaled with OpenCV, and
re-encoded from raw pixels. Re-encoding drops EXIF/metadata and any trailing payload bytes.
"""
import base64
import io

from core.schemas import ImagePayload

MAX_DIMENSION = 1568  # larger images are downscaled by the vision API anyway
MAX_PIXELS = 50_000_000  # decompression-bomb guard
MAX_PAYLOAD_BYTES = 4_500_000  # API limit is 5 MB per image
BLUR_THRESHOLD = 60.0
MIN_SIDE = 400


class ImageValidationError(ValueError):
    pass


def normalize_image(data: bytes, description: str = "") -> tuple[ImagePayload, list[str]]:
    """Return a sanitised image payload plus quality warnings."""
    import cv2
    import numpy as np
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    warnings: list[str] = []
    try:
        probe = Image.open(io.BytesIO(data))
        probe.verify()  # structural check; the handle is unusable afterwards
        img = Image.open(io.BytesIO(data))
        if img.width * img.height > MAX_PIXELS:
            raise ImageValidationError("Image has too many pixels.")
        if img.mode in ("RGBA", "LA", "P"):
            rgba = img.convert("RGBA")
            background = Image.new("RGB", rgba.size, (255, 255, 255))
            background.paste(rgba, mask=rgba.split()[-1])
            img = background
        else:
            img = img.convert("RGB")
    except ImageValidationError:
        raise
    except Exception as exc:  # Pillow raises many exception types for corrupt data
        raise ImageValidationError("File is not a valid image.") from exc

    bgr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    height, width = bgr.shape[:2]
    if max(height, width) > MAX_DIMENSION:
        scale = MAX_DIMENSION / max(height, width)
        bgr = cv2.resize(bgr, (int(width * scale), int(height * scale)), interpolation=cv2.INTER_AREA)
        height, width = bgr.shape[:2]

    if min(height, width) < MIN_SIDE:
        warnings.append("Image is small; labels may be unreadable and components may be missed.")
    sharpness = cv2.Laplacian(cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY), cv2.CV_64F).var()
    if sharpness < BLUR_THRESHOLD:
        warnings.append("Image looks blurry or low-contrast; extraction may be incomplete.")

    ok, encoded = cv2.imencode(".png", bgr)
    media_type = "image/png"
    if not ok:
        raise ImageValidationError("Could not re-encode image.")
    if len(encoded) > MAX_PAYLOAD_BYTES:
        ok, encoded = cv2.imencode(".jpg", bgr, [cv2.IMWRITE_JPEG_QUALITY, 85])
        media_type = "image/jpeg"
        if not ok or len(encoded) > MAX_PAYLOAD_BYTES:
            raise ImageValidationError("Image is too large after compression.")

    payload = ImagePayload(
        media_type=media_type,
        data_b64=base64.b64encode(encoded.tobytes()).decode("ascii"),
        description=description,
    )
    return payload, warnings

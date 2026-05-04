"""
SecureWatch Icon Generator
Run this to create SecureWatch.ico
"""
from PIL import Image, ImageDraw

def draw_shield_icon(size):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Dark background circle
    pad = max(2, size // 20)
    draw.ellipse([pad, pad, size-pad, size-pad], fill=(10, 12, 18, 255))

    # Cyan ring
    rw = max(2, size // 18)
    draw.ellipse([pad, pad, size-pad, size-pad],
                 outline=(30, 144, 255, 255), width=rw)

    cx, cy = size // 2, size // 2

    # Shield
    sw = int(size * 0.48)
    sh = int(size * 0.54)
    sx = cx - sw // 2
    sy = int(size * 0.20)

    shield_pts = [
        (cx, sy),
        (sx + sw, sy + int(sh * 0.22)),
        (sx + sw, sy + int(sh * 0.58)),
        (cx, sy + sh),
        (sx, sy + int(sh * 0.58)),
        (sx, sy + int(sh * 0.22)),
    ]

    draw.polygon(shield_pts, fill=(20, 100, 220, 240))
    draw.polygon(shield_pts, outline=(30, 200, 255, 255), width=max(1, size//40))

    # S letter
    sr = int(size * 0.13)
    sx2 = cx
    sy2 = cy + int(size * 0.03)

    tb = [sx2 - sr, sy2 - sr*2, sx2 + sr, sy2]
    draw.arc(tb, start=30, end=200, fill=(46, 213, 115, 255), width=max(2, size//22))

    bb = [sx2 - sr, sy2, sx2 + sr, sy2 + sr*2]
    draw.arc(bb, start=210, end=20, fill=(46, 213, 115, 255), width=max(2, size//22))

    return img

if __name__ == "__main__":
    sizes = [256, 128, 64, 48, 32, 16]
    images = [draw_shield_icon(s) for s in sizes]
    images[0].save('SecureWatch.ico', format='ICO',
                   sizes=[(s,s) for s in sizes],
                   append_images=images[1:])
    print("[OK] SecureWatch.ico created!")

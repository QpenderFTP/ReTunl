"""Draws the ReTunl icon: a road that forks into two routes."""
import sys
from pathlib import Path
from PIL import Image, ImageDraw

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
S = 1024


def bezier(p0, p1, p2, p3, n=400):
    for i in range(n + 1):
        t = i / n
        a = (1 - t) ** 3
        b = 3 * (1 - t) ** 2 * t
        c = 3 * (1 - t) * t ** 2
        d = t ** 3
        yield (a * p0[0] + b * p1[0] + c * p2[0] + d * p3[0], a * p0[1] + b * p1[1] + c * p2[1] + d * p3[1])


def brush(draw, pts, r, color):
    for x, y in pts:
        draw.ellipse((x - r, y - r, x + r, y + r), fill=color)


def icon(tile, left, right, stem):
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if tile:
        d.rounded_rectangle((40, 40, S - 40, S - 40), radius=230, fill=tile)
    r = 62
    fork = (512, 560)
    brush(d, bezier((512, 860), (512, 760), (512, 660), fork), r, stem)
    brush(d, bezier(fork, (512, 420), (300, 400), (300, 196)), r, right)
    brush(d, bezier(fork, (512, 420), (724, 400), (724, 196)), r, left)
    # destination dots
    for (x, y), c in (((300, 196), right), ((724, 196), left)):
        d.ellipse((x - 92, y - 92, x + 92, y + 92), fill=c)
    return img


INK = (17, 24, 32, 255)
AMBER = (245, 165, 36, 255)
MIST = (226, 232, 238, 255)
GREY = (140, 148, 158, 255)

main = icon(INK, AMBER, MIST, MIST)
main.resize((512, 512), Image.LANCZOS).save(out / "icon.png")
main.resize((32, 32), Image.LANCZOS).save(out / "32x32.png")
main.resize((128, 128), Image.LANCZOS).save(out / "128x128.png")
main.resize((256, 256), Image.LANCZOS).save(out / "128x128@2x.png")
main.save(out / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

# macOS: the tile fits the standard 824 px grid of a 1024 px canvas
mac = Image.new("RGBA", (S, S), (0, 0, 0, 0))
mac.alpha_composite(main.resize((894, 894), Image.LANCZOS), (65, 65))
mac.save(out / "icon.icns")

# Windows installer: the road comes up from the bottom edge of the side panel and forks
K = 4
W, H = 164 * K, 314 * K
side = Image.new("RGB", (W, H), INK[:3])
d = ImageDraw.Draw(side)
r = 9 * K
fork = (W / 2, H * 0.56)
left_dot, right_dot = (W * 0.27, H * 0.27), (W * 0.73, H * 0.27)
brush(d, bezier((W / 2, H + r), (W / 2, H * 0.8), (W / 2, H * 0.66), fork), r, MIST)
brush(d, bezier(fork, (W / 2, H * 0.42), (left_dot[0], H * 0.42), left_dot), r, MIST)
brush(d, bezier(fork, (W / 2, H * 0.42), (right_dot[0], H * 0.42), right_dot), r, AMBER)
for (x, y), c in ((left_dot, MIST), (right_dot, AMBER)):
    d.ellipse((x - 15 * K, y - 15 * K, x + 15 * K, y + 15 * K), fill=c)
side.resize((164, 314), Image.LANCZOS).save(out / "nsis-sidebar.bmp")

# tray: no tile so it reads on light and dark taskbars; off = grey
on = icon(INK, AMBER, MIST, MIST)
off = icon((60, 66, 74, 255), GREY, (200, 204, 210, 255), (200, 204, 210, 255))
on.resize((64, 64), Image.LANCZOS).save(out / "tray-on.png")
off.resize((64, 64), Image.LANCZOS).save(out / "tray-off.png")
print("ok", sorted(p.name for p in out.iterdir()))

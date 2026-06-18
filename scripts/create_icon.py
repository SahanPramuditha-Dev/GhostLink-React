from PIL import Image
from pathlib import Path

src = Path(__file__).parent / 'icon.png'
dest = Path(__file__).parent / 'ghostlink.ico'

if not src.exists():
    print('icon.png not found; skipping ico generation')
else:
    img = Image.open(src).convert('RGBA')
    img.save(dest, format='ICO', sizes=[(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)])
    print(f'Generated {dest}')

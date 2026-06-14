import re
p = 'ghostlink/gui/main_window.py'
with open(p, 'r', encoding='utf-8') as f:
    s = f.read()

replacements = {
    'ÃƒÂ¢Ã¢â‚¬Â Ã¢â€šÂ¬': '│',
    'ÃƒÂ¢Ã…Â¸Ã‚Â³': '⟳',
    'ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“': '✓',
    'ÃƒÂ¢Ã…â€œÃ¢â‚¬â€ ': '✕',
    'ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦': '…',
    'ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â ': '—',
}
for k, v in replacements.items():
    s = s.replace(k, v)

with open(p, 'w', encoding='utf-8') as f:
    f.write(s)
print('Fixed mojibake')

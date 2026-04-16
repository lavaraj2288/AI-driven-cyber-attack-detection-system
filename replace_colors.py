import os
import re

directory = r"c:\Users\LOVE\Desktop\ai\Template"

replacements = {
    re.compile(r'#ff4b2b', re.IGNORECASE): '#28a745',
    re.compile(r'#ffe4e1', re.IGNORECASE): '#d4edda',
    re.compile(r'#e03e26', re.IGNORECASE): '#218838'
}

changed_files = []

for root, dirs, files in os.walk(directory):
    for file in files:
        if file.endswith('.html') or file.endswith('.css'):
            filepath = os.path.join(root, file)
            with open(filepath, 'r', encoding='utf-8') as f:
                try:
                    content = f.read()
                except UnicodeDecodeError:
                    continue
            
            original_content = content
            for pattern, replacement in replacements.items():
                content = pattern.sub(replacement, content)
            
            if content != original_content:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                changed_files.append(filepath)

print("Changed files:")
for f in changed_files:
    print(f)

import re

content = open("app.py", encoding="utf-8").read()
updated = re.sub(r",\s*use_container_width=True", ", width='stretch'", content)
updated = re.sub(r"use_container_width=True", "width='stretch'", updated)
open("app.py", "w", encoding="utf-8").write(updated)
print("Done — deprecated use_container_width replaced.")

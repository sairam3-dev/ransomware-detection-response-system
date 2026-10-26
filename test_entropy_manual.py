
from app.core.entropy import calculate_entropy

normal_text = b"hello world " * 100
repeated_bytes = b"A" * 1000
uniform_bytes = bytes(range(256)) * 20

print("Repeated bytes:", calculate_entropy(repeated_bytes))
print("Normal text:", calculate_entropy(normal_text))
print("Uniform byte distribution:", calculate_entropy(uniform_bytes))


from pathlib import Path
from app.core.entropy import calculate_file_entropy

sandbox = Path("data/sandbox")
sandbox.mkdir(parents=True, exist_ok=True)

text_file = sandbox / "normal_sample.txt"
text_file.write_bytes(b"hello world " * 100)

uniform_file = sandbox / "uniform_sample.bin"
uniform_file.write_bytes(bytes(range(256)) * 256)

print("Text file entropy:", calculate_file_entropy(str(text_file)))
print("Uniform file entropy:", calculate_file_entropy(str(uniform_file)))

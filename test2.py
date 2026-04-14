import re

'''file_path="static/kg/U002_pb.txt"
with open(file_path, "r") as f:
        lines = f.readlines()

# Remove BEGIN and END lines
key_lines = [
    line.strip()
    for line in lines
    if "BEGIN PUBLIC KEY" not in line and
       "END PUBLIC KEY" not in line
]

# Join into single continuous string
key_string = "".join(key_lines)
print(key_string[:64])'''
##################3





def get_first_64_from_private_key(file_path):
    with open(file_path, "r") as f:
        key_text = f.read()

    # Remove PEM headers/footers
    cleaned = re.sub(r"-----.*?-----", "", key_text)

    # Remove whitespace and newlines
    cleaned = cleaned.replace("\n", "").strip()

    # Get first 64 characters
    return cleaned[:64]


# Example usage
file_path = "static/kg/U002_pr.txt"
first_64 = get_first_64_from_private_key(file_path)
print(first_64)

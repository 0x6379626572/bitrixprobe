
# Convert a value into a filesystem-safe filename fragment.

def safe_filename(value) -> str:
    return (str(value)
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace(" ", "_")
    )
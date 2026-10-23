"""
core/vault.py
-------------
Secret Vault packaging, compression, and safe extraction.
Builds an in-memory ZIP archive containing metadata, secret text message,
and attached files. Prevents ZIP path traversal attacks on extraction.
"""

import io
import json
import os
import re
import mimetypes
import hashlib
from datetime import datetime, timezone
import zipfile
from dataclasses import dataclass, field

VAULT_VERSION = 1


@dataclass
class VaultFile:
    name: str
    data: bytes
    size: int
    mime_type: str
    sha256: str


@dataclass
class VaultContent:
    message: str | None
    files: list[VaultFile] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    original_size: int = 0
    compressed_size: int = 0
    compression_saved_pct: float = 0.0


def sanitize_filename(filename: str) -> str:
    """
    Sanitize an archive filename to eliminate directory traversal attacks
    such as '../', '..\\', absolute drive paths, and invalid filesystem characters.
    """
    # Strip any leading directory path components
    base = os.path.basename(filename.replace("\\", "/"))
    # Remove control characters and unsafe symbols
    clean = re.sub(r'[\x00-\x1f\x7f<>:"/\\|?*]', '_', base).strip(" .")
    if not clean:
        clean = "unnamed_file.bin"
    return clean


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hexadecimal digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def guess_mime_type(filename: str) -> str:
    """Guess MIME type from filename extension, defaulting to application/octet-stream."""
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/octet-stream"


def create_vault(
    message: str | None = None,
    files: list[tuple[str, bytes]] | None = None,
) -> tuple[bytes, VaultContent]:
    """
    Package secret message and uploaded files into an in-memory compressed ZIP archive.
    
    Parameters:
        message: Optional secret text string.
        files: Optional list of (filename: str, file_bytes: bytes) tuples.
        
    Returns:
        tuple (zip_bytes: bytes, vault_content: VaultContent)
    """
    files = files or []
    has_message = bool(message and message.strip())
    
    if not has_message and not files:
        raise ValueError("Vault must contain either a secret message or at least one file.")

    vault_files: list[VaultFile] = []
    file_metadata_list: list[dict] = []
    raw_size_sum = 0

    message_bytes = b""
    if has_message:
        message_bytes = message.encode("utf-8")
        raw_size_sum += len(message_bytes)

    # Process files
    seen_names: set[str] = set()
    for raw_name, data in files:
        safe_name = sanitize_filename(raw_name)
        # Ensure unique file names within vault
        base_name, ext = os.path.splitext(safe_name)
        counter = 1
        while safe_name in seen_names:
            safe_name = f"{base_name}_{counter}{ext}"
            counter += 1
        seen_names.add(safe_name)

        size = len(data)
        raw_size_sum += size
        mime = guess_mime_type(safe_name)
        sha = compute_sha256(data)

        vf = VaultFile(
            name=safe_name,
            data=data,
            size=size,
            mime_type=mime,
            sha256=sha,
        )
        vault_files.append(vf)
        file_metadata_list.append({
            "name": safe_name,
            "size": size,
            "mime_type": mime,
            "sha256": sha,
        })

    metadata = {
        "vault_version": VAULT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "message_present": has_message,
        "file_count": len(vault_files),
        "files": file_metadata_list,
    }

    # Build in-memory ZIP
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        # Write metadata.json
        meta_bytes = json.dumps(metadata, indent=2).encode("utf-8")
        zf.writestr("metadata.json", meta_bytes)

        # Write message.txt if present
        if has_message:
            zf.writestr("message.txt", message_bytes)

        # Write attached files inside files/ directory
        for vf in vault_files:
            zf.writestr(f"files/{vf.name}", vf.data)

    zip_bytes = buffer.getvalue()
    compressed_size = len(zip_bytes)

    # Compute compression savings
    if raw_size_sum > 0:
        saved_pct = max(0.0, (1.0 - (compressed_size / raw_size_sum)) * 100.0)
    else:
        saved_pct = 0.0

    content = VaultContent(
        message=message if has_message else None,
        files=vault_files,
        metadata=metadata,
        original_size=raw_size_sum,
        compressed_size=compressed_size,
        compression_saved_pct=saved_pct,
    )

    return zip_bytes, content


def extract_vault(zip_bytes: bytes) -> VaultContent:
    """
    Extract and validate an in-memory ZIP vault.
    Strictly prevents zip path traversal attacks.
    
    Returns:
        VaultContent instance containing message and recovered files.
    """
    if not zip_bytes:
        raise ValueError("Vault archive data is empty.")

    try:
        buffer = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(buffer, mode="r") as zf:
            file_list = zf.namelist()

            # Read metadata.json if present
            metadata = {}
            if "metadata.json" in file_list:
                try:
                    meta_raw = zf.read("metadata.json")
                    metadata = json.loads(meta_raw.decode("utf-8"))
                except Exception:
                    metadata = {}

            # Read secret message if present
            message: str | None = None
            if "message.txt" in file_list:
                try:
                    message = zf.read("message.txt").decode("utf-8")
                except UnicodeDecodeError:
                    message = zf.read("message.txt").decode("utf-8", errors="replace")

            # Extract attached files
            vault_files: list[VaultFile] = []
            for name in file_list:
                # Only look for files inside files/ or non-root files that are not metadata/message
                if name in ("metadata.json", "message.txt") or name.endswith("/"):
                    continue

                # Strip 'files/' prefix if present
                clean_target = name
                if clean_target.startswith("files/"):
                    clean_target = clean_target[6:]

                # Sanitize filename to avoid any path traversal
                safe_name = sanitize_filename(clean_target)
                data = zf.read(name)
                size = len(data)
                mime = guess_mime_type(safe_name)
                sha = compute_sha256(data)

                vf = VaultFile(
                    name=safe_name,
                    data=data,
                    size=size,
                    mime_type=mime,
                    sha256=sha,
                )
                vault_files.append(vf)

            raw_size = sum(vf.size for vf in vault_files)
            if message:
                raw_size += len(message.encode("utf-8"))

            compressed_size = len(zip_bytes)
            saved_pct = max(0.0, (1.0 - (compressed_size / raw_size)) * 100.0) if raw_size > 0 else 0.0

            return VaultContent(
                message=message,
                files=vault_files,
                metadata=metadata,
                original_size=raw_size,
                compressed_size=compressed_size,
                compression_saved_pct=saved_pct,
            )
    except zipfile.BadZipFile:
        raise ValueError("Invalid or corrupted vault package (not a valid ZIP archive).")

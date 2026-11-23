"""File type groups the engines and the reader share."""

MEDIA_EXTENSIONS = {
    # video
    "mkv", "mp4", "m4v", "avi", "mov", "wmv", "mpg", "mpeg", "m2ts", "ts", "vob", "webm",
    "flv", "3gp", "ogv", "divx",
    # audio
    "mp3", "flac", "wav", "m4a", "aac", "ogg", "opus", "wma", "aiff", "ape", "dsf",
}  # fmt: skip
# Real types (libmagic) that count as media for the large-file shortcut.
MEDIA_MIME_PREFIXES = ("video/", "audio/")
MEDIA_MIMES = {"application/x-matroska", "application/ogg"}

IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "heic", "webp", "raw",
                    "cr2", "nef", "arw", "dng", "svg", "ico", "psd"}  # fmt: skip
DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "xlsb", "ppt",
                       "pptx", "pptm", "odt", "ods", "odp", "rtf", "txt", "md", "csv", "epub",
                       "mobi", "srt", "sub", "nfo"}  # fmt: skip
PRINT_EXTENSIONS = {"stl", "3mf", "amf", "obj", "gcode", "gco", "step", "stp", "f3d", "blend"}
BENIGN_EXTENSIONS = MEDIA_EXTENSIONS | IMAGE_EXTENSIONS | DOCUMENT_EXTENSIONS | PRINT_EXTENSIONS

# Things that run when opened (on Windows mostly, where they do the damage).
EXECUTABLE_EXTENSIONS = {
    "exe", "dll", "scr", "com", "pif", "cpl", "msi", "msp", "msc", "bat", "cmd", "ps1", "psm1",
    "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "jar", "reg", "scf", "url",
    "appref-ms", "gadget", "application", "sys", "drv", "ocx", "sh", "elf", "apk", "app",
}  # fmt: skip
EXECUTABLE_MIMES = {
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-pie-executable",
    "application/x-mach-binary",
    "application/x-elf",
    "application/x-ms-shortcut",
    "application/x-msi",
    "application/java-archive",
}

OFFICE_EXTENSIONS = {"doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "xlsb", "xlt",
                     "xltm", "xla", "xlam", "ppt", "pptx", "pptm", "pot", "potm", "ppsm", "rtf",
                     "mht", "mhtml"}  # fmt: skip
OFFICE_MIME_MARKERS = ("msword", "ms-excel", "ms-powerpoint", "officedocument", "ms-office",
                       "rtf", "vnd.ms-", "x-ole-storage", "cdfv2")  # fmt: skip


def is_media(extension: str | None, mime: str | None) -> bool:
    """Named like media and really media."""
    if extension not in MEDIA_EXTENSIONS or not mime:
        return False
    return mime.startswith(MEDIA_MIME_PREFIXES) or mime in MEDIA_MIMES


def is_executable(extension: str | None, mime: str | None) -> bool:
    return extension in EXECUTABLE_EXTENSIONS or (mime or "") in EXECUTABLE_MIMES

#!/usr/bin/env python3
import json
import subprocess
import sys


# Extra mime types for UTIs that don't have them in lsregister
extra_mimes = {
    "com.apple.xar-archive": ["application/x-xar"],
    "com.apple.coreaudio-format": ["audio/x-caf"],
    "com.apple.xml-property-list": ["application/xml+plist"],
    "com.apple.binary-property-list": ["application/x-apple-plist", "application/x-plist"],
}


def process_entry(entry):
    tag_string = entry.get("tags", "")
    if tag_string:
        for tag in tag_string.split(", "):
            if tag.startswith("."):
                entry.setdefault("extensions", []).append(tag)
            elif "/" in tag:
                entry.setdefault("mime_types", []).append(tag)
            else:
                entry.setdefault("unknown_tags", []).append(tag)
        del entry["tags"]
    if entry["uti"] in extra_mimes:
        entry["mime_types"] = list(set(entry.get("mime_types", []) + extra_mimes[entry["uti"]]))
    desc = entry.get("localizedDescription", "")
    if desc:
        languages = dict(
            [
                language.split('" = "', 1)
                for language in desc.strip('"').split('", "')
                if '" = "' in language
            ]
        )
        if languages.get("en", "?") != "?":
            entry["description"] = languages["en"]
        elif "LSDefaultLocalizedValue" in languages:
            entry["description"] = languages["LSDefaultLocalizedValue"]
        del entry["localizedDescription"]
    if "conforms to" in entry:
        entry["parent_uti"] = entry.pop("conforms to")
    return entry


print("Dumping lsregister", file=sys.stderr)
ret = subprocess.run(
    [
        "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister",
        "-dump",
    ],
    capture_output=True,
)


print("Parsing lsregister", file=sys.stderr)
entries = [
    process_entry(
        dict(
            [
                [kv.strip() for kv in entry_line.split(":", 1)]
                for entry_line in entry_text.strip().split("\n")
                if (
                    entry_line.startswith("uti:")
                    or entry_line.startswith("tags:")
                    or entry_line.startswith("conforms to:")
                    or entry_line.startswith("localizedDescription:")
                )
            ]
        )
    )
    for entry_text in ret.stdout.decode("utf-8").split("-" * 80)[1:]
    if "uti:" in entry_text
]

if "--mime-only" in sys.argv:
    # TODO also find mime types for entries that only have extensions in lsregister?
    data = {mime: entry["uti"] for entry in entries for mime in entry.get("mime_types", [])}
    print(json.dumps(data, indent=2))
else:
    print("Writing", len(entries), "parsed entries", file=sys.stderr)
    # Dump the list manually, so each object is on its own line, but the objects aren't split to multiple lines
    print("[")
    for entry in entries[:-1]:
        print("  ", json.dumps(entry), ",", sep="")
    print("  ", json.dumps(entries[-1]), sep="")
    print("]")

print("All done", file=sys.stderr)

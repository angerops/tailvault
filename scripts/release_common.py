#!/usr/bin/env python3
"""Provider-neutral release ownership, integrity checks, and draft recovery."""
import base64
import hashlib
import json
import re
import urllib.parse

MARKER = "<!-- tailvault-build-v1 "

def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_files(version, files):
    checksum, filename = files["SHA256SUMS"].decode().strip().split(maxsplit=1)
    if not re.fullmatch(r"TailVault-v" + re.escape(version) + r"-macos-(arm64|amd64)\.zip", filename):
        raise RuntimeError("Unexpected release archive name")
    if set(files) != {filename, "SHA256SUMS"}:
        raise RuntimeError("Unexpected release assets")
    if digest(files[filename]) != checksum:
        raise RuntimeError("Release archive checksum mismatch")
    return filename


def manifest_for(commit, version, files):
    return {"commit": commit, "version": version, "files": {
        name: dict(sha256=digest(data), size=len(data), **(
            {"data": base64.b64encode(data).decode()} if name == "SHA256SUMS" else {}
        )) for name, data in files.items()
    }}


def description(manifest, filename):
    return ("macOS build from `{}`. Developer ID signed, notarized, stapled, and verified by Gatekeeper.\n\n"
            "Download `{}` and move TailVault.app to Applications. SHA-256 checksums are attached.\n\n"
            + MARKER + "{} -->").format(manifest["commit"], filename, json.dumps(manifest, sort_keys=True))


def publish(client, commit, version, event, ref, files):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise RuntimeError("Invalid application version or commit")
    # Require the build evidence, but keep it outside release assets and notes.
    files = files.copy()
    try:
        report = json.loads(files.pop("notarization.json", b"{}"))
    except (TypeError, ValueError) as error:
        raise RuntimeError("Invalid notarization report") from error
    if not isinstance(report, dict) or report.get("status") != "Accepted":
        raise RuntimeError("Only notarized builds can be uploaded")
    filename = verify_files(version, files)
    if event == "push" and re.fullmatch(r"refs/tags/v" + re.escape(version) + r"(?:-rc\.[1-9][0-9]*)?", ref):
        tag, manual = ref[len("refs/tags/"):], False
    elif event == "workflow_dispatch":
        tag, manual = "signed-" + commit[:12], True
    else:
        raise RuntimeError("Release uploads require a matching version tag or manual dispatch")
    manifest = manifest_for(commit, version, files)
    release = client.request("GET", "/releases/tags/" + urllib.parse.quote(tag, safe=""))
    if release is None:
        release = client.request("POST", "/releases", {
            "tag_name": tag, "target_commitish": commit,
            "name": "v" + version if manual else tag,
            "body": description(manifest, filename), "draft": True, "prerelease": "-rc." in tag,
        })
    if release["tag_name"] != tag or release.get("target_commitish") != commit:
        raise RuntimeError("Existing release belongs to a different commit or tag")
    if bool(release.get("prerelease")) != ("-rc." in tag):
        raise RuntimeError("Existing release has the wrong prerelease status")
    if manual and not release.get("draft"):
        raise RuntimeError("Manual builds must remain drafts")
    path = "/releases/{}".format(release["id"])
    assets = release.get("assets", [])
    if len({a["name"] for a in assets}) != len(assets):
        raise RuntimeError("Duplicate release asset names")
    existing = {a["name"]: a for a in assets}
    body = release.get("body", "")
    if MARKER in body:
        old = json.loads(body.split(MARKER, 1)[1].split(" -->", 1)[0])
        if old.get("commit") != commit or old.get("version") != version:
            raise RuntimeError("Existing release manifest belongs to another build")
        if existing or not release.get("draft"):
            # Retain the original notarized build, even when this run rebuilt it.
            manifest = old
        elif old != manifest:
            client.request("PATCH", path, {"body": description(manifest, filename)})
    if set(manifest["files"]) != set(files) or set(existing) - set(files):
        raise RuntimeError("Existing release contains unexpected build assets")
    resolved = {}
    for name, meta in manifest["files"].items():
        if name in existing:
            data = client.download(existing[name], tag)
        elif "data" in meta:
            data = base64.b64decode(meta["data"], validate=True)
        else:
            data = files[name]
        if len(data) != meta["size"] or digest(data) != meta["sha256"]:
            raise RuntimeError("Conflicting release asset: " + name + "; existing bytes were left unchanged")
        resolved[name] = data
    verify_files(version, resolved)
    # Archive first: the manifest can recover its checksum on a rerun.
    for name in (filename, "SHA256SUMS"):
        if name not in existing:
            asset = client.request("POST", path + "/assets?" + urllib.parse.urlencode({"name": name}), resolved[name], "application/octet-stream")
            if asset.get("name") != name or client.download(asset, tag) != resolved[name]:
                raise RuntimeError("Uploaded asset verification failed: " + name)
    # Re-read the complete release to detect concurrent or partial uploads.
    final = client.request("GET", path)
    if final.get("tag_name") != tag or final.get("target_commitish") != commit:
        raise RuntimeError("Release ownership changed during upload")
    if bool(final.get("prerelease")) != ("-rc." in tag):
        raise RuntimeError("Release prerelease status changed during upload")
    final_assets = final.get("assets", [])
    if len(final_assets) != len(resolved) or {a["name"] for a in final_assets} != set(resolved):
        raise RuntimeError("Release assets changed during upload")
    for asset in final_assets:
        if client.download(asset, tag) != resolved[asset["name"]]:
            raise RuntimeError("Release assets changed during verification")
    if not manual and final["draft"]:
        client.request("PATCH", path, {"draft": False})
    return client.release_url(tag), resolved

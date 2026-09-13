// Test-only fixture server. This is not embedded in the Go binary.
import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

export async function startFixture(port = 18765) {
  let calls = [],
    locked = false,
    clipboard = "",
    savedFiles = [],
    connected = true,
    serverURL = "https://secrets.example.ts.net",
    settingsToken = "fixture-settings",
    settingsSaveError = false,
    listError = "",
    connection = "fixture-view";
  const secrets = new Map();
  const names = [
    "personal/github/token",
    "personal/linear/api-key",
    "personal/notes/recovery-code",
    "platform/development/database-url",
    "platform/development/service-account.json",
    "platform/production/database-url",
    "platform/production/redis-password",
    "platform/production/signing-key.pem",
    "platform/shared/cloudflare-token",
    "platform/shared/deploy-key",
  ];
  function reset() {
    secrets.clear();
    calls = [];
    locked = false;
    clipboard = "";
    savedFiles = [];
    connected = true;
    connection = "fixture-view";
    serverURL = "https://secrets.example.ts.net";
    settingsToken = "fixture-settings";
    settingsSaveError = false;
    listError = "";
    for (const name of names)
      secrets.set(name, {
        Name: name,
        ActiveVersion: 1,
        Values: {
          1: Buffer.from("sample-value-for-testing").toString("base64"),
        },
      });
    secrets.get("platform/production/database-url").Values[2] = Buffer.from(
      "sample-rotated-value",
    ).toString("base64");
    secrets.get("platform/production/database-url").Values[3] =
      Buffer.from("sample-next-value").toString("base64");
    secrets.get("platform/production/database-url").ActiveVersion = 2;
  }
  reset();
  const info = (s) => ({
    Name: s.Name,
    ActiveVersion: s.ActiveVersion,
    Versions: Object.keys(s.Values).map(Number),
  });
  const server = http.createServer(async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    );
    function send(code, data) {
      res.writeHead(code, {
        "Content-Type":
          typeof data === "string" ? "text/plain" : "application/json",
      });
      res.end(typeof data === "string" ? data : JSON.stringify(data));
    }
    if (req.url === "/ui-api/settings") {
      if (req.method === "POST") {
        if (req.headers["x-tailvault-settings"] !== settingsToken)
          return send(409, "Settings changed. Close and reopen Settings before trying again.");
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const input = JSON.parse(Buffer.concat(chunks).toString());
        let target;
        try {
          target = new URL(input.server.trim());
          if (target.protocol !== "https:" || target.username || target.password || target.pathname !== "/" || target.search || target.hash)
            throw new Error("invalid origin");
        } catch {
          return send(400, "Enter an HTTPS server address without a path, credentials, query, or fragment.");
        }
        if (settingsSaveError) return send(500, "The server address could not be saved. Check access to TailVault's settings folder and try again.");
        serverURL = target.origin;
        settingsToken += "-saved";
        locked = true;
      }
      return send(200, { server: serverURL, settingsToken, error: "" });
    }
    if (req.url === "/ui-api/session") {
      if (!serverURL) return send(428, "Set up your Setec server to open the vault.");
      if (!connected) return send(401, "Connect Tailscale to open the vault.");
      if (locked) {
        connection += "-reopened";
        locked = false;
      }
      return send(200, {
        name: "Alex Morgan",
        login: "alex@example.test",
        tailnet: { name: "Example team", dnsName: "example-team.ts.net" },
        connection,
        server: serverURL,
        preview: true,
      });
    }
    if (req.url.startsWith("/ui-api/")) {
      if (
        !connected ||
        locked ||
        req.headers["x-tailvault-connection"] !== connection
      )
        return send(
          401,
          "Tailscale disconnected or its identity changed. Open the vault to reconnect.",
        );
      if (req.url === "/ui-api/status") {
        res.writeHead(204);
        res.end();
        return;
      }
      if (req.url === "/ui-api/close") {
        locked = true;
        res.writeHead(204);
        res.end();
        return;
      }
      const op = req.url.slice(8);
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString() || "{}");
      calls.push({ op, ...body });
      if (op === "curl" || op === "copy-curl") {
        const input = { Name: body.Name };
        if (body.Version) input.Version = body.Version;
        const quote = (value) => "'" + value.replaceAll("'", "'\"'\"'") + "'";
        let command = [
          "curl --disable --fail --silent --show-error",
          "  --noproxy '*'",
          "  --request POST",
          "  --header 'Sec-X-Tailscale-No-Browsers: setec'",
          "  --header 'Content-Type: application/json'",
          "  --data-raw " + quote(JSON.stringify(input)),
          "  " + quote(serverURL + "/api/get"),
        ].join(" \\\n");
        if (body.Decode)
          command += ` |\n  python3 -c 'import base64,json,sys; sys.stdout.buffer.write(base64.b64decode(json.load(sys.stdin)["Value"], validate=True))'`;
        if (op === "copy-curl") {
          clipboard = command;
          res.writeHead(204);
          res.end();
          return;
        }
        return send(200, { command });
      }
      if (op === "list") {
        const visible = [...secrets.values()].filter((s) => s.Name !== "finance/hidden").map(info);
        return listError ? send(502, listError) : send(200, visible.length ? visible : null);
      }
      if (op === "copy-path") {
        clipboard = body.Name;
        res.writeHead(204);
        res.end();
        return;
      }
      if (
        body.Name === "finance/hidden" ||
        (body.Name?.startsWith("finance/") && op !== "info") ||
        (body.Name?.startsWith("platform/production/") &&
          !["get", "info", "copy", "download"].includes(op))
      )
        return send(
          403,
          "Your Tailscale permissions do not allow this action on this path.",
        );
      const secret = secrets.get(body.Name);
      if (op === "put" || op === "create-version") {
        const latest = secret ? Math.max(secret.LatestVersion || 0, ...Object.keys(secret.Values).map(Number)) : 0;
        // This fixture is checked against pinned upstream Setec by shared cases.
        if (op === "put" && secret && (secret.Values[latest] ?? "") === body.Value)
          return send(200, latest);
        const version =
          op === "create-version"
            ? body.Version
            : latest + 1;
        if (secret?.Values[version] !== undefined || secret?.DeletedVersions?.has(version))
          return send(412, "This version number has already been used.");
        const s = secret || {
          Name: body.Name,
          ActiveVersion: version,
          Values: {},
        };
        s.Values[version] = body.Value;
        s.LatestVersion = Math.max(latest, version);
        if (op === "create-version") s.ActiveVersion = version;
        secrets.set(body.Name, s);
        return send(200, op === "put" ? version : {});
      }
      if (op === "delete") {
        secrets.delete(body.Name);
        return send(200, {});
      }
      if (!secret) return send(404, "Secret or version is unavailable.");
      // Stand-ins for Wails callbacks: never touch the OS clipboard or filesystem.
      if (op === "copy" || op === "download") {
        const value = secret.Values[body.Version || secret.ActiveVersion];
        if (value === undefined)
          return send(404, "Secret or version is unavailable.");
        const bytes = Buffer.from(value, "base64");
        if (op === "download") {
          savedFiles.push({ name: body.Name, bytes });
          return send(200, {saved: true});
        }
        else {
          try {
            clipboard = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
          } catch {
            return send(400, "Binary secrets must be downloaded.");
          }
        }
        res.writeHead(204);
        res.end();
        return;
      }
      if (op === "info") return send(200, info(secret));
      if (op === "get") {
        if (secret.Values[body.Version || secret.ActiveVersion] === undefined)
          return send(404, "Secret or version is unavailable.");
        return send(200, {
          Value: secret.Values[body.Version || secret.ActiveVersion],
          Version: body.Version || secret.ActiveVersion,
        });
      }
      if (op === "activate") {
        if (secret.Values[body.Version] === undefined)
          return send(404, "Secret or version is unavailable.");
        secret.ActiveVersion = body.Version;
        return send(200, {});
      }
      if (op === "delete-version") {
        if (body.Version === secret.ActiveVersion)
          return send(502, "Setec could not complete the action. Refresh before retrying.");
        if (secret.Values[body.Version] === undefined)
          return send(404, "Secret or version is unavailable.");
        secret.LatestVersion = Math.max(secret.LatestVersion || 0, ...Object.keys(secret.Values).map(Number));
        delete secret.Values[body.Version];
        (secret.DeletedVersions ||= new Set()).add(body.Version);
        return send(200, {});
      }
      return send(404, "Unknown operation");
    }
    const files = {
      "/": "index.html",
      "/app.js": "app.js",
      "/style.css": "style.css",
      "/icon.svg": "icon.svg",
    };
    if (!files[req.url]) return send(404, "Not found");
    const types = {
      html: "text/html",
      js: "text/javascript",
      css: "text/css",
      svg: "image/svg+xml",
    };
    res.setHeader("Content-Type", types[files[req.url].split(".").pop()]);
    res.end(
      await readFile(
        new URL("../internal/portal/assets/" + files[req.url], import.meta.url),
      ),
    );
  });
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  return {
    server,
    reset,
    secrets,
    get serverURL() { return serverURL; },
    set serverURL(value) { serverURL = value; },
    set settingsSaveError(value) { settingsSaveError = value; },
    set listError(value) { listError = value; },
    set connected(value) {
      connected = value;
    },
    get clipboard() {
      return clipboard;
    },
    get savedFiles() {
      return savedFiles;
    },
    get calls() {
      return calls;
    },
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const fixture = await startFixture();
  console.log(`Sample-data UI preview: ${fixture.url}`);
}

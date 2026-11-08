// Dependency-free packaging: shared sources have one authoritative copy.
import { mkdir, copyFile, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = path.dirname(fileURLToPath(import.meta.url));
for (const target of ["chromium", "firefox"]) {
  const out = path.join(root, "dist", target);
  await mkdir(out, { recursive: true });
  for (const name of ["manifest.json", ...(target === "chromium" ? ["service-worker.js"] : ["background.js", "content.js"])]) {
    await copyFile(path.join(root, target, name), path.join(out, name));
  }
  for (const name of ["core.js", "approval.html", "approval.js", "approval.css", "webauthn.js"]) {
    await copyFile(path.join(root, "shared", name), path.join(out, name));
  }
  // A deterministic, explicit output path keeps native-host manifests independent
  // of development source layout. Chrome retains its existing fixed extension key.
  const manifest = JSON.parse(await readFile(path.join(out, "manifest.json"), "utf8"));
  await writeFile(path.join(out, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
  console.log(out);
}

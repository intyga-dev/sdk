import fs from "node:fs"
import path from "node:path"

/** Files that can authorize, decrypt, or prove an incident are private by default. */
export const PRIVATE_FILE_MODE = 0o600
export const PRIVATE_DIR_MODE = 0o700

function repairMode(target: string, mode: number): void {
  try {
    fs.chmodSync(target, mode)
  } catch {
    // Windows and a few network filesystems do not implement POSIX modes. Creation remains
    // exclusive; callers must still protect the containing volume there.
  }
}

/** Create (or repair) a private directory without following a symlink supplied as a file. */
export function ensurePrivateDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: PRIVATE_DIR_MODE })
  const stat = fs.lstatSync(dir)
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`refusing unsafe directory: ${dir}`)
  repairMode(dir, PRIVATE_DIR_MODE)
}

/** Atomically replace a sensitive file from a same-directory, exclusive temporary file. */
export function writePrivateFile(file: string, contents: string | Buffer): void {
  const dir = path.dirname(file)
  ensurePrivateDir(dir)
  try {
    const existing = fs.lstatSync(file)
    if (existing.isSymbolicLink() || !existing.isFile()) throw new Error(`refusing unsafe file: ${file}`)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err
  }
  const temp = path.join(dir, `.${path.basename(file)}.${process.pid}.${crypto.randomUUID()}.tmp`)
  try {
    fs.writeFileSync(temp, contents, { encoding: "utf8", mode: PRIVATE_FILE_MODE, flag: "wx" })
    repairMode(temp, PRIVATE_FILE_MODE)
    fs.renameSync(temp, file)
    repairMode(file, PRIVATE_FILE_MODE)
  } finally {
    try {
      fs.unlinkSync(temp)
    } catch {}
  }
}

/** Create a marker exactly once. O_EXCL and O_NOFOLLOW make replay state resistant to races/symlinks. */
export function createPrivateMarker(file: string, contents: string): boolean {
  ensurePrivateDir(path.dirname(file))
  try {
    const fd = fs.openSync(
      file,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      PRIVATE_FILE_MODE,
    )
    try {
      fs.writeFileSync(fd, contents, "utf8")
      fs.fchmodSync(fd, PRIVATE_FILE_MODE)
    } finally {
      fs.closeSync(fd)
    }
    return true
  } catch {
    return false
  }
}

import { PathError } from "../errors.js";

const MAX_PATH_LENGTH = 1024;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

/**
 * Canonical form of a vault path: NFC-normalised, forward slashes, relative,
 * no `.` or empty segments. `..` is rejected rather than resolved so a caller
 * can never escape the vault root by construction.
 */
export function diataCanonicalPath(input: unknown): string {
  if (typeof input !== "string" || input.length === 0) {
    throw new PathError("path must be a non-empty string");
  }
  if (input.length > MAX_PATH_LENGTH) {
    throw new PathError("path is too long");
  }
  const normalised = input.normalize("NFC");
  if (CONTROL_CHARACTERS.test(normalised)) {
    throw new PathError("path contains control characters");
  }
  const unified = normalised.replaceAll("\\", "/");
  if (unified.startsWith("/") || /^[a-zA-Z]:/.test(unified)) {
    throw new PathError("path must be relative");
  }
  const segments: string[] = [];
  for (const segment of unified.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") throw new PathError("path must not contain '..'");
    segments.push(segment);
  }
  if (segments.length === 0) {
    throw new PathError("path must name a file");
  }
  return segments.join("/");
}

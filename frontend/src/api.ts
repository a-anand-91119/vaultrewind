export class APIError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}
// Ambiguous transport failures retain the same intent key; successful later clicks create a new capture.
// Only request hashes and opaque idempotency IDs live in memory. Nothing is placed in browser storage.
const intents = new Map<
  string,
  { id: string; expires: number; promise?: Promise<any> }
>();
export async function api(
  path: string,
  method = "GET",
  body?: unknown,
  headers: Record<string, string> = {},
) {
  const csrf = document.cookie
    .split("; ")
    .find((x) => x.startsWith("vr_csrf="))
    ?.slice(8);
  const encoded = body === undefined ? undefined : JSON.stringify(body);
  let intentKey: string | undefined,
    intent: { id: string; expires: number; promise?: Promise<any> } | undefined;
  if (method !== "GET") {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(
        method + "|" + path + "|" + csrf + "|" + encoded,
      ),
    );
    intentKey = Array.from(new Uint8Array(digest), (b) =>
      b.toString(16).padStart(2, "0"),
    ).join("");
    for (const [key, value] of intents)
      if (value.expires < Date.now()) intents.delete(key);
    intent = intents.get(intentKey);
    if (intent?.promise) return intent.promise;
    if (!intent) {
      intent = { id: crypto.randomUUID(), expires: Date.now() + 600000 };
      intents.set(intentKey, intent);
    }
  }
  const perform = async () => {
    let response: Response;
    try {
      response = await fetch("/api/v1" + path, {
        method,
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          ...(csrf ? { "X-CSRF-Token": decodeURIComponent(csrf) } : {}),
          ...(intent ? { "Idempotency-Key": intent.id } : {}),
          ...headers,
        },
        ...(encoded === undefined ? {} : { body: encoded }),
      });
    } catch {
      throw new APIError(
        "CONNECTION_FAILED",
        "Connection interrupted. Retry this action to reconcile the same request; an accepted job continues in the background.",
      );
    }
    const value =
      response.status === 204 ? {} : await response.json().catch(() => ({}));
    if (intentKey && (response.ok || response.status < 500))
      intents.delete(intentKey);
    if (!response.ok)
      throw new APIError(
        value.error?.code || "CONNECTION_FAILED",
        value.error?.message ||
          "The controller could not complete this request. Check connectivity and try again.",
      );
    return value;
  };
  const promise = perform();
  if (intent) intent.promise = promise;
  try {
    return await promise;
  } finally {
    if (intent) intent.promise = undefined;
  }
}
export function rows(value: any): any[] {
  return Array.isArray(value)
    ? value
    : value?.items ||
        value?.instances ||
        value?.snapshots ||
        value?.jobs ||
        value?.destinations ||
        value?.hosts ||
        value?.events ||
        [];
}
export const bytes = (n: number | undefined | null) =>
  n == null
    ? "Not measured"
    : new Intl.NumberFormat(undefined, {
        style: "unit",
        unit:
          n >= 1024 ** 3
            ? "gigabyte"
            : n >= 1024 ** 2
              ? "megabyte"
              : "kilobyte",
        maximumFractionDigits: 1,
      }).format(
        n / (n >= 1024 ** 3 ? 1024 ** 3 : n >= 1024 ** 2 ? 1024 ** 2 : 1024),
      );
export function date(value: string | undefined | null, zone?: string) {
  return value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
        timeZone: zone || "UTC",
      }).format(new Date(value))
    : "Not yet";
}
export function age(seconds: number | null | undefined) {
  if (seconds == null) return "No complete capture";
  return seconds < 60
    ? "Captured just now"
    : seconds < 3600
      ? `${Math.floor(seconds / 60)} minutes old`
      : seconds < 86400
        ? `${Math.floor(seconds / 3600)} hours old`
        : `${Math.floor(seconds / 86400)} days old`;
}

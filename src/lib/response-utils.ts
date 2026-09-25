export type ParsedResponseBody = {
  text: string;
  json: unknown | null;
};

export async function parseResponseBody(
  response: Response
): Promise<ParsedResponseBody> {
  const text = await response.text().catch(() => "");
  if (!text) {
    return { text: "", json: null };
  }

  try {
    return { text, json: JSON.parse(text) as unknown };
  } catch {
    return { text, json: null };
  }
}

export function extractErrorMessage(body: ParsedResponseBody): string | null {
  if (body.json && typeof body.json === "object") {
    const json = body.json as Record<string, unknown>;
    const message =
      (typeof json.error === "string" && json.error) ||
      (typeof json.message === "string" && json.message) ||
      (typeof json.detail === "string" && json.detail);
    if (message) return message;
  }

  const text = body.text.trim();
  if (!text) return null;

  // If we got HTML, avoid dumping it into an Error message verbatim.
  if (/^\s*</.test(text)) {
    return null;
  }

  return text.length > 500 ? `${text.slice(0, 500)}…` : text;
}

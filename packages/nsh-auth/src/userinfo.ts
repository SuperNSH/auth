import { AuthError } from "./errors";
import type { ProviderId } from "./providers";
import type { UserInfo } from "./types";

export async function fetchUserInfo(url: string, accessToken: string): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  } catch (error) {
    throw new AuthError("network", `userinfo request failed: ${String(error)}`);
  }
  if (!response.ok) throw new AuthError("unknown", `userinfo failed with status ${response.status}`);
  try {
    return (await response.json()) as Record<string, unknown>;
  } catch {
    throw new AuthError("unknown", "userinfo response is not JSON");
  }
}

export function mapUserInfo(provider: ProviderId, raw: Record<string, unknown>): UserInfo {
  const source = provider === "x" && isRecord(raw.data) ? raw.data : raw;
  const text = (value: unknown): string | undefined => (typeof value === "string" && value ? value : undefined);
  const number = (value: unknown): string | undefined => (typeof value === "number" ? String(value) : undefined);
  const id = text(source.sub) ?? text(source.id) ?? number(source.id) ?? text(source.login);
  if (!id) throw new AuthError("unknown", "no user id in the response");
  const info: UserInfo = { id, raw };
  const name = text(source.name) ?? text(source.username) ?? text(source.login);
  if (name) info.name = name;
  const email = text(source.email);
  if (email) info.email = email;
  const picture = pictureOf(provider, source, id);
  if (picture) info.picture = picture;
  return info;
}

function pictureOf(provider: ProviderId, source: Record<string, unknown>, id: string): string | undefined {
  const text = (value: unknown): string | undefined => (typeof value === "string" && value ? value : undefined);
  if (provider === "facebook") {
    const picture = source.picture;
    if (isRecord(picture) && isRecord(picture.data)) return text(picture.data.url);
    return undefined;
  }
  if (provider === "discord") {
    const avatar = text(source.avatar);
    return avatar ? `https://cdn.discordapp.com/avatars/${id}/${avatar}.png` : undefined;
  }
  return text(source.picture) ?? text(source.avatar_url) ?? text(source.profile_image_url);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

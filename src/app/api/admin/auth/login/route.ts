import { jsonResponse } from "@/lib/api";
import { withErrorHandler } from "@/lib/api-middleware";
import {
  isAdminConfigured,
  isValidAdminSecret,
  createAdminSessionResponse,
} from "@/lib/admin-auth";
import { RateLimitError } from "@/lib/errors";
import { hashClientIp } from "@/lib/security/client-ip";
import { loginRateLimiter } from "@/lib/security/login-limiter";
import { safeJsonParseBody } from "@/lib/safe-json";

export const POST = withErrorHandler(async (req: Request) => {
  if (!isAdminConfigured()) {
    return jsonResponse({ error: "ADMIN_SECRET no configurado" }, { status: 503 });
  }

  const rateCheck = await loginRateLimiter.check(`login:${hashClientIp(req)}`);
  if (!rateCheck.allowed) {
    throw new RateLimitError("Demasiadas solicitudes. Espera 15 minutos.");
  }

  const bodyText = await req.text();
  const parsed = safeJsonParseBody<{ secret?: string }>(bodyText);
  if (!parsed.ok) {
    return jsonResponse({ error: "JSON inválido" }, { status: 400 });
  }

  const secret = String(parsed.data.secret ?? "").trim();
  if (!secret || !isValidAdminSecret(secret)) {
    return jsonResponse({ error: "Clave incorrecta" }, { status: 401 });
  }

  return await createAdminSessionResponse();
});

import { describe, expect, it } from "vitest";
import { getClientIp, hashClientIp } from "@/lib/security/client-ip";

function request(headers: Record<string, string>): Request {
  return new Request("http://localhost/api/admin/auth/login", { headers });
}

describe("getClientIp", () => {
  it("toma el primer hop cuando x-forwarded-for trae varias IPs", () => {
    expect(
      getClientIp(request({ "x-forwarded-for": "1.2.3.4, 10.0.0.1, 10.0.0.2" }))
    ).toBe("1.2.3.4");
  });

  it("recorta espacios alrededor del primer hop", () => {
    expect(getClientIp(request({ "x-forwarded-for": "  1.2.3.4  , 10.0.0.1" }))).toBe(
      "1.2.3.4"
    );
  });

  it("usa x-real-ip cuando falta x-forwarded-for", () => {
    expect(getClientIp(request({ "x-real-ip": "5.6.7.8" }))).toBe("5.6.7.8");
  });

  it("devuelve unknown sin cabeceras de IP", () => {
    expect(getClientIp(request({}))).toBe("unknown");
  });
});

describe("hashClientIp", () => {
  it("devuelve un hash de 16 caracteres y no la IP en claro", () => {
    const hash = hashClientIp(request({ "x-forwarded-for": "1.2.3.4" }));

    expect(hash).toHaveLength(16);
    expect(hash).toMatch(/^[0-9a-f]{16}$/);
    expect(hash).not.toContain("1.2.3.4");
  });

  it("es determinista para la misma IP", () => {
    const headers = { "x-forwarded-for": "1.2.3.4" };

    expect(hashClientIp(request(headers))).toBe(hashClientIp(request(headers)));
  });

  it("produce la misma clave aunque el atacante varíe los hops siguientes", () => {
    const base = hashClientIp(request({ "x-forwarded-for": "1.2.3.4" }));

    expect(hashClientIp(request({ "x-forwarded-for": "1.2.3.4, nonce-1" }))).toBe(base);
    expect(hashClientIp(request({ "x-forwarded-for": "1.2.3.4, nonce-2" }))).toBe(base);
  });

  it("difiere para primeros hops distintos", () => {
    expect(hashClientIp(request({ "x-forwarded-for": "1.2.3.4" }))).not.toBe(
      hashClientIp(request({ "x-forwarded-for": "5.6.7.8" }))
    );
  });
});

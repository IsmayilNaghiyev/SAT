import { getStore } from "@netlify/blobs";

export default async (req) => {
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ verified: false, error: "Method Not Allowed" }), { status: 405 });
  }
  const tok = req.headers.get("x-vault-token") || "";
  if (!/^[a-f0-9]{64}$/.test(tok)) {
    return new Response(JSON.stringify({ verified: false, error: "Invalid SHA-256 token" }), { status: 401 });
  }
  try {
    const b = await req.json();
    const u = (b.user || "").trim().toLowerCase();
    const act = b.action;

    if (!/^[a-z0-9_]{3,20}$/.test(u)) {
      return new Response(JSON.stringify({ verified: false, error: "Invalid username format" }), { status: 400 });
    }
    if (!Array.isArray(b.thrown) || b.thrown.some(x => !Number.isInteger(x) || x < 0 || x > 20000)) {
      return new Response(JSON.stringify({ verified: false, error: "Corrupted ID array" }), { status: 400 });
    }

    const st = getStore("vault-db");
    const key = `u_${u}`;
    const ex = await st.get(key, { type: "json" });

    if (ex && ex.tok !== tok) {
      return new Response(JSON.stringify({ verified: false, error: "Wrong passkey for this username" }), { status: 403 });
    }

    // If 'push', save the exact current list (so restoring/un-throwing a card works).
    // If 'pull', merge cloud and local lists.
    const mrg = act === "push"
      ? Array.from(new Set(b.thrown))
      : (ex ? Array.from(new Set([...ex.thrown, ...b.thrown])) : b.thrown);

    const hst = Array.isArray(b.hist) && b.hist.length ? b.hist.slice(-50) : (ex?.hist || []);
    const rec = { user: u, tok, thrown: mrg, hist: hst, updatedAt: new Date().toISOString() };

    if (act === "push" || !ex) {
      await st.setJSON(key, rec);
    }

    return new Response(
      JSON.stringify({ verified: true, user: u, thrown: rec.thrown, hist: rec.hist, updatedAt: rec.updatedAt }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  } catch (e) {
    return new Response(JSON.stringify({ verified: false, error: e.message }), { status: 500 });
  }
};

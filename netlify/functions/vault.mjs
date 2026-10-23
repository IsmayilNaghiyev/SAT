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
    const act = b.action; // "pull" (login/register) or "push" (save exact state)

    if (!/^[a-z0-9_]{3,20}$/.test(u)) {
      return new Response(JSON.stringify({ verified: false, error: "Username must be 3–20 characters (a-z, 0-9, _)" }), { status: 400 });
    }
    if (!Array.isArray(b.thrown) || b.thrown.some(x => !Number.isInteger(x) || x < 0 || x > 20000)) {
      return new Response(JSON.stringify({ verified: false, error: "Corrupted ID array" }), { status: 400 });
    }

    const st = getStore("vault-db");
    const key = `u_${u}`;
    const ex = await st.get(key, { type: "json" });

    // If account already exists, check that the passkey hash matches
    if (ex && ex.tok !== tok) {
      return new Response(JSON.stringify({ verified: false, error: "Wrong passkey for this username!" }), { status: 403 });
    }

    let finalThrown = [];
    let finalHist = [];
    let isNewAccount = false;

    if (!ex) {
      // Brand-new account registration: start fresh (or save what they explicitly pushed)
      isNewAccount = true;
      finalThrown = act === "push" ? Array.from(new Set(b.thrown)) : [];
      finalHist = act === "push" && Array.isArray(b.hist) ? b.hist.slice(-50) : [];
    } else if (act === "pull") {
      // Logging in / pulling: strictly return ONLY what belongs to this cloud account!
      // NEVER merge local browser data from another user on the same PC.
      finalThrown = Array.isArray(ex.thrown) ? ex.thrown : [];
      finalHist = Array.isArray(ex.hist) ? ex.hist : [];
    } else {
      // Pushing: overwrite cloud state with this user's current exact list
      finalThrown = Array.from(new Set(b.thrown));
      finalHist = Array.isArray(b.hist) ? b.hist.slice(-50) : (ex.hist || []);
    }

    const rec = {
      user: u,
      tok,
      thrown: finalThrown,
      hist: finalHist,
      updatedAt: new Date().toISOString()
    };

    if (act === "push" || isNewAccount) {
      await st.setJSON(key, rec);
    }

    return new Response(
      JSON.stringify({
        verified: true,
        isNewAccount,
        user: u,
        thrown: rec.thrown,
        hist: rec.hist,
        updatedAt: rec.updatedAt
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  } catch (e) {
    return new Response(JSON.stringify({ verified: false, error: e.message }), { status: 500 });
  }
};

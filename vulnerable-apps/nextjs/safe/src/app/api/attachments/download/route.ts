import { NextResponse } from "next/server";
import { promises as fs } from "fs";
import path from "path";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const UPLOAD_DIR = path.join(process.cwd(), "uploads");

// FIXED TRAVERSAL-001: the resolved path must stay inside the upload directory.
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("name") ?? "";
  const resolved = path.resolve(UPLOAD_DIR, name);
  if (resolved !== UPLOAD_DIR && !resolved.startsWith(UPLOAD_DIR + path.sep)) {
    return NextResponse.json({ error: "invalid path" }, { status: 400 });
  }
  try {
    const data = await fs.readFile(resolved);
    return new NextResponse(data, { headers: { "content-type": "application/octet-stream" } });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 404 });
  }
}

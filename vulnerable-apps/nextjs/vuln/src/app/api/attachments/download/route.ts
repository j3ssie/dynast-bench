import { NextResponse } from "next/server";
import { promises as fs } from "fs";
import path from "path";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const UPLOAD_DIR = path.join(process.cwd(), "uploads");

// VULN TRAVERSAL-001 (CWE-22): the user-supplied filename is joined onto the
// upload dir with no containment check, so `name=../../../../etc/passwd` escapes
// the directory and reads arbitrary files.
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("name") ?? "";
  const filePath = path.join(UPLOAD_DIR, name);
  try {
    const data = await fs.readFile(filePath);
    return new NextResponse(data, { headers: { "content-type": "application/octet-stream" } });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 404 });
  }
}

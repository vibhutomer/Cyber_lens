import { NextFunction, Request, Response } from "express";
import pool from "../db";
import { OwnerContext } from "../constants/owner";

const UUID_V4_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

async function ensureAnonymousClient(clientId: string): Promise<void> {
  await pool.query(
    `
    INSERT INTO anonymous_clients (id)
    VALUES ($1)
    ON CONFLICT (id)
    DO UPDATE SET last_seen = NOW()
    `,
    [clientId],
  );
}

async function resolveOwner(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  // Allow CORS preflight without requiring identity
  if (req.method === "OPTIONS") {
    return next();
  }

  const clientId = req.header("X-Client-ID");

  if (!clientId || !UUID_V4_REGEX.test(clientId)) {
    res.status(400).json({ error: "Invalid or missing X-Client-ID header" });
    return;
  }

  try {
    await ensureAnonymousClient(clientId);
    req.owner = { type: "anonymous", id: clientId };
    next();
  } catch (error) {
    console.error("Failed to resolve owner", error);
    res.status(500).json({ error: "Failed to resolve owner" });
  }
}

export default resolveOwner;

declare global {
  namespace Express {
    interface Request {
      owner: OwnerContext;
    }
  }
}

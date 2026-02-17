import { z } from "zod";
import { Request, Response, NextFunction } from "express";

// ─── Common validators (use these in your routes) ────────────────
export const schemas = {
  id: z.string().regex(/^[a-zA-Z0-9_-]+$/, "Invalid ID format").max(128),
  email: z.string().email().max(254).toLowerCase().trim(),
  url: z.string().url().max(2048),
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  search: z
    .string()
    .max(200)
    .trim()
    .transform((s) => s.replace(/[<>'"`;]/g, "")),
};

// ─── Middleware factory: validate body/query/params ───────────────
// Usage:
//   router.post("/users", validate({ body: createUserSchema }), handler)
//   router.get("/users/:id", validate({ params: z.object({ id: schemas.id }) }), handler)

interface ValidationTarget {
  body?: z.ZodTypeAny;
  query?: z.ZodTypeAny;
  params?: z.ZodTypeAny;
}

export function validate(target: ValidationTarget) {
  return (req: Request, _res: Response, next: NextFunction) => {
    try {
      if (target.body) {
        req.body = target.body.parse(req.body);
      }
      if (target.query) {
        (req as any).query = target.query.parse(req.query);
      }
      if (target.params) {
        req.params = target.params.parse(req.params);
      }
      next();
    } catch (err) {
      next(err); // Caught by errorHandler → 400 with details
    }
  };
}

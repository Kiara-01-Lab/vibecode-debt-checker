import { Router } from "express";
import { z } from "zod";
import { validate, schemas } from "../middleware/validate";
import { AppError } from "../middleware/errorHandler";

const router = Router();

// ─── In-memory store — replace with your DB ──────────────────────
interface Item {
  id: string;
  name: string;
  createdAt: string;
}

const items = new Map<string, Item>();

// ─── Schemas ─────────────────────────────────────────────────────
const createItemSchema = z.object({
  name: z.string().min(1, "Name is required").max(200).trim(),
});

const itemParamsSchema = z.object({ id: schemas.id });

// ─── Routes ──────────────────────────────────────────────────────
router.get("/items", (_req, res) => {
  res.json({ items: Array.from(items.values()) });
});

router.get(
  "/items/:id",
  validate({ params: itemParamsSchema }),
  (req, res) => {
    const item = items.get(req.params.id);
    if (!item) throw new AppError(404, "Item not found");
    res.json(item);
  }
);

router.post(
  "/items",
  validate({ body: createItemSchema }),
  (req, res) => {
    const id = Math.random().toString(36).slice(2, 10);
    const item: Item = {
      id,
      name: req.body.name,
      createdAt: new Date().toISOString(),
    };
    items.set(id, item);
    res.status(201).json(item);
  }
);

router.delete(
  "/items/:id",
  validate({ params: itemParamsSchema }),
  (req, res) => {
    if (!items.has(req.params.id)) throw new AppError(404, "Item not found");
    items.delete(req.params.id);
    res.status(204).send();
  }
);

export default router;

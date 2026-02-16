import { Request, Response, NextFunction } from "express";
import { ZodError } from "zod";
import { log } from "../utils/logger";

// Custom error class for your routes
export class AppError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public isOperational = true
  ) {
    super(message);
    this.name = "AppError";
  }
}

// Catch-all error handler — mount LAST in middleware chain
export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction
) {
  // Zod validation errors → 400
  if (err instanceof ZodError) {
    log.warn("validation_error", {
      path: req.path,
      issues: err.issues.map((i) => ({
        field: i.path.join("."),
        message: i.message,
      })),
    });

    res.status(400).json({
      error: "Validation failed",
      details: err.issues.map((i) => ({
        field: i.path.join("."),
        message: i.message,
      })),
    });
    return;
  }

  // Known operational errors → use their status code
  if (err instanceof AppError && err.isOperational) {
    log.warn("app_error", {
      path: req.path,
      status: err.statusCode,
      message: err.message,
    });

    res.status(err.statusCode).json({
      error: err.message,
    });
    return;
  }

  // Everything else → 500, log full error, return safe message
  log.error("unhandled_error", {
    path: req.path,
    error: err.message,
    stack: process.env.NODE_ENV !== "production" ? err.stack : undefined,
  });

  res.status(500).json({
    error: "Something went wrong",
    // Never leak stack traces in production
    ...(process.env.NODE_ENV !== "production" && {
      debug: err.message,
    }),
  });
}

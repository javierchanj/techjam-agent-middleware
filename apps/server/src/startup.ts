import type { FastifyInstance } from "fastify";
import type { Warden } from "./warden/index.js";

/**
 * Starts the public listener and disposes resources already created during
 * startup if binding fails (for example, EADDRINUSE). Cleanup failures must not
 * hide the original startup error.
 */
export async function listenWithCleanup(
  app: FastifyInstance,
  warden: Pick<Warden, "stop"> | null,
  options: { host: string; port: number },
): Promise<void> {
  try {
    await app.listen(options);
  } catch (error) {
    await Promise.allSettled([
      app.close(),
      ...(warden ? [warden.stop()] : []),
    ]);
    throw error;
  }
}

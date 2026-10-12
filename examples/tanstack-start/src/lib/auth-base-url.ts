/**
 * Site origin. Single-sourced here so the engines and (later) the
 * request middleware share it without importing server-only modules.
 */
export const exampleBaseURL = process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3200'

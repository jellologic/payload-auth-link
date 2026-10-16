// Stand-in for the `payload` peer: Payload's own `.d.ts` does not pass
// `skipLibCheck: false`, and this fixture checks OUR declarations, not
// upstream's. Only the names migrate's types reference.
export type Payload = { readonly config: unknown }

/**
 * Denied marker for the server-guarded admin page. The `admin-denied`
 * testid is a cross-framework contract with the shared e2e suite (the
 * TanStack example renders the same testid from its route
 * `notFoundComponent`), so the suite asserts the marker our code
 * renders rather than either framework's default 404 text.
 */
export default function AdminDenied() {
  return (
    <main>
      <p data-testid="admin-denied">This page could not be found.</p>
    </main>
  )
}

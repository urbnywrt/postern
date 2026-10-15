import { Navigate, useLocation } from "react-router";

import { isUnauthenticated } from "../api/errors";
import { useMe } from "../api/hooks/auth";
import { AppShell } from "./AppShell";
import { FullPageLoader } from "./FullPageLoader";
import { LoadError } from "./LoadError";

/**
 * The guard of every page that needs a session. It asks the panel who is signed
 * in (AuthService.Me): a visitor goes to the login page and comes back to this
 * page after signing in; a signed-in admin gets the page inside the app shell.
 */
export function RequireAuth() {
  const me = useMe();
  const location = useLocation();

  // This holds when the session ends while a page is open, too: the query is
  // asked again (see queryClient.ts) and the answer is a 401.
  if (me.isError && isUnauthenticated(me.error)) {
    return <Navigate to="/login" replace state={{ from: `${location.pathname}${location.search}` }} />;
  }
  if (me.isPending) {
    return <FullPageLoader />;
  }
  // A failed refresh does not take the page away from an admin who has it.
  if (me.isError && me.data === undefined) {
    return (
      <LoadError
        error={me.error}
        onRetry={() => {
          void me.refetch();
        }}
      />
    );
  }
  return <AppShell />;
}

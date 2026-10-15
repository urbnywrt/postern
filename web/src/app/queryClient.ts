import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";

import { isUnauthenticated } from "../api/errors";
import { authKeys } from "../api/hooks/auth";
import { notifyError } from "./notify";

/** What a query or a mutation says about itself, for the handling of its errors. */
export interface CallMeta extends Record<string, unknown> {
  /** The page that asked shows the error, so it is not shown as a notification. */
  silent?: boolean;
  /** The call is made without a session, so a 401 is its answer, not the end of a session. */
  anonymous?: boolean;
}

declare module "@tanstack/react-query" {
  interface Register {
    queryMeta: CallMeta;
    mutationMeta: CallMeta;
  }
}

/**
 * The client of every query and mutation of the panel UI. It is the one place
 * where a failed call is shown to the admin:
 *
 *  - the error is a notification with the message of the panel, unless the call
 *    says it is `silent`;
 *  - a 401 from a call that needs a session means that the session has ended
 *    (it expired, or the password was changed elsewhere): the "who am I" query is
 *    asked again, and the route guard sends the admin to the login page.
 */
export function createQueryClient(): QueryClient {
  const handle = (error: unknown, meta: CallMeta | undefined) => {
    if (isUnauthenticated(error) && meta?.anonymous !== true) {
      void client.invalidateQueries({ queryKey: authKeys.me });
    }
    if (meta?.silent !== true) {
      notifyError(error);
    }
  };

  const client: QueryClient = new QueryClient({
    queryCache: new QueryCache({
      onError: (error, query) => {
        handle(error, query.meta);
      },
    }),
    mutationCache: new MutationCache({
      onError: (error, _variables, _onMutateResult, mutation) => {
        handle(error, mutation.meta);
      },
    }),
    defaultOptions: {
      // A failed call is shown, and the admin tries again: no silent retries.
      queries: { retry: false },
      // A mutation is sent with a password or a code, and answers with a TOTP
      // secret. By default the cache keeps it for five minutes after the form
      // that made it is gone: with `gcTime: 0` it is dropped when nothing
      // observes it any more (a form that is open still has its state).
      mutations: { retry: false, gcTime: 0 },
    },
  });
  return client;
}

import { create } from "@bufbuild/protobuf";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { AuthService, GetSetupStatusResponseSchema } from "../../gen/postern/panel/v1/auth_pb";
import { useClient } from "../client";

export const authKeys = {
  me: ["auth", "me"] as const,
  setupStatus: ["auth", "setupStatus"] as const,
};

// `anonymous` marks a call that is made without a session: a 401 is its answer,
// not a sign that a session has ended. `silent` keeps an error out of the
// notifications; the page that asked shows it. See app/queryClient.ts.

/** The signed-in admin. A visitor gets a 401, which the route guard turns into the login page. */
export function useMe() {
  const auth = useClient(AuthService);
  return useQuery({
    queryKey: authKeys.me,
    queryFn: ({ signal }) => auth.me({}, { signal }),
    staleTime: 30_000,
    meta: { anonymous: true, silent: true },
  });
}

/** Whether the panel still waits for its first admin. */
export function useSetupStatus() {
  const auth = useClient(AuthService);
  return useQuery({
    queryKey: authKeys.setupStatus,
    queryFn: ({ signal }) => auth.getSetupStatus({}, { signal }),
    staleTime: 60_000,
    meta: { anonymous: true, silent: true },
  });
}

export function useSetup() {
  const auth = useClient(AuthService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vars: { setupToken: string; username: string; password: string }) => auth.setup(vars),
    meta: { anonymous: true },
    onSuccess: () => {
      // The panel has an admin now.
      queryClient.setQueryData(
        authKeys.setupStatus,
        create(GetSetupStatusResponseSchema, { needsSetup: false }),
      );
    },
  });
}

export interface LoginVars {
  username: string;
  password: string;
  /** Left out on the first call: the response says whether the admin has to give one. */
  totpCode?: string;
}

export function useLogin() {
  const auth = useClient(AuthService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ username, password, totpCode = "" }: LoginVars) =>
      auth.login({ username, password, totpCode }),
    meta: { anonymous: true },
    onSuccess: async (response) => {
      if (!response.totpRequired) {
        // The session cookie is set. Ask who is signed in: the login page leaves
        // as soon as the answer is there.
        await queryClient.invalidateQueries({ queryKey: authKeys.me });
      }
    },
  });
}

export function useLogout() {
  const auth = useClient(AuthService);
  return useMutation({
    mutationFn: () => auth.logout({}),
    // A session that is gone already is what a sign-out is for.
    meta: { anonymous: true, silent: true },
  });
}

export function useChangePassword() {
  const auth = useClient(AuthService);
  return useMutation({
    mutationFn: (vars: { currentPassword: string; newPassword: string; totpCode: string }) =>
      auth.changePassword(vars),
  });
}

export function useBeginTotp() {
  const auth = useClient(AuthService);
  return useMutation({ mutationFn: () => auth.beginTotp({}) });
}

export function useConfirmTotp() {
  const auth = useClient(AuthService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vars: { code: string; password: string }) => auth.confirmTotp(vars),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: authKeys.me }),
  });
}

export function useDisableTotp() {
  const auth = useClient(AuthService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vars: { password: string; code: string }) => auth.disableTotp(vars),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: authKeys.me }),
  });
}

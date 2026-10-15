import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { type PublicPage, PublicPageSchema, PublicPageService } from "../../gen/postern/panel/v1/publicpage_pb";
import { present } from "../answer";
import { useClient } from "../client";
import { publicPageKeys } from "./keys";

/** The configuration of the public page, items included. */
export function usePublicPage() {
  const service = useClient(PublicPageService);
  return useQuery({
    queryKey: publicPageKeys.all,
    queryFn: async ({ signal }) => present((await service.getPublicPage({}, { signal })).page),
    meta: { silent: true },
  });
}

/**
 * What the form sends: the whole page. Every field is set, the switches included:
 * `allowIndexing` left out would read as false on the panel, which is the safe
 * default, but a form must say what it means.
 */
export type PublicPageVars = Required<Omit<MessageInitShape<typeof PublicPageSchema>, "$typeName" | "$unknown">>;

/**
 * Replaces the configuration of the page. The form shows the refusal of the panel
 * in place (an admin host, a text that is too long), so it is `silent`.
 */
export function useUpdatePublicPage() {
  const service = useClient(PublicPageService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (vars: PublicPageVars): Promise<PublicPage> =>
      present((await service.updatePublicPage({ page: create(PublicPageSchema, vars) })).page),
    onSuccess: (page) => {
      queryClient.setQueryData(publicPageKeys.all, page);
    },
    meta: { silent: true },
  });
}

/**
 * Checks the stored host of the page as a visitor reaches it: its DNS and its
 * HTTPS. The form shows the result, and a failure, in place, so it is `silent`.
 */
export function useCheckPublicPage() {
  const service = useClient(PublicPageService);
  return useMutation({
    mutationFn: async () => service.checkPublicPage({}),
    meta: { silent: true },
  });
}

import type { MessageInitShape } from "@bufbuild/protobuf";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { SettingsService, type StatsSettingsSchema } from "../../gen/postern/panel/v1/settings_pb";
import { useClient } from "../client";
import { metricsKeys, settingsKeys } from "./keys";

/** The settings of the statistics, and the addresses that the nodes see the panel come from. */
export function useStatsSettings() {
  const settings = useClient(SettingsService);
  return useQuery({
    queryKey: settingsKeys.stats,
    queryFn: ({ signal }) => settings.getStatsSettings({}, { signal }),
    meta: { silent: true },
  });
}

/** What the form sends: every setting, as UpdateStatsSettings stores them as a whole. */
export type StatsSettingsVars = Required<Omit<MessageInitShape<typeof StatsSettingsSchema>, "$typeName" | "$unknown">>;

/**
 * Stores the settings as a whole. A new IP policy deletes what it does not keep,
 * so every statistic shown is asked for again, and the size of the database too.
 * The form shows a refusal in place, so it is `silent`.
 */
export function useUpdateStatsSettings() {
  const settings = useClient(SettingsService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vars: StatsSettingsVars) => settings.updateStatsSettings({ settings: vars }),
    onSuccess: (answer) => {
      queryClient.setQueryData(settingsKeys.stats, answer);
      void queryClient.invalidateQueries({ queryKey: metricsKeys.all });
      void queryClient.invalidateQueries({ queryKey: settingsKeys.storage });
    },
    meta: { silent: true },
  });
}

/** How much room the database takes: its file, its free pages, and the rows of the tables that grow. */
export function useStorage() {
  const settings = useClient(SettingsService);
  return useQuery({
    queryKey: settingsKeys.storage,
    queryFn: ({ signal }) => settings.getStorage({}, { signal }),
    meta: { silent: true },
  });
}

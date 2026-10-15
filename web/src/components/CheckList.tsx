import { Stack, Text, Title } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { groupByLayer, isLayer } from "../app/diagnostics";
import type { CheckResult } from "../gen/postern/panel/v1/diagnostics_pb";
import { CheckRow } from "./CheckRow";
import { FixDialog, type FixOffer } from "./FixDialog";

/**
 * Results of checks, grouped by layer along the path of a connection, with the
 * confirmation of a fix. `offeredRunId` is the run that the results are of ("" for
 * the light checks): the panel takes it as the check before the fix.
 */
export function CheckList({ results, nodeId, offeredRunId }: { results: CheckResult[]; nodeId: string; offeredRunId: string }) {
  const { t } = useTranslation();
  const [offer, setOffer] = useState<FixOffer | null>(null);

  return (
    <Stack gap="md">
      {groupByLayer(results).map((group) => (
        <Stack key={group.layer} gap="xs">
          <Title order={4} size="h5">
            {isLayer(group.layer) ? t(`insights.diagnostics.layer.${group.layer}`) : group.layer}
          </Title>
          {group.results.map((result) => (
            <CheckRow
              key={`${result.id} ${result.target}`}
              result={result}
              onFix={(chosen) => {
                setOffer({ nodeId, checkId: chosen.id, target: chosen.target, fix: chosen.fix, offeredRunId });
              }}
            />
          ))}
        </Stack>
      ))}
      {results.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("insights.diagnostics.noResults")}
        </Text>
      ) : null}
      <FixDialog
        offer={offer}
        onClose={() => {
          setOffer(null);
        }}
      />
    </Stack>
  );
}

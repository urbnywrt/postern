import { Alert, Button, Stack, Text } from "@mantine/core";
import type { UseQueryResult } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage, isNotFound } from "../api/errors";
import { PageLoader } from "./PageLoader";

interface QueryViewProps<T> {
  query: UseQueryResult<T>;
  /** The page, given the data. */
  children: (data: T) => ReactNode;
  /** Shown instead of the error when the panel says there is no such thing. */
  notFound?: ReactNode;
}

/**
 * What a page shows of a query: a spinner while there is nothing, the error with
 * a way to try again when the first load failed, and the data otherwise. A load
 * that fails while the page has data (the panel is asked again every few seconds)
 * keeps the page and says that it may be out of date, instead of taking it away.
 */
export function QueryView<T>({ query, children, notFound }: QueryViewProps<T>) {
  const { t } = useTranslation();

  if (query.data === undefined) {
    if (query.isError) {
      if (notFound !== undefined && isNotFound(query.error)) {
        return <>{notFound}</>;
      }
      return (
        <Alert color="red" title={t("errors.loadTitle")} maw={560}>
          <Stack gap="xs" align="flex-start">
            <Text size="sm">{errorMessage(query.error)}</Text>
            <Button
              variant="light"
              size="xs"
              onClick={() => {
                void query.refetch();
              }}
            >
              {t("common.retry")}
            </Button>
          </Stack>
        </Alert>
      );
    }
    return <PageLoader />;
  }

  return (
    <Stack gap="md">
      {query.isError ? (
        <Alert color="yellow" role="status">
          {t("errors.stale")}
        </Alert>
      ) : null}
      {children(query.data)}
    </Stack>
  );
}

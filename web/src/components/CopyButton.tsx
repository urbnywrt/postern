import { ActionIcon, Tooltip } from "@mantine/core";
import { useTimeout } from "@mantine/hooks";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useCopy } from "../app/clipboard";
import { CheckIcon, CopyIcon } from "./icons";

/** Copies `value` to the clipboard and says so; the icon shows a check for a moment. */
export function CopyButton({ value, label }: { value: string; label?: string }) {
  const { t } = useTranslation();
  const copy = useCopy();
  const [copied, setCopied] = useState(false);
  const { start } = useTimeout(() => {
    setCopied(false);
  }, 1500);
  const text = label ?? t("common.copy");

  return (
    <Tooltip label={text}>
      <ActionIcon
        variant="subtle"
        color={copied ? "teal" : "gray"}
        aria-label={text}
        onClick={() => {
          void copy(value).then((done) => {
            if (done) {
              setCopied(true);
              start();
            }
          });
        }}
      >
        {copied ? <CheckIcon /> : <CopyIcon />}
      </ActionIcon>
    </Tooltip>
  );
}

import { SegmentedControl } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { isLanguage, LANGUAGES, setLanguage } from "../i18n";

const options = LANGUAGES.map((language) => ({ value: language, label: language.toUpperCase() }));

export function LanguageSwitcher() {
  const { t, i18n } = useTranslation();
  const current = isLanguage(i18n.resolvedLanguage) ? i18n.resolvedLanguage : "en";

  return (
    <SegmentedControl
      size="xs"
      aria-label={t("common.language")}
      data={options}
      value={current}
      onChange={(value) => {
        if (isLanguage(value)) {
          void setLanguage(value);
        }
      }}
    />
  );
}

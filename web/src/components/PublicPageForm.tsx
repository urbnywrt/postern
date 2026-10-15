import { Code, ConnectError } from "@connectrpc/connect";
import {
  ActionIcon,
  Alert,
  Anchor,
  Button,
  Group,
  Paper,
  Select,
  Stack,
  Switch,
  Text,
  Textarea,
  TextInput,
  Title,
} from "@mantine/core";
import type { UseQueryResult } from "@tanstack/react-query";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { useProxies } from "../api/hooks/proxies";
import { type PublicPageVars, usePublicPage, useUpdatePublicPage } from "../api/hooks/publicpage";
import { notifySuccess } from "../app/notify";
import { useFormState } from "../app/useFormState";
import { isValidHostName } from "../app/validators";
import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";
import type { PublicPage } from "../gen/postern/panel/v1/publicpage_pb";
import { ConfirmDialog } from "./ConfirmDialog";
import { PublicPageCheck } from "./PublicPageCheck";
import { QueryView } from "./QueryView";

// The limits of PublicPageService (proto/postern/panel/v1/publicpage.proto). The
// panel checks them again; the form only saves a round trip and says what is wrong.
const MAX_TITLE_BYTES = 120;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_FOOTER_BYTES = 300;
const MAX_CODE_CHARS = 4;
const MAX_PUBLIC_NAME_CHARS = 64;
const MAX_PUBLIC_NOTE_CHARS = 280;
const MAX_ITEMS = 100;

const byteLength = (text: string) => new TextEncoder().encode(text).length;
/** Code points, not UTF-16 units: the panel counts runes. */
const charCount = (text: string) => Array.from(text).length;

/**
 * The host of the public page: a DNS name of at least two labels, not an IP
 * address, without a scheme, port, path or dot at the end. Empty is no host.
 */
function isValidPublicHost(host: string): boolean {
  return isValidHostName(host) && host.includes(".");
}

/** The code of an item as the panel takes it: up to four ASCII letters and digits. */
const CODE = new RegExp(`^[A-Za-z0-9]{0,${String(MAX_CODE_CHARS)}}$`);

/**
 * The title as it is sent: one line, or two, each without the spaces around it. A
 * title of more than two lines is refused (titleError) before it is sent.
 */
function titleLines(title: string): string {
  return title
    .trim()
    .split("\n")
    .map((line) => line.trim())
    .join("\n");
}

interface Item {
  proxyId: string;
  publicName: string;
  publicNote: string;
  code: string;
  /** What the page shows while the code is empty, by the panel's GeoIP database; "" for unknown. */
  country: string;
}

interface Values {
  host: string;
  title: string;
  bodyMd: string;
  footer: string;
  unavailable: string;
  defaultLocale: string;
}

/** Settings: the public page. Loads what is stored and hands it to the editor. */
export function PublicPageForm() {
  const { t } = useTranslation();
  const titleId = useId();
  const page = usePublicPage();
  const proxies = useProxies();

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId} mb="xs">
        {t("insights.publicPage.title")}
      </Title>
      <Text size="sm" c="dimmed" mb="sm">
        {t("insights.publicPage.intro")}
      </Text>
      <QueryView query={page}>{(stored) => <Editor stored={stored} proxiesQuery={proxies} />}</QueryView>
    </Paper>
  );
}

/** What a proxy is called where the admin picks one: its name, else its domain. */
function proxyLabel(proxy: Proxy): string {
  return proxy.name.trim() === "" ? proxy.domain : `${proxy.name} — ${proxy.domain}`;
}

function Editor({ stored, proxiesQuery }: { stored: PublicPage; proxiesQuery: UseQueryResult<Proxy[]> }) {
  const { t } = useTranslation();
  const proxies = proxiesQuery.data ?? [];
  const update = useUpdatePublicPage();
  // What the form started from, and then what it last saved: the question before the
  // page goes public is asked when it was off here and is on in the form.
  const [baseline, setBaseline] = useState(stored);
  const [enabled, setEnabled] = useState(stored.enabled);
  const [allowIndexing, setAllowIndexing] = useState(stored.allowIndexing);
  const [items, setItems] = useState<Item[]>(
    stored.items.map(({ proxyId, publicName, publicNote, code, country }) => ({ proxyId, publicName, publicNote, code, country })),
  );
  const [pick, setPick] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  // Why the last save failed. A refusal of the panel (INVALID_ARGUMENT: an admin host, a
  // text that is too long) is shown in place for as long as the host it was sent with is
  // in the field; any other failure (the network, the panel's database) until the next save.
  const [refusal, setRefusal] = useState<{ host: string; message: string; refused: boolean } | null>(null);

  const form = useFormState<Values>({
    host: stored.host,
    title: stored.title,
    bodyMd: stored.bodyMd,
    footer: stored.footer,
    unavailable: stored.unavailable === "" ? "mark" : stored.unavailable,
    defaultLocale: stored.defaultLocale === "" ? "ru" : stored.defaultLocale,
  });
  const { values, submitted } = form;
  const fields = form.check({});

  // ---- what is wrong, in words --------------------------------------------------
  const host = values.host.trim();
  const hostError =
    host === ""
      ? enabled
        ? t("insights.publicPage.validation.hostRequired")
        : undefined
      : isValidPublicHost(host)
        ? undefined
        : t("insights.publicPage.validation.host");
  const title = titleLines(values.title);
  const titleError =
    title.split("\n").length > 2
      ? t("insights.publicPage.validation.titleLines")
      : byteLength(title) > MAX_TITLE_BYTES
        ? t("insights.publicPage.validation.bytesLong", { max: MAX_TITLE_BYTES })
        : undefined;
  const footerError =
    byteLength(values.footer.trim()) > MAX_FOOTER_BYTES
      ? t("insights.publicPage.validation.bytesLong", { max: MAX_FOOTER_BYTES })
      : undefined;
  const bodyError =
    byteLength(values.bodyMd) > MAX_BODY_BYTES
      ? t("insights.publicPage.validation.bytesLong", { max: MAX_BODY_BYTES })
      : undefined;
  const itemsError = items.length > MAX_ITEMS ? t("insights.publicPage.validation.tooMany", { max: MAX_ITEMS }) : undefined;
  const nameError = (item: Item) =>
    charCount(item.publicName.trim()) > MAX_PUBLIC_NAME_CHARS
      ? t("validation.textLong", { max: MAX_PUBLIC_NAME_CHARS })
      : undefined;
  const codeError = (item: Item) =>
    CODE.test(item.code.trim()) ? undefined : t("insights.publicPage.validation.code", { max: MAX_CODE_CHARS });
  const noteError = (item: Item) =>
    charCount(item.publicNote.trim()) > MAX_PUBLIC_NOTE_CHARS
      ? t("validation.textLong", { max: MAX_PUBLIC_NOTE_CHARS })
      : undefined;
  const valid =
    [hostError, titleError, bodyError, footerError, itemsError].every((error) => error === undefined) &&
    items.every((item) => nameError(item) === undefined && noteError(item) === undefined && codeError(item) === undefined);
  const shown = (error: string | undefined) => (submitted ? error : undefined);

  // ---- the items ------------------------------------------------------------------
  const listed = new Set(items.map((item) => item.proxyId));
  const candidates = proxies.filter((proxy) => !listed.has(proxy.id));
  /** What the buttons of a row call its item: the public name, else the domain of its proxy, else the id. */
  const nameOf = (item: Item) => {
    const name = item.publicName.trim();
    if (name !== "") {
      return name;
    }
    const domain = proxies.find((proxy) => proxy.id === item.proxyId)?.domain ?? "";
    return domain === "" ? item.proxyId : domain;
  };

  function add() {
    const proxy = proxies.find((entry) => entry.id === pick);
    if (proxy === undefined || listed.has(proxy.id)) {
      return;
    }
    setItems((current) => [
      ...current,
      { proxyId: proxy.id, publicName: proxy.name.trim() || proxy.domain, publicNote: "", code: "", country: "" },
    ]);
    setPick(null);
  }

  function move(index: number, by: -1 | 1) {
    setItems((current) => {
      const target = index + by;
      if (target < 0 || target >= current.length) {
        return current;
      }
      const next = [...current];
      const [item] = next.splice(index, 1);
      if (item === undefined) {
        return current;
      }
      next.splice(target, 0, item);
      return next;
    });
  }

  function remove(index: number) {
    setItems((current) => current.filter((_item, at) => at !== index));
  }

  function edit(index: number, change: Partial<Item>) {
    setItems((current) => current.map((item, at) => (at === index ? { ...item, ...change } : item)));
  }

  // ---- saving ---------------------------------------------------------------------
  function payload(): PublicPageVars {
    return {
      enabled,
      host,
      title,
      bodyMd: values.bodyMd,
      footer: values.footer.trim(),
      unavailable: values.unavailable,
      defaultLocale: values.defaultLocale,
      items: items.map((item) => ({
        proxyId: item.proxyId,
        publicName: item.publicName.trim(),
        publicNote: item.publicNote.trim(),
        code: item.code.trim().toUpperCase(),
      })),
      // Always sent: left out, the panel reads it as false, and the form must say what it means.
      allowIndexing,
    };
  }

  function submit() {
    if (update.isPending) {
      return;
    }
    form.setSubmitted(true);
    if (!valid) {
      return;
    }
    if (enabled && !baseline.enabled) {
      setConfirming(true);
      return;
    }
    void send();
  }

  async function send() {
    setConfirming(false);
    setRefusal(null);
    try {
      const saved = await update.mutateAsync(payload());
      setBaseline(saved);
      setRefusal(null);
      notifySuccess(t("insights.publicPage.saved"));
    } catch (error) {
      setRefusal({
        host: values.host,
        message: errorMessage(error),
        refused: error instanceof ConnectError && error.code === Code.InvalidArgument,
      });
    }
  }

  const servedAt = baseline.enabled && baseline.host !== "" ? `https://${baseline.host}/` : null;

  return (
    <form
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      <Stack gap="sm">
        <Alert color="yellow" role="note">
          {t("insights.publicPage.warning")}
        </Alert>
        <Switch
          label={t("insights.publicPage.enabled")}
          description={t("insights.publicPage.enabledHint")}
          checked={enabled}
          onChange={(event) => {
            setEnabled(event.currentTarget.checked);
          }}
        />
        {servedAt !== null ? (
          <Text size="sm">
            {t("insights.publicPage.link")}{" "}
            <Anchor href={servedAt} target="_blank" rel="noopener noreferrer" aria-label={t("insights.publicPage.openLink")}>
              {servedAt}
            </Anchor>
          </Text>
        ) : null}
        <TextInput
          label={t("insights.publicPage.host")}
          description={t("insights.publicPage.hostHint")}
          autoComplete="off"
          spellCheck={false}
          {...fields.bind("host")}
          error={shown(hostError)}
        />
        {baseline.host !== "" ? (
          // The panel checks the host it has stored, so the check follows what was saved.
          <PublicPageCheck
            host={baseline.host}
            autoRun={stored.enabled && stored.host !== ""}
            unsaved={host !== baseline.host}
          />
        ) : null}
        <Textarea
          label={t("insights.publicPage.pageTitle")}
          description={t("insights.publicPage.pageTitleHint")}
          autoComplete="off"
          autosize
          minRows={1}
          maxRows={2}
          {...fields.bind("title")}
          error={shown(titleError)}
        />
        <Textarea
          label={t("insights.publicPage.body")}
          description={t("insights.publicPage.bodyHint")}
          autosize
          minRows={3}
          maxRows={12}
          {...fields.bind("bodyMd")}
          error={shown(bodyError)}
        />
        <Textarea
          label={t("insights.publicPage.footer")}
          description={t("insights.publicPage.footerHint")}
          autosize
          minRows={2}
          maxRows={6}
          {...fields.bind("footer")}
          error={shown(footerError)}
        />
        <Select
          label={t("insights.publicPage.unavailable")}
          description={t("insights.publicPage.unavailableHint")}
          data={[
            { value: "mark", label: t("insights.publicPage.unavailableMark") },
            { value: "hide", label: t("insights.publicPage.unavailableHide") },
          ]}
          allowDeselect={false}
          {...fields.bindSelect("unavailable")}
        />
        <Switch
          label={t("insights.publicPage.allowIndexing")}
          description={t("insights.publicPage.allowIndexingHint")}
          checked={allowIndexing}
          onChange={(event) => {
            setAllowIndexing(event.currentTarget.checked);
          }}
        />
        <Select
          label={t("insights.publicPage.defaultLocale")}
          description={t("insights.publicPage.defaultLocaleHint")}
          data={[
            { value: "ru", label: "Русский" },
            { value: "en", label: "English" },
          ]}
          allowDeselect={false}
          {...fields.bindSelect("defaultLocale")}
        />

        <Stack gap="xs">
          <div>
            <Text component="h3" size="sm" fw={500}>
              {t("insights.publicPage.items")}
            </Text>
            <Text size="xs" c="dimmed">
              {t("insights.publicPage.itemsHint")}
            </Text>
          </div>
          {items.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("insights.publicPage.noItems")}
            </Text>
          ) : (
            <Stack component="ul" role="list" gap="xs" p={0} m={0} style={{ listStyle: "none" }}>
              {items.map((item, index) => (
                <Paper component="li" key={item.proxyId} withBorder p="sm" radius="sm">
                  <Group align="flex-start" wrap="nowrap" gap="sm">
                    <Stack gap="xs" style={{ flex: 1 }}>
                      <Group align="flex-end" wrap="nowrap" gap="sm">
                        <TextInput
                          label={t("insights.publicPage.code")}
                          description={t("insights.publicPage.codeHint")}
                          placeholder={item.country === "" ? t("insights.publicPage.codeAuto") : item.country}
                          autoComplete="off"
                          spellCheck={false}
                          w={150}
                          value={item.code}
                          error={shown(codeError(item))}
                          onChange={(event) => {
                            edit(index, { code: event.currentTarget.value });
                          }}
                        />
                        <TextInput
                          label={t("insights.publicPage.publicName")}
                          autoComplete="off"
                          value={item.publicName}
                          error={shown(nameError(item))}
                          style={{ flex: 1 }}
                          onChange={(event) => {
                            edit(index, { publicName: event.currentTarget.value });
                          }}
                        />
                      </Group>
                      <TextInput
                        label={t("insights.publicPage.publicNote")}
                        autoComplete="off"
                        value={item.publicNote}
                        error={shown(noteError(item))}
                        onChange={(event) => {
                          edit(index, { publicNote: event.currentTarget.value });
                        }}
                      />
                    </Stack>
                    <Stack gap={4} mt={26}>
                      <ActionIcon
                        variant="default"
                        aria-label={t("insights.publicPage.moveUp", { name: nameOf(item) })}
                        disabled={index === 0}
                        onClick={() => {
                          move(index, -1);
                        }}
                      >
                        ↑
                      </ActionIcon>
                      <ActionIcon
                        variant="default"
                        aria-label={t("insights.publicPage.moveDown", { name: nameOf(item) })}
                        disabled={index === items.length - 1}
                        onClick={() => {
                          move(index, 1);
                        }}
                      >
                        ↓
                      </ActionIcon>
                      <ActionIcon
                        variant="default"
                        color="red"
                        aria-label={t("insights.publicPage.remove", { name: nameOf(item) })}
                        onClick={() => {
                          remove(index);
                        }}
                      >
                        ×
                      </ActionIcon>
                    </Stack>
                  </Group>
                </Paper>
              ))}
            </Stack>
          )}
          {shown(itemsError) !== undefined ? (
            <Text size="sm" c="red">
              {itemsError}
            </Text>
          ) : null}
          {proxiesQuery.isError ? (
            <Text size="sm" c="red">
              {t("insights.publicPage.proxiesFailed", { reason: errorMessage(proxiesQuery.error) })}
            </Text>
          ) : proxiesQuery.data === undefined ? (
            <Text size="sm" c="dimmed">
              {t("insights.publicPage.proxiesLoading")}
            </Text>
          ) : proxies.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("insights.publicPage.noProxies")}
            </Text>
          ) : candidates.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("insights.publicPage.allAdded")}
            </Text>
          ) : (
            <Group align="flex-end" gap="sm">
              <Select
                label={t("insights.publicPage.addProxy")}
                placeholder={t("insights.publicPage.addProxyPlaceholder")}
                data={candidates.map((proxy) => ({ value: proxy.id, label: proxyLabel(proxy) }))}
                searchable
                value={pick}
                onChange={setPick}
                style={{ flex: 1 }}
              />
              <Button variant="default" onClick={add} disabled={pick === null}>
                {t("insights.publicPage.add")}
              </Button>
            </Group>
          )}
        </Stack>

        {refusal !== null && (!refusal.refused || refusal.host === values.host) ? (
          <Alert
            color="red"
            role="alert"
            title={refusal.refused ? t("insights.publicPage.refused") : t("insights.publicPage.saveFailed")}
          >
            {refusal.message}
          </Alert>
        ) : null}
        <Group gap="sm" mt="xs">
          <Button type="submit" loading={update.isPending}>
            {t("insights.publicPage.save")}
          </Button>
        </Group>
      </Stack>

      <ConfirmDialog
        opened={confirming}
        title={t("insights.publicPage.confirm.title")}
        message={t("insights.publicPage.confirm.message", { host, count: items.length })}
        confirmLabel={t("insights.publicPage.confirm.confirm")}
        loading={update.isPending}
        onConfirm={() => {
          void send();
        }}
        onClose={() => {
          setConfirming(false);
        }}
      />
    </form>
  );
}

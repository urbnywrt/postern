import { Button, Group, Select, Stack, Textarea, TextInput } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { type SavedListener, type UpdateListenerVars, useCreateListener, useUpdateListener } from "../api/hooks/listeners";
import type { Listener } from "../gen/postern/panel/v1/proxies_pb";
import { LISTENER_KINDS } from "../app/listener";
import { notifySuccess, notifyWarning } from "../app/notify";
import { type FieldErrors, useFormState } from "../app/useFormState";
import {
  parseLines,
  validateBindIp,
  validateListenerPort,
  validateMaskTarget,
  validateOptionalHost,
  validateTrustedCidrs,
  validateUpstreamBindIp,
} from "../app/validators";

interface Values {
  kind: string;
  bindIp: string;
  port: string;
  linkHostOverride: string;
  strangerAction: string;
  maskTarget: string;
  nonTlsAction: string;
  /** One per line. */
  trustedCidrs: string;
}

interface ListenerFormProps {
  /** A new listener on this node. */
  nodeId?: string;
  /** The listener whose settings are edited. */
  listener?: Listener;
  onDone: (listener: Listener) => void;
  onCancel: () => void;
}

/**
 * The form of a listener: the port that a node accepts the clients of its proxies
 * on, and what it does with a connection that is not for one of them. A new
 * listener starts with what the panel would pick: all addresses, mask, drop. An
 * http-upstream listener (for WEB proxies under a path of a site that a web
 * server of the node serves) binds a loopback address and names the web servers
 * whose X-Forwarded-For it believes; the kind of a listener does not change.
 */
export function ListenerForm({ nodeId, listener, onDone, onCancel }: ListenerFormProps) {
  const { t } = useTranslation();
  const editing = listener !== undefined;
  const create = useCreateListener();
  const update = useUpdateListener();
  const pending = create.isPending || update.isPending;
  // What the form started from, and then what it last saved. Only what differs from it is
  // sent, so a field that was not touched cannot undo a change that somebody else made.
  const [baseline, setBaseline] = useState(listener);

  const form = useFormState<Values>({
    kind: listener?.kind ?? "tls",
    bindIp: listener?.bindIp ?? "0.0.0.0",
    port: listener ? String(listener.port) : "",
    linkHostOverride: listener?.linkHostOverride ?? "",
    strangerAction: listener?.strangerAction ?? "mask",
    maskTarget: listener?.maskTarget ?? "",
    nonTlsAction: listener?.nonTlsAction ?? "drop",
    trustedCidrs: listener?.trustedCidrs.join("\n") ?? "127.0.0.1/32",
  });
  const { values } = form;
  const upstream = values.kind === "http-upstream";
  const masking = values.strangerAction === "mask";
  const fields = form.check({
    bindIp: upstream ? validateUpstreamBindIp(values.bindIp) : validateBindIp(values.bindIp),
    // The port is judged by the address that the form has now: the node keeps its
    // internal ports on 0.0.0.0 and on 127.0.0.1 only.
    port: validateListenerPort(values.port, upstream && values.bindIp.trim() === "" ? "127.0.0.1" : values.bindIp),
    linkHostOverride: upstream ? null : validateOptionalHost(values.linkHostOverride),
    maskTarget: !upstream && masking ? validateMaskTarget(values.maskTarget) : null,
    trustedCidrs: upstream ? validateTrustedCidrs(values.trustedCidrs) : null,
  } satisfies FieldErrors<Values>);

  async function submit() {
    if (pending) {
      return; // a second Enter must not send the same try again
    }
    form.setSubmitted(true);
    if (!fields.valid) {
      return;
    }
    const bindIp = values.bindIp.trim();
    const port = Number(values.port.trim());
    const linkHostOverride = upstream ? "" : values.linkHostOverride.trim();
    const maskTarget = values.maskTarget.trim();
    const trustedCidrs = upstream ? parseLines(values.trustedCidrs) : [];
    try {
      if (baseline === undefined) {
        const created = await create.mutateAsync({
          nodeId: nodeId ?? "",
          kind: values.kind,
          bindIp,
          port,
          linkHostOverride,
          strangerAction: upstream ? "" : values.strangerAction,
          // A target is for strangers that are relayed; the others have none.
          maskTarget: !upstream && masking ? maskTarget : "",
          nonTlsAction: upstream ? "" : values.nonTlsAction,
          trustedCidrs,
        });
        warnIfTaken(created);
        onDone(created.listener);
        return;
      }
      const changes: UpdateListenerVars = { id: baseline.id };
      if (bindIp !== baseline.bindIp) changes.bindIp = bindIp;
      if (port !== baseline.port) changes.port = port;
      if (upstream) {
        if (trustedCidrs.join("\n") !== baseline.trustedCidrs.join("\n")) changes.trustedCidrs = { cidrs: trustedCidrs };
      } else {
        if (linkHostOverride !== baseline.linkHostOverride) changes.linkHostOverride = linkHostOverride;
        if (values.strangerAction !== baseline.strangerAction) changes.strangerAction = values.strangerAction;
        if (masking) {
          if (maskTarget !== baseline.maskTarget) changes.maskTarget = maskTarget;
        } else if (values.strangerAction !== baseline.strangerAction && baseline.maskTarget !== "") {
          // It stopped relaying strangers, and its target goes with that.
          changes.maskTarget = "";
        }
        if (values.nonTlsAction !== baseline.nonTlsAction) changes.nonTlsAction = values.nonTlsAction;
      }
      if (Object.keys(changes).length === 1) {
        onDone(baseline);
        return;
      }
      const saved = await update.mutateAsync(changes);
      setBaseline(saved.listener);
      notifySuccess(t("listener.form.saved"));
      warnIfTaken(saved);
      onDone(saved.listener);
    } catch {
      // The query client has shown why, and the form keeps what was typed.
    }
  }

  /**
   * A listener is stored on a port that another process holds (a proxy that moves to Postern
   * needs that), but the edge cannot listen there until it is free, and the node does not apply
   * its state until then: the admin is told, and the warning stays until it is closed.
   */
  function warnIfTaken({ listener: saved, portTakenBy }: SavedListener) {
    if (portTakenBy.length === 0) {
      return;
    }
    notifyWarning(
      t("listener.portTaken.title", { address: `${saved.bindIp}:${String(saved.port)}` }),
      t("listener.portTaken.message", { owners: portTakenBy.map((owner) => owner.owner).join(", ") }),
    );
  }

  return (
    <form
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <Stack gap="sm">
        {editing ? null : (
          <Select
            label={t("listener.form.kind")}
            description={t("listener.form.kindHint")}
            data={LISTENER_KINDS.map((kind) => ({ value: kind, label: t(`listener.kind.${kind}`) }))}
            allowDeselect={false}
            {...fields.bindSelect("kind")}
            onChange={(value) => {
              const kind = value ?? "tls";
              form.set("kind", kind);
              // Each kind has its own usual address.
              form.set("bindIp", kind === "http-upstream" ? "127.0.0.1" : "0.0.0.0");
            }}
          />
        )}
        <TextInput
          label={t("listener.form.bindIp")}
          description={upstream ? t("listener.form.bindIpHintUpstream") : t("listener.form.bindIpHint")}
          autoComplete="off"
          spellCheck={false}
          {...fields.bind("bindIp")}
        />
        <TextInput
          label={t("listener.form.port")}
          description={upstream ? t("listener.form.portHintUpstream") : t("listener.form.portHint")}
          inputMode="numeric"
          autoComplete="off"
          data-autofocus
          {...fields.bind("port")}
        />
        {upstream ? (
          <Textarea
            label={t("listener.form.trustedCidrs")}
            description={t("listener.form.trustedCidrsHint")}
            autosize
            minRows={2}
            maxRows={8}
            spellCheck={false}
            {...fields.bind("trustedCidrs")}
          />
        ) : (
          <>
            <TextInput
              label={t("listener.form.linkHostOverride")}
              description={t("listener.form.linkHostOverrideHint")}
              autoComplete="off"
              spellCheck={false}
              {...fields.bind("linkHostOverride")}
            />
            <Select
              label={t("listener.form.strangerAction")}
              description={t("listener.form.strangerActionHint")}
              data={[
                { value: "mask", label: t("listener.stranger.mask") },
                { value: "reject", label: t("listener.stranger.reject") },
                { value: "drop", label: t("listener.stranger.drop") },
              ]}
              allowDeselect={false}
              {...fields.bindSelect("strangerAction")}
            />
            {masking ? (
              <TextInput
                label={t("listener.form.maskTarget")}
                description={t("listener.form.maskTargetHint")}
                autoComplete="off"
                spellCheck={false}
                {...fields.bind("maskTarget")}
              />
            ) : null}
            <Select
              label={t("listener.form.nonTlsAction")}
              data={[
                { value: "drop", label: t("listener.nonTls.drop") },
                { value: "http400", label: t("listener.nonTls.http400") },
              ]}
              allowDeselect={false}
              {...fields.bindSelect("nonTlsAction")}
            />
          </>
        )}
        <Group gap="sm" mt="xs">
          <Button type="submit" loading={pending}>
            {editing ? t("listener.form.save") : t("listener.form.create")}
          </Button>
          <Button variant="default" onClick={onCancel} disabled={pending}>
            {t("common.cancel")}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}

import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { vi } from "vitest";

import {
  type CreateDnsCredentialRequest,
  type DeleteDnsCredentialRequest,
  type DnsCredential,
  DnsCredentialSchema,
  type UpdateDnsCredentialRequest,
} from "../gen/postern/panel/v1/dns_pb";
import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";

// An in-memory DnsCredentialService: credentials without their tokens, as the
// panel answers. The tokens that were sent are kept apart, so that a test can
// see that the UI sent one and never shows it.

const now = () => Math.floor(Date.now() / 1000);
let sequence = 0;

type CredentialInit = MessageInitShape<typeof DnsCredentialSchema>;

export function makeDnsCredential(init: CredentialInit = {}): DnsCredential {
  const n = ++sequence;
  return create(DnsCredentialSchema, {
    id: `dns-${String(n)}`,
    name: `Cloudflare ${String(n)}`,
    provider: "cloudflare",
    usedBy: 0,
    createdUnix: BigInt(now() - 3600),
    updatedUnix: BigInt(now() - 3600),
    ...init,
  });
}

export interface DnsOptions {
  dnsCredentials?: CredentialInit[];
}

function handler<Request, Response>(impl: (req: Request) => Response) {
  return vi.fn<(req: Request) => Response | Promise<Response>>(impl);
}

export function createFakeDns(requireSession: () => void, inventory: { proxies: Proxy[] }, options: DnsOptions = {}) {
  const state = {
    credentials: (options.dnsCredentials ?? []).map((init) => makeDnsCredential(init)),
    /** The token of each credential, as it was sent. */
    tokens: new Map<string, string>(),
  };
  const find = (id: string) => {
    const credential = state.credentials.find((entry) => entry.id === id);
    if (credential === undefined) {
      throw new ConnectError("no such dns credential", Code.NotFound);
    }
    return credential;
  };
  const usedBy = (id: string) => inventory.proxies.filter((proxy) => proxy.web?.dnsCredentialId === id).length;

  const rpc = {
    listDnsCredentials: vi.fn(() => {
      requireSession();
      return { credentials: state.credentials.map((credential) => ({ ...credential, usedBy: usedBy(credential.id) })) };
    }),

    createDnsCredential: handler((req: CreateDnsCredentialRequest) => {
      requireSession();
      if (req.name.trim() === "") {
        throw new ConnectError("name is empty", Code.InvalidArgument);
      }
      if (req.token.trim() === "") {
        throw new ConnectError("token is empty", Code.InvalidArgument);
      }
      const credential = makeDnsCredential({ name: req.name.trim(), provider: req.provider === "" ? "cloudflare" : req.provider });
      state.credentials.push(credential);
      state.tokens.set(credential.id, req.token);
      return { credential };
    }),

    updateDnsCredential: handler((req: UpdateDnsCredentialRequest) => {
      requireSession();
      const credential = find(req.id);
      if (req.name !== undefined) credential.name = req.name;
      if (req.token !== undefined) {
        if (req.token.trim() === "") {
          throw new ConnectError("token is empty", Code.InvalidArgument);
        }
        state.tokens.set(credential.id, req.token);
      }
      credential.updatedUnix = BigInt(now());
      return { credential };
    }),

    deleteDnsCredential: handler((req: DeleteDnsCredentialRequest) => {
      requireSession();
      find(req.id);
      if (usedBy(req.id) > 0) {
        throw new ConnectError("proxies still use the dns credential: give them another one first", Code.FailedPrecondition);
      }
      state.credentials = state.credentials.filter((entry) => entry.id !== req.id);
      state.tokens.delete(req.id);
      return {};
    }),
  };

  return { rpc, state };
}

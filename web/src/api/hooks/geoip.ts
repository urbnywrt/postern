import { fromJson, type JsonValue } from "@bufbuild/protobuf";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { GeoIPService, type GeoIPStatus, GeoIPStatusSchema } from "../../gen/postern/panel/v1/geoip_pb";
import { present } from "../answer";
import { useClient } from "../client";
import { geoipKeys, metricsKeys } from "./keys";

/** Whether country lookups are on, and which country database the panel has. */
export function useGeoIP() {
  const geoip = useClient(GeoIPService);
  return useQuery({
    queryKey: geoipKeys.status,
    queryFn: async ({ signal }) => present((await geoip.getGeoIP({}, { signal })).status),
    meta: { silent: true },
  });
}

/**
 * Looks for the database of the month now. A look that fails is not an error of the
 * call: it is in the status (error), which the page shows.
 */
export function useRefreshGeoIP() {
  const geoip = useClient(GeoIPService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => present((await geoip.refreshGeoIP({})).status),
    onSuccess: (status) => {
      queryClient.setQueryData(geoipKeys.status, status);
      void queryClient.invalidateQueries({ queryKey: metricsKeys.all });
    },
  });
}

/** Turns country lookups on or off. */
export function useSetGeoIPEnabled() {
  const geoip = useClient(GeoIPService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (enabled: boolean) => present((await geoip.setGeoIPEnabled({ enabled })).status),
    onSuccess: (status) => {
      queryClient.setQueryData(geoipKeys.status, status);
    },
  });
}

/** Sends a country database file; answers the status of the database that the panel then has. */
export type UploadGeoIP = (file: File) => Promise<GeoIPStatus>;

export const GEOIP_UPLOAD_URL = "/api/geoip";

/**
 * PUT /api/geoip with the file as the body, gzip as DB-IP publishes it or unpacked.
 * The panel answers 200 with the status as JSON, and anything else (400 for a file
 * that is not a country database, 413 for one too large) with a line of text, which
 * becomes the error.
 */
export const uploadGeoIP: UploadGeoIP = async (file) => {
  const response = await fetch(GEOIP_UPLOAD_URL, {
    method: "PUT",
    body: file,
    credentials: "same-origin",
    headers: { "Content-Type": "application/octet-stream" },
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(text.trim() !== "" ? text.trim() : `HTTP ${String(response.status)}`);
  }
  return fromJson(GeoIPStatusSchema, JSON.parse(text) as JsonValue, { ignoreUnknownFields: true });
};

/** The upload, with the status that it answers put where GetGeoIP keeps it. The form shows a failure in place. */
export function useUploadGeoIP(upload: UploadGeoIP = uploadGeoIP) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (file: File) => upload(file),
    onSuccess: (status) => {
      queryClient.setQueryData(geoipKeys.status, status);
      void queryClient.invalidateQueries({ queryKey: metricsKeys.all });
    },
    meta: { silent: true },
  });
}

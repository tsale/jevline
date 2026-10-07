// The canonical event model. Every telemetry source (Sysmon, Security 4688, EDR, CSV, text) is
// mapped into these shapes, so everything after normalization, including what Jev is asked, is
// independent of the schema the logs arrived in.

/** What an event is about, independent of its source. */
export type Kind =
  | 'process_start' | 'process_end'
  | 'inject'          // A wrote into or started a thread in B (Sysmon 8, EDR injection APIs)
  | 'process_access'  // A opened a handle to B (Sysmon 10); `access` has the mask
  | 'file_create' | 'file_delete' | 'file_time' | 'image_load'
  | 'network' | 'dns'
  | 'registry_set'
  | 'pipe_create' | 'pipe_connect'
  | 'service_install' | 'task_create'
  | 'logon' | 'logon_failed'  // an account logged on (or tried to) to a host, from somewhere
  | 'http_request'            // a web request from a client to a server
  | 'other';

/** A process as one event describes it. Any field may be missing. */
export interface ProcRef {
  guid?: string;    // Sysmon ProcessGuid / EDR entity ID, upper-case without braces
  pid?: number;
  name?: string;    // image file name, original case
  path?: string;    // full image path
  cmd?: string;     // command line, trimmed
  user?: string;
  sha256?: string;  // lower-case hex
}

export interface Event {
  /** Position in the combined input (file order, then line order): the tie-breaker everywhere. */
  seq: number;
  /** The event's own ID, or `line-N` / `event-N` from its place in the file. */
  id: string;
  /** The ID is line-N, made from the line number. */
  lineId?: true;
  /** Which input file (index into Inputs) and where in it, for reading the raw record back. */
  file: number;
  line: number;
  /** Microseconds since the epoch, or null when the event has no usable time. */
  t: number | null;
  /** Canonical host: lower-case short name ("cla-ws-214"), "" when unknown. */
  host: string;
  kind: Kind;
  /** Where the event came from: "sysmon:1", "security:4688", "ecs", "flat"... */
  source: string;
  /** The process that did it (for process_start: the new process). */
  proc: ProcRef;
  /** process_start: the parent. */
  parent?: ProcRef;
  /** inject / process_access: the other process. */
  target?: ProcRef;
  file_path?: string;
  file_sha256?: string;
  access?: number;           // process_access GrantedAccess mask
  net?: {ip?: string; port?: number; domain?: string};
  /** dns: an answer the resolver relayed (Elastic Defend's lookup_result, logged by the DNS Client
   * service), not a lookup by this process. The asking process has its own lookup_requested event. */
  dns_answer?: true;
  reg?: {key?: string; value?: string};
  pipe?: string;
  /** service_install / task_create: the image or command the service or task runs. */
  launches?: string;
  /** logon / logon_failed / http_request: the account involved (canonical user name). */
  account?: string;
  /** Where a connection, logon or request came from, when that isn't the host itself. */
  src?: {ip?: string; port?: number; host?: string};
  /** This host's own IP addresses, when the record says them (used to tell internal addresses apart). */
  host_ips?: string[];
  logon_type?: string;
  http?: {method?: string; url?: string; status?: number};
}

/** What a node of the incident graph is. Processes carry an execution chain; the others are what an
 * intrusion moves through in logs without processes (authentication, firewall, proxy, web server). */
export type EntityType = 'process' | 'host' | 'user' | 'ip' | 'domain';

/** One node of the incident graph: a process merged from every event that identifies it, or another
 * entity (an account, host, address or domain) with the events it appears in. */
export interface ProcessNode {
  /** "g:<host>:<guid>" or "p:<host>:<pid>:<start µs | first-seen µs>" for processes; "user:alice",
   * "host:ws-01", "ip:203.0.113.9", "domain:evil.example" for other entities. */
  key: string;
  type: EntityType;
  host: string;
  guid?: string;
  pid?: number;
  start: number | null;   // µs; null when the start is not in the input
  firstSeen: number | null;
  end: number | null;
  name?: string;
  path?: string;
  cmd?: string;
  user?: string;
  sha256?: string;
  parent?: string;        // parent node key
  /** Every event this process did (seq numbers, in time order once indexed). */
  events: number[];
  /** process_start events that describe this process's creation (Sysmon 1, 4688, EDR...). */
  starts: number[];
}

export type LinkType =
  | 'spawned'              // parent created child
  | 'injected'             // remote thread / memory write into the target
  | 'opened_for_injection' // handle with VM write + operation, create thread, or full access
  | 'dropped_and_ran'      // A wrote the file B was started from
  | 'dropped_and_loaded'   // A wrote a DLL that B loaded
  | 'pipe'                 // B connected to a named pipe A created
  | 'persisted_and_ran'    // A registered a run key / service / task that later started B
  // Between entities, followed both ways:
  | 'contacted'            // a process or host connected to (or looked up) an address or domain
  | 'logged_on'            // an account logged on to a host
  | 'logon_from'           // a logon to a host came from an address (or another host)
  | 'used_account'         // an address logged on as an account
  | 'failed_logon'         // an address tried to log on as an account and failed
  | 'requested';           // an address sent web requests to a server

export interface Link {
  type: LinkType;
  from: string;   // node key
  to: string;     // node key
  /** When the link took effect: the child's start, the injection, the dropped file's start... */
  t: number | null;
  /** When `from` did its part (the write behind a drop, the registration behind persistence);
   * a process can only pass the incident on through actions after it joined the incident. */
  act: number | null;
  /** The last time the link was seen, and how many times (a beacon contacts its C2 hundreds of times). */
  last: number | null;
  count: number;
  /** Seq numbers of the events that show the link (at most a few). */
  evidence: number[];
  /** Short observed detail: the file, pipe, registry key or access mask. */
  detail?: string;
}
